"""dumpcap supervisor.

Owns one dumpcap subprocess per CaptureSession. Rotation is delegated to
dumpcap via -b. We poll the active rotation file's size to emit
real-time bytes/sec stats; on each rotation we mark the previous file
as closed so the consumer side (the web app) can scan it. dumpcap's
exit summary gives us the authoritative drop count.
"""

from __future__ import annotations

import glob
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

log = logging.getLogger("capd.supervisor")

# 200MB × 10 files = ~2GB ring per session, per user spec.
DEFAULT_FILESIZE_KB = 200_000
DEFAULT_FILES = 10

# dumpcap "Packets captured: N" / "Packets dropped: N" appear at exit.
_PKTS_RE = re.compile(r"Packets captured:\s*(\d+)")
_DROPS_RE = re.compile(r"Packets dropped:\s*(\d+)")

# dumpcap's ring-buffer filename sequence number (cap_00177_<ts>.pcapng ->
# 177). Confirmed empirically (a real `-b files:N` ring capture, N small,
# under enough traffic to force many rotations): this index increments
# forever and never wraps back to reuse 1..N — only the *files on disk*
# get evicted once the ring cap is exceeded, the numbering itself doesn't
# reset. That's what makes gap detection below reliable: any jump in this
# number bigger than +1 between two polls means dumpcap's own eviction
# deleted one or more intermediate files before either poll ever observed
# them on disk — the only case (rotation outpacing the poll interval,
# combined with a small ring_files) this class can't recover from, only
# detect and report.
_SEQ_RE = re.compile(r"cap_(\d+)_")


def _seq_of(path: str) -> int | None:
    m = _SEQ_RE.search(os.path.basename(path))
    return int(m.group(1)) if m else None

# How long to wait after spawning dumpcap before confirming it's actually
# alive. An interface that vanished between server.py's pre-flight check
# and this exec, a capability/permission rejection, or a BPF/DLT mismatch
# dumpcap itself rejects all make it exit almost immediately having
# written zero files. Without this check, start() reported success
# regardless, and the resulting "capture" silently showed a clean
# status="stopped" with 0 bytes on its first poll — the real cause sat
# unseen in dumpcap's own stderr the whole time.
_STARTUP_LIVENESS_GRACE_S = 0.3


@dataclass
class CaptureConfig:
    session_id: str
    interface: str
    bpf_filter: str = ""
    output_dir: Path = field(default_factory=Path)
    filesize_kb: int = DEFAULT_FILESIZE_KB
    files: int = DEFAULT_FILES
    max_duration_s: int = 0  # 0 = no cap; web app enforces its own deadline


@dataclass
class CaptureStats:
    ts: float
    bytes_total: int
    bytes_per_sec: float
    current_file: str | None
    file_index: int
    files_closed: list[str]
    running: bool
    # Cumulative count of rotation files dumpcap's own ring eviction
    # deleted before any poll ever observed them on disk — see _SEQ_RE's
    # docstring. 0 in the overwhelming common case (poll interval keeps up
    # with the actual rotation rate); a nonzero value means real capture
    # data was lost to a too-small ring_files/poll-interval combination,
    # not a bug in this class itself.
    files_lost_count: int = 0


class CaptureSupervisor:
    """One instance per active capture session."""

    def __init__(self, cfg: CaptureConfig, dumpcap_path: str | None = None):
        if not cfg.session_id or not cfg.session_id.replace("-", "").replace("_", "").isalnum():
            # session_id ends up in a path; refuse anything that could traverse.
            raise ValueError("session_id must be alphanumeric (with - or _)")
        self.cfg = cfg
        self.dumpcap = dumpcap_path or shutil.which("dumpcap")
        if not self.dumpcap:
            raise RuntimeError("dumpcap not found on PATH")

        self._proc: subprocess.Popen | None = None
        self._stderr_thread: threading.Thread | None = None
        self._stderr_buf: list[str] = []
        self._lock = threading.Lock()

        self._started_at: float | None = None
        self._last_poll_ts: float = 0.0
        self._last_poll_bytes: int = 0

        # Closed-file tracking. We don't open or read these — we just
        # name them so the consumer side can pick them up. dumpcap
        # writes a sequence cap_00001_<ts>.pcapng, cap_00002_<ts>.pcapng…
        self._known_files: set[str] = set()
        self._previous_active: str | None = None
        self._closed_emitted: list[str] = []
        self._chmod_done: set[str] = set()
        # Highest ring-buffer sequence number accounted for so far (either
        # emitted as closed, or currently the active file) — see _SEQ_RE.
        # Used to detect a gap: dumpcap's own eviction outpacing our poll
        # interval, silently deleting one or more intermediate files
        # before any poll ever saw them exist.
        self._highest_seq_accounted_for: int = 0
        self._files_lost_count: int = 0

        # Authoritative tallies (parsed from dumpcap exit output).
        self.final_packets: int | None = None
        self.final_drops: int | None = None

    # ── lifecycle ────────────────────────────────────────────

    def start(self) -> None:
        if self._proc is not None:
            raise RuntimeError("supervisor already started")

        out_dir = Path(self.cfg.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "cap.pcapng"

        argv: list[str] = [
            self.dumpcap,
            "-i", self.cfg.interface,
            "-q",                                  # less console noise
            "-n",                                  # don't try to resolve names
            "-b", f"filesize:{int(self.cfg.filesize_kb)}",
            "-b", f"files:{int(self.cfg.files)}",
            "-w", str(out_path),
        ]
        if self.cfg.bpf_filter.strip():
            argv += ["-f", self.cfg.bpf_filter.strip()]
        if self.cfg.max_duration_s and self.cfg.max_duration_s > 0:
            argv += ["-a", f"duration:{int(self.cfg.max_duration_s)}"]

        log.info("session=%s spawning %s", self.cfg.session_id, " ".join(argv))
        self._proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._started_at = time.time()
        self._stderr_thread = threading.Thread(
            target=self._consume_stderr, daemon=True,
            name=f"capd-stderr-{self.cfg.session_id}",
        )
        self._stderr_thread.start()

        time.sleep(_STARTUP_LIVENESS_GRACE_S)
        if self._proc.poll() is not None:
            exit_code = self._proc.returncode
            self._stderr_thread.join(timeout=1.0)
            with self._lock:
                reason = "\n".join(self._stderr_buf).strip()
            self._proc = None
            raise RuntimeError(
                reason or f"dumpcap exited immediately with code {exit_code}"
            )

    def stop(self, timeout: float = 5.0) -> CaptureStats:
        if self._proc is None:
            return self._snapshot(running=False)

        # SIGINT lets dumpcap flush + emit its summary line.
        try:
            self._proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            log.warning("session=%s dumpcap didn't exit on SIGINT, killing", self.cfg.session_id)
            self._proc.kill()
            self._proc.wait(timeout=2.0)

        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=2.0)

        # Final stats from stderr summary.
        joined = "\n".join(self._stderr_buf)
        m = _PKTS_RE.search(joined)
        if m:
            self.final_packets = int(m.group(1))
        m = _DROPS_RE.search(joined)
        if m:
            self.final_drops = int(m.group(1))

        # The active file at stop time is now closed too.
        snap = self._snapshot(running=False, finalize=True)
        self._proc = None
        return snap

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    # ── stats ────────────────────────────────────────────────

    def poll(self) -> CaptureStats:
        # finalize=(not running), not always False: a session that ends on
        # its own (dumpcap's own `-a duration:N` timer elapses, or it
        # simply exits/crashes) — as opposed to an explicit stop() RPC,
        # which already passes finalize=True — was never detected as
        # having a final closed file here. Both the local StatsHub loop
        # and the remote agent's session_stats reporter only ever call
        # poll() (never stop()) to observe an in-progress session, so for
        # any capture that self-expires without an explicit /stop request,
        # the last active file was never marked closed, its report never
        # got generated, and this was true for BOTH local and remote
        # captures. Confirmed real: a remote max_duration_s capture, run to
        # natural completion with no explicit stop, correctly showed
        # status="stopped" but never produced a report at all. Safe to
        # finalize repeatedly — _closed_emitted already makes this
        # idempotent per file.
        running = self.is_running()
        return self._snapshot(running=running, finalize=not running)

    def _snapshot(self, running: bool, finalize: bool = False) -> CaptureStats:
        out_dir = Path(self.cfg.output_dir)
        files = sorted(glob.glob(str(out_dir / "cap_*.pcapng")))
        active = files[-1] if files else None

        # Everything below reads-then-mutates self._chmod_done/
        # _previous_active/_closed_emitted (rotation detection) and
        # _last_poll_ts/_last_poll_bytes (bps calc) — held under one lock
        # end-to-end, not just around the getsize() calls as before.
        # poll() runs on the stats-loop thread while stop() can run
        # concurrently on an RPC-handling thread (a user clicking Stop
        # while the stats stream is live is the ordinary case, not an
        # edge case); without a single lock spanning the whole check-
        # then-append sequence, both could see the same rotated file as
        # "not yet closed" at once and both report it in their own
        # CaptureStats — double-processing one rotation (duplicate engine
        # subprocess spawn, duplicate shipped report for the same pcap).
        with self._lock:
            # dumpcap creates capture files 0600 (root-owned, since this
            # process runs as root). The web app reads this directory as
            # a different, non-root user — without this, every file is
            # unreadable to it and the scan consumer.py queues for each
            # rotated file fails silently (permission denied, logged but
            # never surfaced to the user).
            for f in files:
                if f not in self._chmod_done:
                    try:
                        os.chmod(f, 0o644)
                    except OSError:
                        pass
                    else:
                        self._chmod_done.add(f)

            # Detect a gap: dumpcap's own ring eviction outpacing this
            # poll, deleting one or more intermediate files before this or
            # any previous poll ever saw them exist on disk. Must run
            # before the files_closed accounting below (which only ever
            # reports files it can actually see) — this is the only place
            # that can detect data that's already gone, since it compares
            # against the ever-increasing ring sequence number rather than
            # just this poll's file listing.
            seqs = [s for s in (_seq_of(f) for f in files) if s is not None]
            if seqs:
                lowest_seq = min(seqs)
                if lowest_seq > self._highest_seq_accounted_for + 1:
                    gap = lowest_seq - self._highest_seq_accounted_for - 1
                    self._files_lost_count += gap
                    log.warning(
                        "session=%s rotation outpaced polling — %d capture "
                        "file(s) (sequence %d-%d) were evicted by dumpcap's "
                        "own ring before ever being observed; their data is "
                        "unrecoverable. Consider a larger ring_files or a "
                        "shorter poll interval.",
                        self.cfg.session_id, gap,
                        self._highest_seq_accounted_for + 1, lowest_seq - 1,
                    )
                self._highest_seq_accounted_for = max(self._highest_seq_accounted_for, max(seqs))

            # Detect rotation: anything we previously saw as "active" but
            # which is no longer the newest file is closed and ready for
            # the consumer to ingest.
            newly_closed: list[str] = []
            if self._previous_active and self._previous_active != active:
                if self._previous_active not in self._closed_emitted:
                    newly_closed.append(self._previous_active)
                    self._closed_emitted.append(self._previous_active)
            for f in files:
                if f != active and f not in self._closed_emitted:
                    newly_closed.append(f)
                    self._closed_emitted.append(f)
            # On finalize, the active file itself is closed.
            if finalize and active and active not in self._closed_emitted:
                newly_closed.append(active)
                self._closed_emitted.append(active)

            self._previous_active = active

            # Bytes total = closed files (final size) + active file (current size).
            bytes_total = 0
            for f in files:
                try:
                    bytes_total += os.path.getsize(f)
                except OSError:
                    pass

            now = time.time()
            bps = 0.0
            if self._last_poll_ts and now > self._last_poll_ts:
                bps = max(0.0, (bytes_total - self._last_poll_bytes) / (now - self._last_poll_ts))
            self._last_poll_ts = now
            self._last_poll_bytes = bytes_total
            files_lost_count = self._files_lost_count

        return CaptureStats(
            ts=now,
            bytes_total=bytes_total,
            bytes_per_sec=bps,
            current_file=active,
            file_index=len(files),
            files_closed=newly_closed,
            running=running,
            files_lost_count=files_lost_count,
        )

    # ── internal ─────────────────────────────────────────────

    def _consume_stderr(self) -> None:
        assert self._proc is not None
        if self._proc.stderr is None:
            return
        for line in self._proc.stderr:
            line = line.rstrip("\n")
            with self._lock:
                self._stderr_buf.append(line)
                # Cap memory; an OOMing capd helps no one.
                if len(self._stderr_buf) > 500:
                    del self._stderr_buf[:250]
            log.debug("session=%s dumpcap: %s", self.cfg.session_id, line)


def stats_loop(supervisor: CaptureSupervisor, on_stats: Callable[[CaptureStats], None],
               interval_s: float = 1.0, stop_event: threading.Event | None = None) -> None:
    """Convenience polling loop — blocks until stop_event is set or capture exits."""
    while True:
        if stop_event is not None and stop_event.is_set():
            return
        stats = supervisor.poll()
        on_stats(stats)
        if not stats.running:
            return
        time.sleep(interval_s)
