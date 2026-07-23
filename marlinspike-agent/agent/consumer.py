"""Rotation consumer — agent-side.

Adapted from marlinspike/capture/consumer.py's enqueue_scan/make_listener:
when a rotated pcap closes, spawn the same analysis engine ('python -m
marlinspike ... chain') that processes uploaded captures, exactly the
pattern already used for local live-capture auto-scanning today.

Unlike the central version, this writes its report to a local staging
directory (there's no REPORTS_DIR concept on a bare agent host) — the
caller (agent/client.py's stats-reporter) reads the finished report back
and ships it upward to the gateway, then this module's job is done.

Requires the real `marlinspike` package to be installed/importable on the
agent host (engine.py + plugins + rules + optionally the DPI/malware Rust
binaries + tshark) — a real dependency, unlike the deliberately dependency-
free transport layer (client.py/capd_client.py). See README.md.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import tempfile
import uuid

log = logging.getLogger("marlinspike-agent")


def _safe_stem(path: str) -> str:
    stem = os.path.splitext(os.path.basename(path))[0]
    return re.sub(r"[^a-zA-Z0-9._-]", "_", stem)[:60]


def run_scan(*, pcap_path: str, session_id: str, staging_dir: str,
             scan_profile: str = "fast",
             dpi_engine: str | None = None, dpi_binary: str | None = None) -> str | None:
    """Run the engine chain synchronously against one rotated pcap.

    Blocking — the caller (agent/client.py) runs this via
    loop.run_in_executor, same as every other capd round-trip. Returns the
    report file path on success, or None on failure (logged, not raised —
    one bad rotation shouldn't take down the stats-reporter loop).
    """
    os.makedirs(staging_dir, exist_ok=True)

    run_id = str(uuid.uuid4())
    prefix = _safe_stem(pcap_path) or "live"
    report_filename = f"{prefix}-marlinspike-{run_id[:8]}.json"
    report_path = os.path.join(staging_dir, report_filename)

    args: list[str] = [sys.executable, "-u", "-m", "marlinspike", "--pcap", pcap_path]
    if dpi_engine:
        args += ["--dpi-engine", dpi_engine]
    if dpi_binary:
        args += ["--dpi-binary", dpi_binary]
    if scan_profile == "fast":
        args.append("--fast")
    args += ["--collapse-threshold", "50", "--no-grassmarlin", "-o", report_path, "chain"]

    log.info("session=%s running scan for %s -> %s", session_id, pcap_path, report_path)

    try:
        proc = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, cwd=staging_dir,
        )
    except Exception:
        log.exception("session=%s failed to spawn engine for %s", session_id, pcap_path)
        return None

    if proc.returncode != 0:
        tail = "\n".join((proc.stdout or "").splitlines()[-10:])
        log.warning("session=%s scan failed rc=%d for %s; tail=%s",
                     session_id, proc.returncode, pcap_path, tail)
        return None

    if not os.path.isfile(report_path):
        log.warning("session=%s scan exited 0 but no report at %s", session_id, report_path)
        return None

    log.info("session=%s scan complete: %s", session_id, report_path)
    return report_path


def default_staging_dir() -> str:
    return os.path.join(tempfile.gettempdir(), "marlinspike-agent-reports")


def default_spool_dir() -> str:
    """Durable local queue (Phase 5): a report that can't be shipped right
    now (link down) is written here instead of being dropped, and flushed
    on the next successful reconnect. See agent/client.py's _spool_report/
    _flush_spool. A flat-file spool rather than SQLite — this only ever
    holds a handful of not-yet-shipped reports, and plain files are easy
    to inspect/clear by hand if something goes wrong."""
    return os.path.join(tempfile.gettempdir(), "marlinspike-agent-spool")
