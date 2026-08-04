"""Server-side scan launcher for pcaps forwarded by fleet agents.

Called from server.py's pcap_complete handler once a pcap upload has been
fully received and published. Mirrors app.py's manual-upload scan-launch
path (CLI arg building, run_store.record_start/record_finish sequencing)
but uses asyncio.create_subprocess_exec + await proc.wait() instead of a
blocking subprocess.Popen().wait() — this runs directly on the gateway's
own asyncio event loop, so a blocking wait would freeze every other
agent's connection for the scan's entire duration. run_in_executor is
reserved for the quick record_start/record_finish DB writes only.

No separate enrich.run_all() call here: the ``chain`` command already runs
enrichment (MITRE/ARP/APT/CISA) internally before it exits (engine.py's
_maybe_enrich) — this is the happy path, not the crash-recovery path,
where marlinspike.recovery's reaper re-runs enrichment defensively for a
narrow crash window between report.save() and _maybe_enrich().
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import os
import re

from marlinspike import config, recovery, run_store

from .db import get_app

log = logging.getLogger("fleet.gateway.scan")


def _report_path_for(pcap_path: str, user_id: int, project_id: int, run_id: str) -> str:
    pcap_stem = os.path.splitext(os.path.basename(pcap_path))[0]
    pcap_stem = re.sub(r"[^a-zA-Z0-9._-]", "_", pcap_stem)[:60]
    prefix = f"{pcap_stem}-" if pcap_stem else ""
    report_filename = f"{prefix}marlinspike-{run_id[:8]}.json"
    out_dir = os.path.join(config.REPORTS_DIR, str(user_id), str(project_id))
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, report_filename)


def _pcap_hash(pcap_path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(pcap_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _record_start(*, run_id: str, user_id: int, project_id: int, pcap_path: str,
                   report_path: str, engine_pid: int, engine_argv: list[str],
                   agent_id: int | None) -> None:
    app = get_app()
    with app.app_context():
        run_store.record_start(
            run_id, user_id=user_id, project_id=project_id, command="chain", scan_profile="fast",
            pcap_source=os.path.basename(pcap_path), pcap_hash=_pcap_hash(pcap_path),
            pcap_path=pcap_path, report_path=report_path,
            engine_pid=engine_pid, engine_argv=engine_argv, agent_id=agent_id,
        )


def _record_finish(*, run_id: str, status: str, error_tail: str | None,
                    node_count: int, edge_count: int) -> None:
    app = get_app()
    with app.app_context():
        run_store.record_finish(
            run_id, status=status, error_tail=error_tail,
            node_count=node_count, edge_count=edge_count,
        )


# One lock per session_uuid serializes rotations of the *same* capture
# session through launch_scan. Without it, two pcap_complete events close
# enough together (rotation N's engine subprocess still running when
# rotation N+1's pcap finishes uploading) run concurrently: record_start
# always overwrites report_path/pcap_path for the row keyed by run_id
# (=session_uuid), so rotation N+1's record_start can land while rotation
# N is still running — when N then finishes and calls record_finish, its
# status/node_count/edge_count get written onto a row whose
# report_path/pcap_path already point at rotation N+1 instead. Rotation
# N's own report file still exists on disk but the DB row never points at
# it again — a silent, permanent loss of that rotation's result. Entries
# are never removed; bounded by the number of distinct capture sessions
# this gateway process ever handles, small relative to process lifetime.
_session_locks: dict[str, asyncio.Lock] = {}


def _lock_for(session_uuid: str) -> asyncio.Lock:
    lock = _session_locks.get(session_uuid)
    if lock is None:
        lock = _session_locks[session_uuid] = asyncio.Lock()
    return lock


async def launch_scan(*, pcap_path: str, user_id: int, project_id: int, session_uuid: str,
                       agent_id: int | None, loop: asyncio.AbstractEventLoop) -> None:
    """Spawn the analysis engine for a fully-received agent pcap and wait
    for it to finish. Reuses session_uuid as the ScanHistory run_id —
    record_start is an upsert-by-run_id (run_store.record_start queries
    the existing row first), so a session that ships more than one
    rotation just updates the same row on each subsequent call rather than
    colliding on run_id's unique constraint. Serialized per session_uuid
    via _lock_for so concurrent rotations can't interleave their
    record_start/record_finish pairs (see _session_locks docstring above).
    """
    async with _lock_for(session_uuid):
        await _launch_scan_locked(
            pcap_path=pcap_path, user_id=user_id, project_id=project_id,
            session_uuid=session_uuid, agent_id=agent_id, loop=loop,
        )


async def _launch_scan_locked(*, pcap_path: str, user_id: int, project_id: int, session_uuid: str,
                               agent_id: int | None, loop: asyncio.AbstractEventLoop) -> None:
    run_id = session_uuid
    report_path = _report_path_for(pcap_path, user_id, project_id, run_id)

    args = list(config.MARLINSPIKE_ENGINE_CMD) + [
        "--pcap", pcap_path, "--fast", "--collapse-threshold", "50", "--no-grassmarlin",
        "-o", report_path, "chain",
    ]

    log.info("session=%s launching scan for %s -> %s", session_uuid, pcap_path, report_path)

    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        cwd=config.REPORTS_DIR,
    )

    # Recorded immediately after spawn, with the real PID, so a reaper
    # scoped to this container (see run_store.get_active_agent_scans_for_recovery)
    # has a live PID to check if the gateway process itself dies mid-scan.
    await loop.run_in_executor(None, functools.partial(
        _record_start, run_id=run_id, user_id=user_id, project_id=project_id,
        pcap_path=pcap_path, report_path=report_path, engine_pid=proc.pid,
        engine_argv=args, agent_id=agent_id,
    ))

    tail_lines: list[str] = []

    async def _drain_stdout() -> None:
        while True:
            line = await proc.stdout.readline()
            if not line:
                return
            tail_lines.append(line.decode("utf-8", errors="replace").rstrip())
            if len(tail_lines) > 200:
                del tail_lines[: len(tail_lines) - 200]

    drain_task = asyncio.create_task(_drain_stdout())
    await proc.wait()
    await drain_task

    is_complete = recovery.report_complete(report_path)
    node_count = edge_count = 0
    error_tail = None
    if is_complete:
        status = "completed"
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                parsed = json.load(f)
            topology = parsed.get("topology") or parsed
            node_count = len(topology.get("nodes") or [])
            edge_count = len(topology.get("edges") or [])
        except Exception:
            pass  # cosmetic counts only — never worth failing the run over
    else:
        status = "failed"
        error_tail = "\n".join(tail_lines[-10:]) if tail_lines else (
            f"engine exited rc={proc.returncode} with no complete report"
        )

    await loop.run_in_executor(None, functools.partial(
        _record_finish, run_id=run_id, status=status, error_tail=error_tail,
        node_count=node_count, edge_count=edge_count,
    ))
    log.info("session=%s scan %s for %s -> %s", session_uuid, status, pcap_path, report_path)
