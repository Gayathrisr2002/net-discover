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


async def launch_scan(*, pcap_path: str, user_id: int, project_id: int, session_uuid: str,
                       agent_id: int | None, loop: asyncio.AbstractEventLoop) -> None:
    """Spawn the analysis engine for a fully-received agent pcap and wait
    for it to finish. Reuses session_uuid as the ScanHistory run_id —
    record_start is an upsert-by-run_id (run_store.record_start queries
    the existing row first), so a session that ships more than one
    rotation just updates the same row on each subsequent call rather than
    colliding on run_id's unique constraint.
    """
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
