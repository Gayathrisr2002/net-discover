"""Automated capture scheduling — triggers a capture start on every online
agent at a site when one of its configured daily UTC time slots is due.

A plain threading.Thread + sleep-loop, matching the pattern already used
by recovery.py's own background watcher — no new dependency
(APScheduler/Celery aren't in requirements.txt) is justified for something
this simple, and the deployment is a single process today (Dockerfile's
CMD runs plain `app.run()`, not gunicorn).

Reuses capture/api.py's _start_capture_session — the exact same policy
gates (interface allowlist, duration cap, retained-bytes cap) apply to an
automated trigger as to a manual click; the only thing this module adds
is automating the *start* trigger. Stop/ship/analyze already happen on
their own once a session is running (CaptureSession.max_duration_s's
self-expiring finalizer, then the pcap-forwarding pipeline).

Only ever started from app.py's `if __name__ == "__main__":` block, never
from create_app() itself — every test calls create_app() directly, and a
persistent background thread started there would leak across the whole
test suite (each test's app_context would then be raced by this thread's
own periodic app.app_context() calls against a completely different test
database).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone

from marlinspike.models import Agent, Project, Site, db

log = logging.getLogger("marlinspike.scheduler")

_POLL_INTERVAL_S = 60
# How long past a slot's exact time it's still considered "due" — wide
# enough to tolerate this thread's own 60s poll granularity plus any
# ordinary scheduling jitter, narrow enough that a slot missed by more
# than this (app was down, gateway restarting, etc.) is simply skipped
# for that day rather than firing hours late.
_SLOT_GRACE_S = 180


def _parse_schedule(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _due_slot_today(schedule: dict, now: datetime, last_triggered_at) -> bool:
    """True if some configured times_utc entry is due right now (within
    grace) and hasn't already been triggered today (or, for the grace
    window's sake, since it last became due)."""
    for raw_time in schedule.get("times_utc") or []:
        try:
            hh, mm = str(raw_time).split(":")
            hh, mm = int(hh), int(mm)
        except (ValueError, TypeError):
            continue  # malformed entry — ignore it, not fatal to the others
        slot_today = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if slot_today > now:
            continue  # hasn't happened yet today
        if (now - slot_today).total_seconds() > _SLOT_GRACE_S:
            continue  # missed its window — don't fire hours late
        if last_triggered_at is not None:
            lt = last_triggered_at
            if lt.tzinfo is None:
                lt = lt.replace(tzinfo=timezone.utc)
            if lt >= slot_today:
                continue  # this exact slot already fired
        return True
    return False


def _run_due_schedules(app) -> None:
    from marlinspike.capture.api import _start_capture_session

    now = datetime.now(timezone.utc)
    with app.app_context():
        sites = Site.query.filter(Site.capture_schedule.isnot(None)).all()
        for site in sites:
            schedule = _parse_schedule(site.capture_schedule)
            if not schedule or not schedule.get("enabled"):
                continue
            if not _due_slot_today(schedule, now, site.capture_schedule_last_triggered_at):
                continue

            interface = str(schedule.get("interface") or "").strip()
            duration_s = int(schedule.get("duration_s") or 300)
            bpf_filter = str(schedule.get("bpf_filter") or "")

            project = Project.query.get(site.project_id)
            if project is None:
                log.warning("scheduler: site %s's project %s is gone — skipping", site.id, site.project_id)
                continue

            online_agents = Agent.query.filter_by(site_id=site.id, status="online").all()
            if not online_agents:
                log.info("scheduler: site %s has a due slot but no online agents", site.id)
            for agent in online_agents:
                result, status = _start_capture_session(
                    user_id=project.user_id, project=project, agent=agent,
                    interface=interface, bpf_filter=bpf_filter,
                    ring_filesize_kb=200_000, ring_files=10, max_duration_s=duration_s,
                    actor_username="scheduler",
                )
                if status == 201:
                    log.info("scheduler: started capture on agent %s (site %s)", agent.id, site.id)
                else:
                    log.warning("scheduler: failed to start capture on agent %s (site %s): %s",
                                agent.id, site.id, result.get("error"))

            # Marked fired even with zero online agents — deliberate,
            # otherwise a site with no online agents would retry every
            # tick for the rest of the grace window instead of just
            # waiting for its next scheduled slot.
            site.capture_schedule_last_triggered_at = now
            db.session.commit()


def _loop(app) -> None:
    while True:
        try:
            _run_due_schedules(app)
        except Exception:
            log.exception("scheduler: tick failed")
        time.sleep(_POLL_INTERVAL_S)


def start(app) -> threading.Thread:
    t = threading.Thread(target=_loop, args=(app,), daemon=True, name="capture-scheduler")
    t.start()
    return t
