"""Tests for marlinspike.scheduler — the automated 2x/day capture trigger.

Covers the pure due-slot-detection logic in isolation (no DB needed) and
the DB-driven _run_due_schedules end-to-end (with _start_capture_session
monkeypatched — this is about scheduling correctness, not the capture
pipeline itself, which is covered by capture/api.py's own tests).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-scheduler")

import pytest

from marlinspike import scheduler
from marlinspike.app import create_app
from marlinspike.models import Agent, Project, User, db


# ── _due_slot_today (pure logic, no DB) ────────────────────────────────


def test_slot_not_yet_reached_today():
    now = datetime(2026, 1, 1, 5, 0, tzinfo=timezone.utc)
    schedule = {"times_utc": ["06:00", "18:00"]}
    assert not scheduler._due_slot_today(schedule, now, None)


def test_slot_due_right_now():
    now = datetime(2026, 1, 1, 6, 1, tzinfo=timezone.utc)
    schedule = {"times_utc": ["06:00", "18:00"]}
    assert scheduler._due_slot_today(schedule, now, None)


def test_slot_missed_past_grace_window():
    now = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)  # hours past 06:00
    schedule = {"times_utc": ["06:00"]}
    assert not scheduler._due_slot_today(schedule, now, None)


def test_slot_already_triggered_today_is_not_due_again():
    now = datetime(2026, 1, 1, 6, 1, tzinfo=timezone.utc)
    last_triggered = datetime(2026, 1, 1, 6, 0, 30, tzinfo=timezone.utc)
    schedule = {"times_utc": ["06:00"]}
    assert not scheduler._due_slot_today(schedule, now, last_triggered)


def test_second_daily_slot_is_due_after_first_already_fired():
    now = datetime(2026, 1, 1, 18, 1, tzinfo=timezone.utc)
    last_triggered = datetime(2026, 1, 1, 6, 0, 30, tzinfo=timezone.utc)  # this morning's slot
    schedule = {"times_utc": ["06:00", "18:00"]}
    assert scheduler._due_slot_today(schedule, now, last_triggered)


def test_same_slot_due_again_next_day():
    now = datetime(2026, 1, 2, 6, 1, tzinfo=timezone.utc)
    last_triggered = datetime(2026, 1, 1, 6, 0, 30, tzinfo=timezone.utc)  # yesterday
    schedule = {"times_utc": ["06:00"]}
    assert scheduler._due_slot_today(schedule, now, last_triggered)


def test_malformed_time_entry_is_ignored_not_fatal():
    now = datetime(2026, 1, 1, 6, 1, tzinfo=timezone.utc)
    schedule = {"times_utc": ["not-a-time", "06:00"]}
    assert scheduler._due_slot_today(schedule, now, None)


def test_empty_times_utc_never_due():
    now = datetime(2026, 1, 1, 6, 1, tzinfo=timezone.utc)
    assert not scheduler._due_slot_today({"times_utc": []}, now, None)


# ── _parse_schedule ─────────────────────────────────────────────────────


def test_parse_schedule_none_and_malformed():
    assert scheduler._parse_schedule(None) is None
    assert scheduler._parse_schedule("") is None
    assert scheduler._parse_schedule("not json") is None
    assert scheduler._parse_schedule("[]") is None  # valid json, not a dict


def test_parse_schedule_valid():
    assert scheduler._parse_schedule('{"enabled": true}') == {"enabled": True}


# ── _run_due_schedules (DB-driven) ──────────────────────────────────────


@pytest.fixture
def app():
    application = create_app()
    application.config["TESTING"] = True
    application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with application.app_context():
        db.drop_all()
        db.create_all()
    yield application


@pytest.fixture
def app_ctx(app):
    with app.app_context():
        yield


@pytest.fixture
def owner(app_ctx):
    u = User(username="sched-owner", password_hash="x", role="user")  # type: ignore
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def project(app_ctx, owner):
    p = Project(user_id=owner.id, name="proj")  # type: ignore
    db.session.add(p)
    db.session.commit()
    return p


def _due_schedule_json():
    now = datetime.now(timezone.utc)
    due_time = (now).strftime("%H:%M")
    return json.dumps({
        "enabled": True, "times_utc": [due_time], "duration_s": 300, "interface": "eth0",
    })


def test_run_due_schedules_starts_capture_on_online_agents(app, app_ctx, project, monkeypatch):
    project.capture_schedule = _due_schedule_json()
    db.session.commit()
    agent = Agent(agent_uuid="a1", project_id=project.id, name="agent-1", status="online")  # type: ignore
    db.session.add(agent)
    db.session.commit()

    calls = []

    def fake_start(**kwargs):
        # Extract plain values now, inside the same app_context this runs
        # under — kwargs["agent"] is a live ORM instance that becomes
        # detached once _run_due_schedules' app_context exits below.
        calls.append({
            "interface": kwargs["interface"], "max_duration_s": kwargs["max_duration_s"],
            "agent_id": kwargs["agent"].id, "actor_username": kwargs["actor_username"],
        })
        return {"ok": True, "session": {"session_uuid": "sess-x"}}, 201

    monkeypatch.setattr("marlinspike.capture.api._start_capture_session", fake_start)

    scheduler._run_due_schedules(app)

    assert len(calls) == 1
    assert calls[0]["interface"] == "eth0"
    assert calls[0]["max_duration_s"] == 300
    assert calls[0]["agent_id"] == agent.id
    assert calls[0]["actor_username"] == "scheduler"

    refreshed = db.session.get(Project, project.id)
    assert refreshed is not None
    assert refreshed.capture_schedule_last_triggered_at is not None


def test_run_due_schedules_skips_disabled_schedule(app, app_ctx, project, monkeypatch):
    project.capture_schedule = json.dumps({"enabled": False, "times_utc": ["00:00"]})
    db.session.commit()

    calls = []
    monkeypatch.setattr("marlinspike.capture.api._start_capture_session",
                         lambda **kw: calls.append(kw))
    scheduler._run_due_schedules(app)
    assert calls == []


def test_run_due_schedules_no_online_agents_still_marks_slot_fired(app, app_ctx, project, monkeypatch):
    """No online agents right now -> nothing to start, but the slot is
    still marked fired rather than retried every tick for the rest of its
    grace window."""
    project.capture_schedule = _due_schedule_json()
    db.session.commit()
    agent = Agent(agent_uuid="a1", project_id=project.id, name="agent-1", status="offline")  # type: ignore
    db.session.add(agent)
    db.session.commit()

    calls = []
    monkeypatch.setattr("marlinspike.capture.api._start_capture_session",
                         lambda **kw: calls.append(kw))
    scheduler._run_due_schedules(app)
    assert calls == []
    refreshed = db.session.get(Project, project.id)
    assert refreshed is not None
    assert refreshed.capture_schedule_last_triggered_at is not None


def test_run_due_schedules_not_due_yet_does_not_trigger(app, app_ctx, project, monkeypatch):
    far_future = (datetime.now(timezone.utc) + timedelta(hours=5)).strftime("%H:%M")
    project.capture_schedule = json.dumps({"enabled": True, "times_utc": [far_future],
                                            "duration_s": 300, "interface": "eth0"})
    db.session.commit()
    agent = Agent(agent_uuid="a1", project_id=project.id, name="agent-1", status="online")  # type: ignore
    db.session.add(agent)
    db.session.commit()

    calls = []
    monkeypatch.setattr("marlinspike.capture.api._start_capture_session",
                         lambda **kw: calls.append(kw))
    scheduler._run_due_schedules(app)
    assert calls == []
    refreshed = db.session.get(Project, project.id)
    assert refreshed is not None
    assert refreshed.capture_schedule_last_triggered_at is None
