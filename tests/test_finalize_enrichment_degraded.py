"""Regression tests for Finding #10 (plugin failure swallowed, run still
"completed").

``_finalize_run`` runs the MITRE/ARP/APT/CISA enrichment plugins after a
successful engine chain. Each plugin call is wrapped in a bare
``try/except Exception`` that only appends a ``[!] ... skipped`` line to the
scan output and then unconditionally sets ``status = "completed"``. A report
whose enrichment silently failed (plugin timeout, subprocess crash, network
hiccup) is therefore indistinguishable from a fully-enriched one — the run
shows green and the only trace is a buried stdout line. For a tool whose value
is the ATT&CK / IOC context it adds, that is silent engagement-data loss.

The fix keeps ``status = "completed"`` (the primary report is still valid and
viewable — every UI consumer keys on that) but records a distinct, durable
"enrichment degraded" signal: ``run_state["enrichment_degraded"]``, the list of
failed plugin ids, and a reason persisted to ``ScanHistory.error_tail`` so it
survives to the scans list / status endpoint instead of vanishing with the
in-memory output buffer.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-finalize-degraded")

import pytest


@pytest.fixture
def app():
    from marlinspike.app import create_app
    from marlinspike.models import db
    application = create_app()
    application.config["TESTING"] = True
    application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with application.app_context():
        db.drop_all()
        db.create_all()
    return application


def _run_state():
    from datetime import datetime, timezone
    return {
        "process": None,
        "output": ["[*] chain complete"],
        "status": "running",
        "stage": 5,
        "stage_name": "Risk",
        "stages": [],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "return_code": 0,           # engine succeeded — enrichment is what fails
        "artifacts_produced": {},
        "project_id": None,
        "user_id": 1,
        "stop_requested": False,
        "command": "chain",
        "scan_profile": "full",
        "report_path": "",
        "report_filename": "",
    }


def _write_report(tmp_path):
    import json
    p = tmp_path / "marlinspike-chain-report.json"
    p.write_text(json.dumps({"topology": {"nodes": [{"id": "a"}], "edges": []}}))
    return str(p)


def _seed_scan_row(app, run_id, report_path):
    from marlinspike.models import ScanHistory, User, db
    with app.app_context():
        if User.query.get(1) is None:
            db.session.add(User(id=1, username="fin_user", password_hash="x", role="admin"))
        db.session.add(ScanHistory(
            run_id=run_id, user_id=1, command="chain", scan_profile="full",
            status="running", report_path=report_path,
        ))
        db.session.commit()


def test_plugin_exception_marks_run_degraded_not_clean_completed(app, tmp_path, monkeypatch):
    import marlinspike.app as appmod

    report_path = _write_report(tmp_path)
    run_id = "fin-degraded"
    _seed_scan_row(app, run_id, report_path)

    # MITRE plugin blows up (timeout/crash/etc.); the others succeed with no artifact.
    def boom(_report_path):
        raise RuntimeError("mitre subprocess timed out")

    monkeypatch.setattr(appmod, "_run_mitre_plugin", boom)
    monkeypatch.setattr(appmod, "_run_arp_plugin", lambda p: ("", []))
    monkeypatch.setattr(appmod, "_run_apt_plugin", lambda p: ("", []))
    monkeypatch.setattr(appmod, "_run_cisa_plugin", lambda p: ("", []))

    run_state = _run_state()
    appmod._finalize_run(app, run_id, run_state, report_path)

    # Primary report is still valid → status stays "completed" (UI keys on it).
    assert run_state["status"] == "completed"

    # ...but the run must carry a distinct, inspectable degraded signal.
    assert run_state.get("enrichment_degraded") is True, (
        "a swallowed plugin failure left the run indistinguishable from a clean run"
    )
    assert "marlinspike-mitre" in (run_state.get("enrichment_failures") or [])

    # And it must be durable — persisted to ScanHistory.error_tail, not just the
    # ephemeral in-memory output buffer.
    from marlinspike.models import ScanHistory
    with app.app_context():
        rec = ScanHistory.query.filter_by(run_id=run_id).first()
        assert rec.status == "completed"
        assert rec.error_tail and "marlinspike-mitre" in rec.error_tail


def test_all_plugins_succeed_is_not_degraded(app, tmp_path, monkeypatch):
    import marlinspike.app as appmod

    report_path = _write_report(tmp_path)
    run_id = "fin-clean"
    _seed_scan_row(app, run_id, report_path)

    monkeypatch.setattr(appmod, "_run_mitre_plugin", lambda p: ("mitre.json", ["ok"]))
    monkeypatch.setattr(appmod, "_run_arp_plugin", lambda p: ("arp.json", ["ok"]))
    monkeypatch.setattr(appmod, "_run_apt_plugin", lambda p: ("apt.json", ["ok"]))
    monkeypatch.setattr(appmod, "_run_cisa_plugin", lambda p: ("cisa.json", ["ok"]))

    run_state = _run_state()
    appmod._finalize_run(app, run_id, run_state, report_path)

    assert run_state["status"] == "completed"
    assert not run_state.get("enrichment_degraded")
    assert not run_state.get("enrichment_failures")
