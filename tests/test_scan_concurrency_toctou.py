"""Regression tests for Finding #8 (TOCTOU race on scan concurrency limits).

The scan-start route checked the concurrency limit under ``_runs_lock``, released
the lock, then registered the run ~100 lines later under a *separate* lock
acquisition. Two near-simultaneous requests could both observe
``active_count < limit`` before either registered — so both proceeded and the
per-user / per-tier concurrency cap was exceeded.

Fix: ``_reserve_scan_slot`` performs the limit check AND reserves the slot (a
``pending`` placeholder in ``_run_registry``) inside a single critical section,
so a reservation counts immediately against the very next check. The route uses
it, releasing the reservation (``_release_scan_slot``) if start-up fails.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-toctou")


@pytest.fixture
def app():
    from marlinspike.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    return application


def test_reserve_scan_slot_reservation_counts_immediately(app):
    """After a successful reservation the slot must count against the next check
    within the same lock discipline — the property that closes the TOCTOU window."""
    import marlinspike.app as appmod

    # Force a global limit of exactly 1.
    appmod.set_concurrent_check_fn(lambda uid: (len(appmod._get_active_runs()), 1))
    try:
        with app.app_context():
            appmod._run_registry.clear()

            ok1, info1 = appmod._reserve_scan_slot(1, "toctou-a", "chain")
            assert ok1 is True and info1 is None

            # The first reservation must already count — the second is rejected
            # even though no full run_state was ever registered.
            ok2, info2 = appmod._reserve_scan_slot(1, "toctou-b", "chain")
            assert ok2 is False, "second reservation slipped through — TOCTOU window still open"
            scan_limit, active_ids = info2
            assert scan_limit == 1
            assert "toctou-a" in active_ids
    finally:
        appmod.set_concurrent_check_fn(None)
        appmod._run_registry.pop("toctou-a", None)
        appmod._run_registry.pop("toctou-b", None)


def test_release_scan_slot_frees_reservation(app):
    """A failed start-up must release its reservation so the slot is reusable."""
    import marlinspike.app as appmod

    appmod.set_concurrent_check_fn(lambda uid: (len(appmod._get_active_runs()), 1))
    try:
        with app.app_context():
            appmod._run_registry.clear()

            ok1, _ = appmod._reserve_scan_slot(1, "rel-a", "chain")
            assert ok1 is True
            appmod._release_scan_slot("rel-a")

            # Slot freed → a new reservation succeeds.
            ok2, _ = appmod._reserve_scan_slot(1, "rel-b", "chain")
            assert ok2 is True, "reservation was not released"
    finally:
        appmod.set_concurrent_check_fn(None)
        appmod._run_registry.pop("rel-a", None)
        appmod._run_registry.pop("rel-b", None)


def test_release_does_not_evict_a_running_run(app):
    """Releasing must only drop a still-pending reservation, never a live run."""
    import marlinspike.app as appmod
    with app.app_context():
        appmod._run_registry.clear()
        appmod._run_registry["live"] = {"status": "running", "user_id": 1, "finished_at": None}
        appmod._release_scan_slot("live")
        assert "live" in appmod._run_registry, "release wrongly evicted a running run"
        appmod._run_registry.pop("live", None)
