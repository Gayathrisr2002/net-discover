"""Regression test (recovery/concurrency plumbing #68): missing index on
scan_history.status.

The recovery reaper (`filter_by(status="running")` on every boot) and the
`MARLINSPIKE_RUN_STORE=db` concurrency check (`filter_by(status="running",
user_id=...)` on every scan-start) query scan_history by status, but the column
had no index — a full table scan that gets slow as history grows. `run_id` is
unique (indexed), `status` was not.

Fix: a composite index on (status, user_id) — its leading `status` column serves
the reaper's status-only query, and the full index serves the per-user
concurrency count.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-scan-index")


def test_scan_history_status_is_indexed():
    from marlinspike.models import ScanHistory

    indexed_leading = set()
    all_indexed = set()
    for ix in ScanHistory.__table__.indexes:
        cols = list(ix.columns.keys())
        all_indexed.update(cols)
        if cols:
            indexed_leading.add(cols[0])

    assert "status" in all_indexed, "scan_history.status has no index (full scan on recovery/concurrency queries)"
    assert "status" in indexed_leading, "the status index must lead with status to serve status-only queries"


def test_scan_history_status_user_composite_present():
    from marlinspike.models import ScanHistory
    combos = {tuple(ix.columns.keys()) for ix in ScanHistory.__table__.indexes}
    assert ("status", "user_id") in combos, (
        f"expected a (status, user_id) composite index; have {combos}"
    )
