"""Regression test: capd silently dropped rotation files when dumpcap's own
ring eviction outpaced the poll interval.

dumpcap's ring-buffer sequence number (cap_00001_<ts>.pcapng, cap_00002_...)
was confirmed empirically to increment forever and never wrap — only the
files on disk get evicted once the ring cap (files:N) is exceeded, the
numbering itself doesn't reset. That means comparing the lowest currently-
existing sequence number against the highest one any poll has ever
accounted for reliably detects a gap: if more rotations happened between
two polls than ring_files allows, the evicted files' sequence numbers never
appear in any glob result this class ever sees, so the old code (which only
ever compared "previous active filename" against "current file listing")
had no way to notice they ever existed at all.

Fix: _snapshot() now tracks the highest sequence number accounted for and
flags a gap the moment the lowest currently-existing file's sequence number
jumps ahead of it by more than one, logging a warning and accumulating the
lost count on CaptureStats.files_lost_count.
"""

from __future__ import annotations

import os

import pytest

from capd.supervisor import CaptureConfig, CaptureSupervisor, _seq_of


@pytest.fixture
def sup(tmp_path):
    cfg = CaptureConfig(session_id="rotgap", interface="eth0", output_dir=tmp_path)
    return CaptureSupervisor(cfg, dumpcap_path="/bin/true")


def _touch(path, size=0):
    with open(path, "wb") as f:
        f.write(b"x" * size)


def test_seq_of_parses_dumpcap_ring_filename():
    assert _seq_of("/tmp/x/cap_00177_20260728112303.pcapng") == 177
    assert _seq_of("/tmp/x/cap_00001_20260101000000.pcapng") == 1
    assert _seq_of("/tmp/x/not-a-cap-file.pcapng") is None


def test_no_gap_when_polling_keeps_up(sup, tmp_path):
    """The ordinary case: every rotation is observed before the next one —
    files_lost_count must stay 0."""
    _touch(tmp_path / "cap_00001_20260101000001.pcapng", 100)
    stats1 = sup._snapshot(running=True)
    assert stats1.files_lost_count == 0

    _touch(tmp_path / "cap_00002_20260101000002.pcapng", 100)
    stats2 = sup._snapshot(running=True)
    assert stats2.files_lost_count == 0
    assert "cap_00001_20260101000001.pcapng" in [os.path.basename(f) for f in stats2.files_closed]


def test_gap_detected_when_ring_evicts_before_any_poll_sees_it(sup, tmp_path):
    """Simulates the actual bug: between two polls, several rotations
    happened AND got evicted by dumpcap's own ring (files:N) before this
    class ever saw them on disk — only files far ahead in sequence remain."""
    _touch(tmp_path / "cap_00001_20260101000001.pcapng", 100)
    stats1 = sup._snapshot(running=True)
    assert stats1.files_lost_count == 0

    # Ring evicted 1-14 already; only 15-17 are still on disk when this
    # poll runs (files 2-14 were created AND evicted with no poll in
    # between — exactly what a too-slow poll interval under high rotation
    # produces in real dumpcap ring-buffer mode).
    os.unlink(tmp_path / "cap_00001_20260101000001.pcapng")
    _touch(tmp_path / "cap_00015_20260101000015.pcapng", 100)
    _touch(tmp_path / "cap_00016_20260101000016.pcapng", 100)
    _touch(tmp_path / "cap_00017_20260101000017.pcapng", 100)
    stats2 = sup._snapshot(running=True)

    assert stats2.files_lost_count == 13, "sequence 2-14 (13 files) were evicted unseen"


def test_gap_count_is_cumulative_across_polls(sup, tmp_path):
    _touch(tmp_path / "cap_00001_20260101000001.pcapng", 100)
    sup._snapshot(running=True)

    # Ring evicted file 1 by the time this poll runs — real eviction
    # deletes the old file, it doesn't just stop being "active".
    os.unlink(tmp_path / "cap_00001_20260101000001.pcapng")
    _touch(tmp_path / "cap_00010_20260101000010.pcapng", 100)
    stats = sup._snapshot(running=True)
    assert stats.files_lost_count == 8  # sequence 2-9

    os.unlink(tmp_path / "cap_00010_20260101000010.pcapng")
    _touch(tmp_path / "cap_00025_20260101000025.pcapng", 100)
    stats = sup._snapshot(running=True)
    assert stats.files_lost_count == 8 + 14  # + sequence 11-24
