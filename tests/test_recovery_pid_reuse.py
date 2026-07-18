"""Regression tests for Finding #23 (PID-reuse defense uses substring match).

``_live_argv_matches`` joined the live process's argv into one string and tested
``token in actual_blob`` — a *substring* match. So a distinctive token like
``marlinspike`` matched any unrelated process whose command line merely contained
that substring (``/opt/marlinspike-tools/daemon``, a shell editing
``marlinspike_notes.txt``, even the install path). On a busy host where the
engine's PID was recycled, the reaper could then treat an unrelated process as
"the scan still running" and re-attach to it.

Fix: match distinctive tokens against *whole argv elements* (exact membership),
not as substrings of the joined command line.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from marlinspike.recovery import _live_argv_matches


def test_substring_in_path_no_longer_false_matches():
    # Unrelated process whose PATH merely contains "marlinspike" as a substring.
    actual = ["/opt/marlinspike-tools/daemon", "--serve"]
    expected = [sys.executable, "-m", "marlinspike"]
    assert not _live_argv_matches(actual, expected), (
        "substring match falsely identified an unrelated process as our engine"
    )


def test_exact_token_element_matches():
    # Real engine argv: distinctive tokens are separate argv elements.
    actual = ["python3", "-m", "marlinspike", "--pcap", "/tmp/x.pcap", "chain"]
    expected = [sys.executable, "-m", "marlinspike", "--pcap", "/tmp/x.pcap", "chain"]
    assert _live_argv_matches(actual, expected)


def test_pcap_path_element_matches():
    actual = ["python3", "-m", "marlinspike", "/data/captures/engagement.pcap", "chain"]
    expected = [sys.executable, "-m", "marlinspike", "/data/captures/engagement.pcap", "chain"]
    assert _live_argv_matches(actual, expected)


def test_unrelated_shell_does_not_match():
    actual = ["/bin/bash", "-c", "sleep 100"]
    expected = [sys.executable, "-m", "marlinspike", "/tmp/x.pcap"]
    assert not _live_argv_matches(actual, expected)


def test_flags_and_interpreter_alone_do_not_match():
    # Only flags + interpreter in common → not distinctive enough to claim identity.
    actual = ["python3", "-m", "somethingelse"]
    expected = [sys.executable, "-m", "marlinspike"]
    assert not _live_argv_matches(actual, expected)
