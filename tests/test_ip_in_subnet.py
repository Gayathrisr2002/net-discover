"""Regression tests for Finding #14 (``_ip_in_subnet`` naive string-prefix match
breaks ``--subnet-map`` Purdue classification).

The check was ``ip.startswith(subnet.split('/')[0].rsplit('.', 1)[0])`` — it threw
away the CIDR prefix length and always compared the first three octets as a
string. So a ``/16`` subnet only matched hosts sharing the third octet, a ``/25``
was entirely wrong, and string-prefix matching produced both false negatives and
false positives. Purdue-level misclassification changes cross-zone-violation
findings — a core OT detection — so a documented, expected subnet-map override
silently produced wrong zoning.

Fix: use the stdlib ``ipaddress`` module for a correct CIDR membership test.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from marlinspike.engine import TopologyBuilder

_in = TopologyBuilder._ip_in_subnet


def test_slash16_matches_across_third_octet():
    # Old code checked startswith("10.5.0") → missed anything not in 10.5.0.x
    assert _in("10.5.9.9", "10.5.0.0/16")
    assert _in("10.5.255.1", "10.5.0.0/16")


def test_slash24_membership():
    assert _in("192.168.1.50", "192.168.1.0/24")
    assert not _in("192.168.2.50", "192.168.1.0/24")


def test_slash25_non_octet_aligned():
    # 10.0.0.0/25 covers .0-.127 only
    assert _in("10.0.0.100", "10.0.0.0/25")
    assert not _in("10.0.0.200", "10.0.0.0/25")


def test_no_string_prefix_false_positive():
    # "10.0.0.0/24" must NOT match 100.0.0.x (string prefix "10.0.0" pitfalls)
    assert not _in("10.0.99.1", "10.0.0.0/24")
    assert not _in("100.0.0.1", "10.0.0.0/8")  # 100.x is NOT in 10.0.0.0/8
    assert not _in("11.0.0.1", "10.0.0.0/8")


def test_single_host_and_invalid():
    assert _in("10.0.0.5", "10.0.0.5")          # bare host == /32
    assert not _in("10.0.0.6", "10.0.0.5")
    assert not _in("not-an-ip", "10.0.0.0/24")  # invalid input → False, no crash
    assert not _in("10.0.0.5", "garbage")
