"""Regression tests for agent/cli.py's --gateway HOST:PORT parsing.

_split_host_port used a plain rpartition(":"), which "successfully" split
a URL like "http://localhost:8765" into host="http://localhost", port=8765
— a value that passes int(port) but produces a hostname getaddrinfo can
never resolve, surfacing as a confusing socket.gaierror deep in a
traceback instead of a clear, immediate CLI error. Users instinctively
type a URL here since that's the muscle-memory format for almost every
other network address, even though this flag wants a bare HOST:PORT pair.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.cli import _split_host_port


def test_plain_host_port():
    assert _split_host_port("localhost:8765") == ("localhost", 8765)
    assert _split_host_port("192.168.1.5:8765") == ("192.168.1.5", 8765)


def test_http_scheme_prefix_is_stripped():
    assert _split_host_port("http://localhost:8765") == ("localhost", 8765)


def test_https_scheme_prefix_is_stripped():
    assert _split_host_port("https://192.168.1.5:8765") == ("192.168.1.5", 8765)


def test_missing_colon_rejected():
    with pytest.raises(SystemExit):
        _split_host_port("localhost")


def test_empty_host_rejected():
    with pytest.raises(SystemExit):
        _split_host_port(":8765")


def test_non_numeric_port_rejected():
    with pytest.raises(SystemExit):
        _split_host_port("localhost:notaport")


def test_garbage_input_rejected():
    with pytest.raises(SystemExit):
        _split_host_port("not-a-valid-thing")
