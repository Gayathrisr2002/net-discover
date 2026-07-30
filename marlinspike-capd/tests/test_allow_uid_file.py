"""--allow-uid-file: the dynamic alternative to the static --allow-uid list.

Lets marlinspike-agent's and marlinspike-capd's own .deb postinst scripts
wire up cross-package socket access automatically (appending a uid to this
file) instead of requiring a manual `systemctl edit --full` + restart.
Re-read on every connection attempt via a cheap mtime check, so a change
takes effect immediately without restarting capd.
"""

from __future__ import annotations

import time

import pytest

from capd import server as capd_server


@pytest.fixture
def server(tmp_path):
    cfg = capd_server.ServerConfig(
        socket_path=tmp_path / "capd.sock",
        capture_root=tmp_path / "captures",
        allowed_uids={0},
    )
    return capd_server.CapdServer(cfg)


def test_no_file_configured_returns_static_set_only(server):
    assert server._effective_allowed_uids() == {0}


def test_missing_file_is_tolerated(tmp_path):
    cfg = capd_server.ServerConfig(
        socket_path=tmp_path / "capd.sock",
        capture_root=tmp_path / "captures",
        allowed_uids={0},
        allow_uid_file=tmp_path / "does-not-exist",
    )
    srv = capd_server.CapdServer(cfg)
    assert srv._effective_allowed_uids() == {0}


def test_uids_from_file_are_merged_with_static_set(tmp_path):
    uid_file = tmp_path / "allowed-uids"
    uid_file.write_text("1000\n1001\n")
    cfg = capd_server.ServerConfig(
        socket_path=tmp_path / "capd.sock",
        capture_root=tmp_path / "captures",
        allowed_uids={0},
        allow_uid_file=uid_file,
    )
    srv = capd_server.CapdServer(cfg)
    assert srv._effective_allowed_uids() == {0, 1000, 1001}


def test_blank_lines_and_comments_are_ignored(tmp_path):
    uid_file = tmp_path / "allowed-uids"
    uid_file.write_text("# marlinspike-agent\n1000\n\n# trailing comment\n")
    cfg = capd_server.ServerConfig(
        socket_path=tmp_path / "capd.sock",
        capture_root=tmp_path / "captures",
        allowed_uids={0},
        allow_uid_file=uid_file,
    )
    srv = capd_server.CapdServer(cfg)
    assert srv._effective_allowed_uids() == {0, 1000}


def test_non_numeric_lines_are_ignored_not_fatal(tmp_path):
    uid_file = tmp_path / "allowed-uids"
    uid_file.write_text("1000\nnot-a-uid\n1001\n")
    cfg = capd_server.ServerConfig(
        socket_path=tmp_path / "capd.sock",
        capture_root=tmp_path / "captures",
        allowed_uids={0},
        allow_uid_file=uid_file,
    )
    srv = capd_server.CapdServer(cfg)
    assert srv._effective_allowed_uids() == {0, 1000, 1001}


def test_appending_a_uid_takes_effect_without_recreating_the_server(tmp_path):
    """The whole point: a postinst script appends a uid to a file capd is
    already running against, with no restart — confirm a live CapdServer
    instance picks up the change on its next read."""
    uid_file = tmp_path / "allowed-uids"
    uid_file.write_text("1000\n")
    cfg = capd_server.ServerConfig(
        socket_path=tmp_path / "capd.sock",
        capture_root=tmp_path / "captures",
        allowed_uids={0},
        allow_uid_file=uid_file,
    )
    srv = capd_server.CapdServer(cfg)
    assert srv._effective_allowed_uids() == {0, 1000}

    # Force a distinct mtime — some filesystems have 1s resolution.
    time.sleep(1.01)
    uid_file.write_text("1000\n1002\n")
    assert srv._effective_allowed_uids() == {0, 1000, 1002}


def test_cache_is_reused_when_file_unchanged(tmp_path, monkeypatch):
    uid_file = tmp_path / "allowed-uids"
    uid_file.write_text("1000\n")
    cfg = capd_server.ServerConfig(
        socket_path=tmp_path / "capd.sock",
        capture_root=tmp_path / "captures",
        allowed_uids={0},
        allow_uid_file=uid_file,
    )
    srv = capd_server.CapdServer(cfg)
    srv._effective_allowed_uids()  # populates the cache

    read_calls = []
    original_read_text = type(uid_file).read_text

    def _tracking_read_text(self, *a, **k):
        read_calls.append(self)
        return original_read_text(self, *a, **k)

    monkeypatch.setattr(type(uid_file), "read_text", _tracking_read_text)
    srv._effective_allowed_uids()
    assert read_calls == []  # mtime unchanged -> no re-read
