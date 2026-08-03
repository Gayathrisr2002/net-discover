"""Tests for marlinspike/fleet/gateway/db.py's begin_pcap_upload/
finish_pcap_upload — ownership, path-safety, and extension checks behind
the pcap_chunk/pcap_complete transport (see test_fleet_gateway_pcap.py for
the chunk-reassembly logic these two functions sit underneath).
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-gateway-db-pcap")

from marlinspike.app import create_app
from marlinspike.fleet.gateway import db as gw_db
from marlinspike.models import Agent, CaptureSession, Project, User, db


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr("marlinspike.config.UPLOADS_DIR", str(tmp_path / "uploads"))
    application = create_app()
    application.config["TESTING"] = True
    application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with application.app_context():
        db.drop_all()
        db.create_all()
    # gw_db.get_app() lazily caches its own minimal Flask app on first
    # call — without pointing it at THIS test's already-initialized app,
    # it builds an unrelated, tableless in-memory SQLite of its own.
    gw_db._app = application
    yield application
    gw_db._app = None


@pytest.fixture
def app_ctx(app):
    with app.app_context():
        yield


@pytest.fixture
def owner(app_ctx):
    u = User(username="pcap-owner", password_hash="x", role="user")
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def project(app_ctx, owner):
    p = Project(user_id=owner.id, name="proj")
    db.session.add(p)
    db.session.commit()
    return p


@pytest.fixture
def agent(app_ctx, project):
    a = Agent(agent_uuid="agent-uuid-1", project_id=project.id, name="agent-1", status="online")
    db.session.add(a)
    db.session.commit()
    return a


@pytest.fixture
def other_agent(app_ctx, project):
    a = Agent(agent_uuid="agent-uuid-2", project_id=project.id, name="agent-2", status="online")
    db.session.add(a)
    db.session.commit()
    return a


@pytest.fixture
def capture_session(app_ctx, project, agent):
    cs = CaptureSession(
        session_uuid="sess-uuid-1", user_id=project.user_id, project_id=project.id,
        agent_id=agent.id, interface="eth0", status="running",
    )
    db.session.add(cs)
    db.session.commit()
    return cs


@pytest.mark.parametrize("filename", ["cap.exe", "cap", "../../etc/passwd", ".", ".."])
def test_begin_pcap_upload_rejects_unsafe_or_wrong_extension_filenames(
        app_ctx, capture_session, agent, filename):
    result = gw_db.begin_pcap_upload(
        session_uuid=capture_session.session_uuid, filename=filename, agent_uuid=agent.agent_uuid,
    )
    assert result is None


@pytest.mark.parametrize("filename", ["cap.pcap", "cap.pcapng", "CAP.PCAPNG"])
def test_begin_pcap_upload_accepts_pcap_extensions(app_ctx, capture_session, agent, filename):
    result = gw_db.begin_pcap_upload(
        session_uuid=capture_session.session_uuid, filename=filename, agent_uuid=agent.agent_uuid,
    )
    assert result is not None
    partial_path, final_path = result
    assert partial_path == final_path + ".partial"
    assert os.path.basename(final_path).lower() == filename.lower()


def test_begin_pcap_upload_rejects_unknown_session(app_ctx, agent):
    result = gw_db.begin_pcap_upload(
        session_uuid="does-not-exist", filename="cap.pcap", agent_uuid=agent.agent_uuid,
    )
    assert result is None


def test_begin_pcap_upload_rejects_session_owned_by_different_agent(
        app_ctx, capture_session, other_agent):
    result = gw_db.begin_pcap_upload(
        session_uuid=capture_session.session_uuid, filename="cap.pcap",
        agent_uuid=other_agent.agent_uuid,
    )
    assert result is None


def test_begin_pcap_upload_rejects_local_session_with_no_agent(app_ctx, project):
    cs = CaptureSession(
        session_uuid="local-sess", user_id=project.user_id, project_id=project.id,
        agent_id=None, interface="eth0", status="running",
    )
    db.session.add(cs)
    db.session.commit()
    result = gw_db.begin_pcap_upload(
        session_uuid="local-sess", filename="cap.pcap", agent_uuid="whatever",
    )
    assert result is None


def test_begin_pcap_upload_rejects_session_with_no_project(app_ctx, owner, agent):
    cs = CaptureSession(
        session_uuid="no-project-sess", user_id=owner.id, project_id=None,
        agent_id=agent.id, interface="eth0", status="running",
    )
    db.session.add(cs)
    db.session.commit()
    result = gw_db.begin_pcap_upload(
        session_uuid="no-project-sess", filename="cap.pcap", agent_uuid=agent.agent_uuid,
    )
    assert result is None


def test_begin_pcap_upload_path_lands_under_uploads_dir(app_ctx, capture_session, agent, project):
    from marlinspike import config
    partial_path, final_path = gw_db.begin_pcap_upload(
        session_uuid=capture_session.session_uuid, filename="cap.pcapng", agent_uuid=agent.agent_uuid,
    )
    expected_dir = os.path.join(config.UPLOADS_DIR, str(project.user_id), str(project.id))
    assert os.path.dirname(final_path) == expected_dir
    assert os.path.isdir(expected_dir)


def test_finish_pcap_upload_publishes_file_and_resolves_ids(
        app_ctx, capture_session, agent, project, tmp_path):
    partial_path, final_path = gw_db.begin_pcap_upload(
        session_uuid=capture_session.session_uuid, filename="cap.pcapng", agent_uuid=agent.agent_uuid,
    )
    with open(partial_path, "wb") as f:
        f.write(b"fake pcap bytes")

    result = gw_db.finish_pcap_upload(
        partial_path=partial_path, final_path=final_path,
        session_uuid=capture_session.session_uuid, agent_uuid=agent.agent_uuid,
    )
    assert result == (project.user_id, project.id, agent.id)
    assert os.path.isfile(final_path)
    assert not os.path.isfile(partial_path)
    with open(final_path, "rb") as f:
        assert f.read() == b"fake pcap bytes"


def test_finish_pcap_upload_rejects_wrong_agent_but_keeps_file(
        app_ctx, capture_session, agent, other_agent, tmp_path):
    partial_path, final_path = gw_db.begin_pcap_upload(
        session_uuid=capture_session.session_uuid, filename="cap.pcapng", agent_uuid=agent.agent_uuid,
    )
    with open(partial_path, "wb") as f:
        f.write(b"fake pcap bytes")

    result = gw_db.finish_pcap_upload(
        partial_path=partial_path, final_path=final_path,
        session_uuid=capture_session.session_uuid, agent_uuid=other_agent.agent_uuid,
    )
    assert result is None
    # Already published (rename happens before the ownership re-check) —
    # deliberate: the file is fully written and complete by this point, no
    # reason to leave it stranded under a .partial name over a downstream
    # DB lookup failure.
    assert os.path.isfile(final_path)
    assert not os.path.isfile(partial_path)


def test_finish_pcap_upload_rejects_unknown_session(app_ctx, agent, tmp_path):
    partial_path = str(tmp_path / "cap.pcapng.partial")
    final_path = str(tmp_path / "cap.pcapng")
    with open(partial_path, "wb") as f:
        f.write(b"data")
    result = gw_db.finish_pcap_upload(
        partial_path=partial_path, final_path=final_path,
        session_uuid="does-not-exist", agent_uuid=agent.agent_uuid,
    )
    assert result is None


def test_finish_pcap_upload_missing_partial_file_returns_none(app_ctx, capture_session, agent, tmp_path):
    result = gw_db.finish_pcap_upload(
        partial_path=str(tmp_path / "nonexistent.partial"),
        final_path=str(tmp_path / "nonexistent"),
        session_uuid=capture_session.session_uuid, agent_uuid=agent.agent_uuid,
    )
    assert result is None
