"""Tests for marlinspike.fleet.api's _validate_schedule_body — the
validation behind PUT /api/fleet/sites/<id>/capture-schedule."""

from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-schedule-validation")

from marlinspike.fleet.api import _validate_schedule_body


def test_valid_full_schedule():
    assert _validate_schedule_body({
        "enabled": True, "times_utc": ["06:00", "18:00"],
        "duration_s": 300, "interface": "eth0", "bpf_filter": "",
    }) is None


def test_empty_body_is_valid_clears_schedule():
    assert _validate_schedule_body({}) is None


def test_unknown_key_rejected():
    err = _validate_schedule_body({"unexpected_field": 1})
    assert err is not None and "unknown key" in err


def test_enabled_must_be_bool():
    assert _validate_schedule_body({"enabled": "yes"}) is not None


def test_times_utc_must_be_nonempty_list():
    assert _validate_schedule_body({"times_utc": []}) is not None
    assert _validate_schedule_body({"times_utc": "06:00"}) is not None


def test_times_utc_entries_must_be_hh_mm():
    assert _validate_schedule_body({"times_utc": ["25:00"]}) is not None
    assert _validate_schedule_body({"times_utc": ["6:00"]}) is not None
    assert _validate_schedule_body({"times_utc": ["06:60"]}) is not None
    assert _validate_schedule_body({"times_utc": ["06:00"]}) is None


def test_duration_s_must_be_positive_int():
    assert _validate_schedule_body({"duration_s": 0}) is not None
    assert _validate_schedule_body({"duration_s": -5}) is not None
    assert _validate_schedule_body({"duration_s": "300"}) is not None
    assert _validate_schedule_body({"duration_s": True}) is not None  # bool is an int subclass
    assert _validate_schedule_body({"duration_s": 300}) is None


def test_enabled_requires_interface_and_times():
    err = _validate_schedule_body({"enabled": True})
    assert err is not None and "interface" in err

    err = _validate_schedule_body({"enabled": True, "interface": "eth0"})
    assert err is not None and "times_utc" in err

    assert _validate_schedule_body({
        "enabled": True, "interface": "eth0", "times_utc": ["06:00"],
    }) is None


def test_disabled_schedule_does_not_require_interface_or_times():
    assert _validate_schedule_body({"enabled": False}) is None
