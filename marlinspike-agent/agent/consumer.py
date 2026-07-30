"""Local directory helpers for the agent's capture-shipping pipeline.

No local analysis happens on this agent — each rotated pcap is shipped
upward as raw bytes for the fleet-gateway to analyze (see agent/client.py).
This module just centralizes where the durable local spool (a rotated
pcap that couldn't be shipped right away, kept as a reference — not a
copy — until the next reconnect; see client.py's _spool_pcap_ref/
_flush_spool) lives on disk.
"""

from __future__ import annotations

import os
import tempfile


def default_spool_dir() -> str:
    """Durable local queue: a reference to a not-yet-shipped rotated pcap
    is written here instead of the capture being dropped, and flushed on
    the next successful reconnect. A flat-file spool rather than SQLite —
    this only ever holds a handful of not-yet-shipped references, and
    plain files are easy to inspect/clear by hand if something goes wrong."""
    return os.path.join(tempfile.gettempdir(), "marlinspike-agent-spool")
