"""Regression tests for Finding #12 (benign NTP/DNS flagged as CRITICAL C2
beaconing).

NTP (123) and DNS (53) are *inherently periodic* — an NTP client polls its
server on a fixed cadence, so a conversation to a public NTP/DNS server scores
high on the beacon detector. The public-destination beaconing branch raised a
CRITICAL "C2 beaconing" finding for any public destination with a high beacon
score, with no exception for these expected-periodic services. In a tool whose
whole pitch is signal-over-noise triage, flooding responders with CRITICAL
false positives on ordinary NTP/DNS traffic causes alert fatigue.

Fix: exclude the benign-periodic well-known services (DNS/mDNS/NTP) from
beaconing C2 classification. Genuine C2 over DNS is still caught by the
entropy-based DNS-exfil detector; real beaconing channels (443, arbitrary high
ports, …) are unaffected.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from marlinspike.engine import Conversation, RiskSurface


def _conv(port, transport="udp"):
    c = Conversation(
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",           # public
        src_mac="aa:bb:cc:00:00:01",
        dst_mac="aa:bb:cc:00:00:02",
        first_seen="",
        last_seen="",
        protocol=transport,
        port=port,
        packet_count=120,
        bytes_total=9600,
    )
    c.beacon_score = 0.9   # strongly periodic
    c.beacon_interval = 64.0
    c.beacon_jitter = 0.03
    return c


def _beacon_indicators(conv):
    rs = RiskSurface(topology={"nodes": [], "edges": []}, conversations=[conv])
    return [i for i in rs._check_c2_indicators() if i["type"] == "C2_BEACONING"]


def test_ntp_to_public_not_flagged_as_beaconing():
    assert _beacon_indicators(_conv(123)) == [], "benign NTP polling flagged as C2 beaconing"


def test_dns_to_public_not_flagged_as_beaconing():
    assert _beacon_indicators(_conv(53)) == [], "benign DNS traffic flagged as C2 beaconing"


def test_real_c2_beaconing_still_detected():
    """Guardrail: the fix must not suppress genuine beaconing on non-benign ports."""
    inds = _beacon_indicators(_conv(4444, transport="tcp"))
    assert inds, "real C2 beaconing on a high port should still be flagged"
    assert inds[0]["severity"] == "CRITICAL"


def test_https_beaconing_still_detected():
    """443 is the #1 real C2 channel — must NOT be treated as benign-periodic."""
    inds = _beacon_indicators(_conv(443, transport="tcp"))
    assert inds, "beaconing to a public host on 443 should still be flagged"
