"""Regression tests for Finding #13 (DNS-exfil entropy thresholds unreachable
for short labels).

DNS-exfil detection compares the *absolute* average Shannon entropy of subdomain
labels against fixed thresholds (``> 4.0`` critical, ``> 3.5`` high). But the
maximum achievable Shannon entropy of a string of length L is ``log2(L)``, so a
label must be longer than 16 chars to reach 4.0 and ≥12 to reach 3.5 — no matter
how random it is. A realistic tunnel/DGA label (an 8-char base32 chunk, max
entropy log2(8)=3.0) can therefore NEVER trip the detector, even at massive
fanout. For an OT threat-hunting tool, that is a silent false negative on the
exact technique it advertises.

The fix adds a length-normalized entropy ratio (H / log2(L), independent of
label length) and lets the strong existing gates (>50 unique subdomains, or high
volume) fire on a high ratio too — so short high-entropy exfil is caught while
the fanout/volume gates keep benign traffic from false-positiving.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from marlinspike import engine
from marlinspike.engine import Conversation, RiskSurface


# 60 unique 8-char high-per-length-entropy labels under one base domain.
_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"  # base32


def _short_random_labels(n):
    # n unique short subdomain labels. The label content only affects the unique
    # fanout count here — the per-length entropy is set explicitly on the
    # conversation below to model an all-distinct (max-ratio) short label.
    return [f"lbl{i:05d}.tunnel.evil.com" for i in range(n)]


def _exfil_conversation(labels, entropy_ratio):
    conv = Conversation(
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",
        src_mac="aa:bb:cc:00:00:01",
        dst_mac="aa:bb:cc:00:00:02",
        first_seen="",
        last_seen="",
        protocol="dns",
        port=53,
        packet_count=len(labels),
        bytes_total=len(labels) * 80,
        dns_queries=labels,
    )
    # Simulate what dissection computes: the absolute average entropy of an
    # all-distinct 8-char label is log2(8)=3.0 — below both 4.0 and 3.5 gates.
    conv.dns_entropy = 3.0
    conv.dns_entropy_ratio = entropy_ratio
    return conv


def _detect(conv):
    rs = RiskSurface(topology={"nodes": [], "edges": []}, conversations=[conv])
    return rs._check_c2_indicators()


def test_short_high_entropy_high_fanout_is_detected():
    labels = _short_random_labels(60)
    conv = _exfil_conversation(labels, entropy_ratio=1.0)
    indicators = _detect(conv)
    dns = [i for i in indicators if i["type"].startswith("C2_DNS")]
    assert dns, (
        "short-label DNS exfil at high fanout was not detected — absolute-entropy "
        "thresholds are unreachable for <16-char labels"
    )


def test_benign_low_ratio_high_fanout_not_flagged():
    """Many subdomains but low per-length entropy (repetitive/benign) → no exfil."""
    labels = [f"aaaaaaaa{i}.cdn.example.com" for i in range(60)]
    conv = _exfil_conversation(labels, entropy_ratio=0.4)
    conv.dns_entropy = 1.5
    indicators = _detect(conv)
    dns = [i for i in indicators if i["type"].startswith("C2_DNS")]
    assert not dns, "benign low-entropy subdomains were wrongly flagged as exfil"


def test_normalized_entropy_ratio_is_length_independent():
    """A random short label and a random long label both approach ratio 1.0."""
    short = engine._compute_dns_entropy_ratio_from_queries(["abcdefgh.evil.com"])   # 8 distinct
    long = engine._compute_dns_entropy_ratio_from_queries(["abcdefghijklmnop.evil.com"])  # 16 distinct
    assert short > 0.95 and long > 0.95, (short, long)
