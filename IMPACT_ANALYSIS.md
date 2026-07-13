# MarlinSpike — Impact Analysis

Companion document to the bug-hunt findings (70 total, from a 14-way parallel code review).
This document scores each finding by **real-world consequence**, not just technical severity —
the two don't always match. A bug that's technically "just a logic error" can matter more than a
memory-safety bug if it silently corrupts the threat findings an OT security team hands a client.

## How impact is scored

For each finding:

- **Trigger** — what access level / conditions are needed to hit it (unauthenticated,
  any authenticated user, project member, admin, specific config, or just "normal operation").
- **CIA impact** — Confidentiality / Integrity / Availability, and which one(s) actually apply.
- **Blast radius** — one user, one project, one tenant/instance, or cross-tenant.
- **Domain consequence** — MarlinSpike is a passive OT/ICS analysis tool used *during live security
  engagements*. Two consequences are specific to that context and are called out explicitly where
  they apply:
  - **Engagement-integrity risk**: a bug that silently produces wrong findings (false negative on
    a real C2/exfil technique, or a false positive that wastes responder time) directly undermines
    the product's core value proposition — worse than an equivalent bug in a typical CRUD app,
    because the "user" of the output is often a responder making real triage decisions during an
    incident, or a consultant handing a report to a client as the record of what was found.
  - **Engagement-confidentiality risk**: reports contain live client network topology, asset
    inventories, and findings from a real target environment. A cross-tenant/cross-user leak here
    isn't "a user sees another user's to-do list" — it's one client's OT network map and security
    findings leaking to another user of a shared instance.
- **Priority** — my recommended fix-order priority, which may differ from the original
  CRITICAL/HIGH/MEDIUM/LOW technical severity label when trigger complexity or blast radius
  changes the real-world picture.

---

## Risk register — CRITICAL + HIGH (25 findings)

| # | Finding | Trigger | CIA | Blast radius | Domain consequence | Priority |
|---|---|---|---|---|---|---|
| 1 | Stored XSS in Users page → admin takeover | Any account that can create a user (or CSRF) | C+I (full) | Every admin on the instance | Attacker who plants this can pivot to reading/exporting **every client's** report data | **P0** |
| 2 | Path traversal in preset sanitizer → wipe/overwrite data dir | Admin session | I+A (catastrophic) | Whole instance | Every project, every engagement's data, gone in one request | **P0** |
| 3 | IDOR on `/api/runs/*` | Any authenticated user | C (read) + A (kill) | Cross-user, single instance | One tenant reads/kills another's in-progress scan — leaks live topology/findings mid-engagement | **P0** |
| 6 | `/api/reports/*` wrong directory, no ownership check | Any authenticated user, any project | Availability only (breaks for legit shared users; verified not a cross-tenant leak because the per-uid path nesting happens to contain it) | Per-project | Sharing feature is non-functional, not a leak — still blocks real collaborative engagement workflows | P1 |
| 7 | `/api/scans/start` ignores shared-member role | Authenticated editor on a shared project | Availability (silent misrouting) | Per-user | Editor's scan silently lands in the wrong project — could confuse which engagement a result belongs to | P1 |
| 4 | `deliver_reset_token` missing entirely | Any user requesting password reset | Availability | Per-user | Self-service reset is 100% broken outside default delivery mode; ops burden, not data risk | P1 |
| 5 | No rate limit on aggregate/IOC-scan/export endpoints | Any project member (viewer+) | Availability (DoS) | Whole instance (shared worker pool) | One noisy low-priv user on one project can starve every other concurrent engagement | P1 |
| 8 | TOCTOU race on scan concurrency limits | Two near-simultaneous requests, same user or timed | Availability (resource exhaustion) | Whole instance | Breaks the tier/concurrency model the product's multi-tenant story depends on | P1 |
| 9 | Recovery path skips MITRE/ARP/APT/CISA enrichment | Flask restart during a scan (routine ops event) | **Integrity** — silent data loss | Per-scan, no visible signal | A report handed to a client is silently missing ATT&CK/IOC context and nothing says so — an engagement-integrity risk, not just a UX gap | **P0** (silent + undetectable) |
| 10 | Plugin failure swallowed, run still "completed" | Any plugin timeout/crash (network hiccup, subprocess issue) | **Integrity** — silent data loss | Per-scan | Same class as #9: the report looks green/complete but is missing enrichment data, with the only trace a buried stdout line | **P0** |
| 16 | Malware stage never runs on chunked pipeline | Any large-PCAP scan (the docs' recommended default path) | **Integrity** — systematic, not occasional | Every large-PCAP scan on the instance | This isn't a rare edge case — it's the *default* behavior for the documented "huge PCAP" workflow. Every such report is missing IOC/malware findings by design-accident | **P0** |
| 12 | Benign NTP/DNS flagged as CRITICAL C2 | Normal network traffic containing NTP/public DNS | **Integrity** — false positive | Every report with such traffic (very common) | Alert fatigue in a tool whose entire pitch is signal-over-noise triage; responders start ignoring CRITICAL findings | P1 |
| 13 | DNS-exfil detection can't catch realistic short labels | Any DGA/tunnel exfil using <12-16 char labels | **Integrity** — false negative | Every report with this traffic pattern | The detector is blind to the technique it's specifically built to catch, in its most realistic form — a genuine finding for an OT/ICS security product to have wrong | **P0** (silent false negative on the core value prop) |
| 14 | `_ip_in_subnet` breaks `--subnet-map` | Any user supplying a subnet map override (a documented, expected workflow) | **Integrity** — silent misclassification | Every affected report | Purdue-level misclassification changes cross-zone-violation findings — a core OT-specific detection | P1 |
| 15 | VMware OUI mislabeled as Rockwell | Any capture containing a VMware-NIC'd VM (extremely common: HMI/EWS/historian VMs) | **Integrity** — false vendor/priority data | Every affected report | Inflates attack-priority score for something that isn't OT hardware at all — misdirects responder attention during triage | P1 |
| 17 | `--chunk-size` no-ops under default Rust DPI | Any large-PCAP scan on a host with `marlinspike-dpi` installed (the *recommended* default) | Availability (OOM risk, not data loss) | Large-PCAP scans specifically | Defeats the one feature that exists specifically so large engagement captures don't crash the box | P1 |
| 18 | Wildcard domain IOCs never match | Any analyst adding a `*.domain` IOC (a documented, expected IOC format) | **Integrity** — false negative, IOC-hunting silently broken | Per-IOC-list | An analyst adds a known-bad wildcard domain, gets 0 hits forever, and has no way to know the feature is broken vs. "genuinely no matches" | **P0** (silent, and the whole point of threat hunting is trusting a negative result) |
| 19 | Audit log write failures swallowed | Any transient DB hiccup during login/reset/password-change | **Integrity** of the audit trail | Per-event | For a tool with a dedicated `/audit` compliance feature, a silently-missing security event undermines the one thing that page exists to guarantee | P1 |
| 20 | MITRE plugin `severity` filter unimplemented | Any rule author following the documented example verbatim | **Integrity** — silent over-matching | Per-rule-pack | A rule meant to gate on HIGH/CRITICAL fires on everything — inflates ATT&CK coverage numbers a client might rely on | P2 |
| 21 | capd no interface-level lock | Multi-worker deployment + two near-simultaneous live-capture starts on one NIC | Availability (double capture load) + documentation is factually false | Live-capture deployments only (opt-in, Linux-only) | Smaller blast radius since live capture is off by default | P2 |
| 22 | Reaper bypasses PID-liveness before marking abandoned | Flask restart during a slow-but-healthy scan | **Integrity** — a good report is discarded/hidden, and the user is shown a false failure | Per-scan | Erodes trust in the tool ("it said this failed but the data was fine") | P1 |
| 23 | PID-reuse defense is substring match | PID reuse + any coincidentally-matching process string (plausible on a busy host over time) | Integrity of the recovery mechanism itself | Per-restart-cycle | Could cause the reaper to treat an unrelated process as "the scan," with unpredictable downstream effects | P2 |
| 24 | `reap_orphan_runs` ignores RUN_STORE mode | Any multi-worker deployment + any worker restart (routine ops: rolling deploy, `--max-requests` recycling) | **Integrity** — duplicate finalization, double-run enrichment plugins | Per-restart, any multi-worker (cloud/production) deployment | This hits *every* production-recommended (`gunicorn -w N`) deployment on *every* routine restart — not a rare edge case | **P0** |
| 25 | Reaper races finalize pipeline mid-enrichment | Flask crash during the ~seconds-to-tens-of-seconds MITRE/ARP/APT window | **Integrity** — silent enrichment loss | Per-crash-during-that-window | Same failure mode as #9/#10/#16 (silent missing enrichment), one more independent path to the same user-facing symptom | P1 |
| 11 | No `MAX_CONTENT_LENGTH` | Any authenticated user, any upload | Availability (disk/memory exhaustion) | Whole instance | Real but requires sustained abuse; lower urgency than the P0s | P2 |

Findings #4, #5, #7 in the original numbering that don't have dedicated rows above (kept same
numbering as the bug report) are folded into the table where relevant.

---

## Why the priority column reorders some things

The original bug report ranked by **technical severity** (how bad is it if triggered, in
isolation). This analysis reorders around a different question: **how likely is a real user to
hit this, and would they ever know it happened?**

Six findings get bumped to **P0** even though only three were originally labeled CRITICAL, because
they share a specific, dangerous shape: **they corrupt engagement data silently, under normal
operating conditions, with no error surfaced anywhere** —

- #9 (recovery skips enrichment), #10 (plugin failure swallowed), #16 (malware stage skipped on
  chunked pipeline), #24 (reaper ignores RUN_STORE mode) — all four are variations of the same
  underlying problem: **the run-completion/enrichment pipeline has no "degraded" state.** A report
  is either fully enriched or it silently isn't, and the UI can't tell the difference. This is
  arguably the single most consequential architectural gap in the codebase, because it directly
  undermines trust in every report the tool produces.
- #13 (DNS-exfil can't catch short labels) and #18 (wildcard IOCs never match) are both "detector
  claims to work, silently doesn't, for the realistic/common case" — for a threat-hunting/OT
  security tool, a confidently-wrong negative is worse than a crash, because nobody double-checks
  a clean result.

Conversely, a few originally-HIGH findings are pushed down to **P2** where the blast radius is
narrow (opt-in/off-by-default feature like live capture, #21) or the trigger requires sustained
deliberate abuse rather than normal use (#11, #20).

---

## Recommended fix order (P0 first)

1. **#3 — IDOR on `/api/runs/*`** (CRITICAL, cross-tenant read + kill, trivial to trigger, no
   special config needed)
2. **#2 — Path traversal in preset sanitizer** (CRITICAL, but admin-only trigger narrows exposure
   somewhat vs. #3)
3. **#1 — Stored XSS → admin takeover** (CRITICAL, requires an attacker to already hold *some*
   account, or a CSRF setup — one step further removed than #3)
4. **#24 — `reap_orphan_runs` ignores RUN_STORE mode** (hits every production multi-worker
   deployment on every routine restart)
5. **#9 / #10 / #16 / #25 — the four enrichment-silently-skipped variants** (fix together — they
   share root cause: no "degraded" status concept)
6. **#13 / #18 — the two silently-broken detectors** (DNS-exfil thresholds, wildcard IOCs)
7. Remaining P1s, then P2s, in the order listed in the table.

---

## Findings #26–70 (MEDIUM/LOW) — impact notes, grouped by theme

Full technical detail for these is in `MARLINSPIKE_BUG_REPORT.md`. Grouped impact summary:

- **Project-sharing correctness (#29, #32, #34, #35)** — orphaned files on disk, uploads landing
  in the wrong directory, dedup splitting one asset into two. All integrity/UX issues within a
  single project; no cross-tenant exposure. Worth fixing before shipping a "sharing" feature as
  production-ready, but not urgent from a security standpoint.
- **Emit-format correctness (#43–46)** — OCSF/Sigma/STIX output can be malformed or silently
  wrong (missing `time`, invalid empty selectors, wrong tag format, IPv6-as-MAC). Impact is
  entirely on **downstream consumers** (a SIEM, a Sigma engine, a STIX platform) — if nobody
  currently consumes these exports operationally, impact is latent; if someone does, findings
  silently fail to load/match there.
- **Recovery/concurrency plumbing (#54–56, #68)** — latent landmines (stale `engine_pid`, silent
  in-memory-DB fallback, missing index) that don't cause visible harm today but will surface
  confusingly later (a future "kill stuck scan by PID" admin tool, a slow concurrency check at
  scale, a forgotten `.env` var in a fresh shell).
- **Extension-contract gaps (#47–49)** — the documented plugin/rule-pack contracts (by-ID
  override, envelope fields, schema validation) aren't implemented. No current user-facing impact
  since nothing exercises these paths yet, but it means the extensibility story in the docs is
  aspirational, not real, for a third party writing a plugin today.
- **Capture-sidecar races (#50–53)** — all confined to the live-capture feature, which is
  off-by-default and Linux-only. Real but low blast radius until that feature sees more use.
- **Everything in LOW (#57–70)** — genuinely minor: off-by-ones, missing subprocess error
  handling on rare toolchain-missing cases, temp-file hygiene, cosmetic logging.
