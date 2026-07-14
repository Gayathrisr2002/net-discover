# MarlinSpike Bug-Fix Traceability Matrix

Tracks every finding from `MARLINSPIKE_BUG_REPORT.md` / `IMPACT_ANALYSIS.md` through to its
regression test and fix commit. Updated as each finding is worked, one at a time, TDD-first
(regression test written and confirmed RED against pre-fix code, then fix applied and confirmed
GREEN) going forward from Finding #3 onward.

Status values: `Fixed` (test + fix both in place, verified RED→GREEN) · `In Progress` ·
`Pending` (not yet started).

## CRITICAL + HIGH (fix-order scope)

| # | Finding | Severity | Status | Regression Test | Fix Location | Notes |
|---|---|---|---|---|---|---|
| 1 | Stored XSS in Users page → admin takeover | CRITICAL | Pending | — | `marlinspike/templates/users.html` | Edit attempted once, rejected/reverted; not yet reapplied |
| 2 | Path traversal in preset sanitizer | CRITICAL | Pending | — | `marlinspike/app.py` (`_safe_preset_name`) | |
| 3 | IDOR on `/api/runs/*` | CRITICAL | **Fixed** | `tests/test_run_ownership.py` (8 tests, RED confirmed pre-fix via `git stash`, GREEN confirmed post-fix) | `marlinspike/app.py` (`_run_owned_by_current_user` helper + 6 routes: list/status/output/stop/topology/live) | Full suite regression run still pending (last run attempt skipped) |
| 4 | `deliver_reset_token` missing function | HIGH | Pending | — | `marlinspike/auth.py` / `marlinspike/app.py` | |
| 5 | No rate limiting on expensive project endpoints | HIGH | Pending | — | `marlinspike/app.py` | |
| 6 | `/api/reports/<filename>*` wrong directory + no ownership check | HIGH | Pending | — | `marlinspike/app.py` (`user_reports_dir`/`user_uploads_dir`) | |
| 7 | `/api/scans/start` ignores shared-member role model | HIGH | Pending | — | `marlinspike/app.py` | |
| 8 | TOCTOU race on scan concurrency limits | HIGH | Pending | — | `marlinspike/app.py` | |
| 9 | Recovery path bypasses enrichment plugins | HIGH | Pending | — | `marlinspike/recovery.py` | |
| 10 | Plugin failures swallowed, run still "completed" | HIGH | Pending | — | `marlinspike/app.py` (`_finalize_run`) | |
| 11 | No `MAX_CONTENT_LENGTH`; size check after full body spooled | HIGH | Pending | — | `marlinspike/app.py` | |
| 12 | Benign NTP/DNS traffic flagged as C2 beaconing | HIGH | Pending | — | `marlinspike/engine.py` (`_check_c2_indicators`) | |
| 13 | DNS entropy thresholds unreachable for short labels | HIGH | Pending | — | `marlinspike/engine.py` | |
| 14 | `_ip_in_subnet` naive string-prefix match | HIGH | Pending | — | `marlinspike/engine.py` | |
| 15 | VMware OUI `00:50:56` mislabeled as Rockwell Automation | HIGH | Pending | — | `marlinspike/engine.py` (`ICS_OUI_DB`) | |
| 16 | Malware IOC stage never runs on chunked pipeline | HIGH | Pending | — | `marlinspike/engine.py` (`run_chain_from_conversations`) | |
| 17 | `--chunk-size` ignored when Rust DPI engine selected | HIGH | Pending | — | `marlinspike/engine.py` (`_dissect_with_selected_engine`) | |
| 18 | Wildcard domain IOCs never match anything | HIGH | Pending | — | `marlinspike/iocs.py` | |
| 19 | Audit log write failures silently swallowed | HIGH | Pending | — | `marlinspike/audit.py` | |
| 20 | MITRE plugin missing `severity` rule filter | HIGH | Pending | — | `plugins/marlinspike_mitre/plugin.py` | |
| 21 | capd has no interface-level session lock | HIGH | Pending | — | `marlinspike-capd/capd/server.py` | |
| 22 | Reaper timeout check bypasses PID-liveness check | HIGH | Pending | — | `marlinspike/recovery.py` | |
| 23 | PID-reuse defense uses substring match not token match | HIGH | Pending | — | `marlinspike/recovery.py` (`_live_argv_matches`) | |
| 24 | `reap_orphan_runs` ignores RUN_STORE mode, multi-worker race | HIGH | Pending | — | `marlinspike/app.py` / `marlinspike/recovery.py` | |
| 25 | Reaper races app finalize pipeline, drops enrichment silently | HIGH | Pending | — | `marlinspike/recovery.py` / `marlinspike/app.py` | |

## MEDIUM + LOW (#26–70)

Not yet scheduled — tracked in `MARLINSPIKE_BUG_REPORT.md` only until the CRITICAL/HIGH set is
worked through. Will be added to this matrix with the same columns once picked up.

## Process notes

- Each row moves `Pending → In Progress → Fixed` one at a time — no batching.
- "Fixed" requires: a regression test that reproduces the bug, confirmed to fail against pre-fix
  code (RED), the minimal fix applied, and the same test confirmed passing (GREEN).
- A full existing-suite regression run (`pytest tests/ -q`) is recorded per finding once
  performed; until then, treat "Fixed" as verified only for that finding's own new test(s), not
  yet cleared of side effects on the rest of the suite.
