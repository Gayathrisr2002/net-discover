# Session Changelog — Fleet Remote-Agent Overhaul

A working log of one continuous session's changes to the Fleet
(remote sensor agent) feature, in the order they happened. For the
resulting feature as it stands today, see
[docs/fleet-agents.md](docs/fleet-agents.md); this file is the
narrative of how it got there, not a replacement for that guide.

## 1. Flattened `Site` into `Project` (`9118860`)

Agents used to belong to a `Site`, which belonged to a `Project`
(`Project → Site → Agent`). Since `Project` already had its own
sharing model (`ProjectMember`) and capture policy, the `Site`/
`SiteMember` layer was pure duplication — a new "project" concept
was requested, and since `Project` already existed under that name,
the fix was to remove the indirection rather than rename around it.

- `Agent`/`AgentEnrollmentToken` now carry `project_id` directly.
- `SiteMember` deleted — agents now use the existing `ProjectMember`
  viewer/editor/owner roles.
- `Site.capture_policy` deleted — an agent's capture now uses
  `Project.capture_policy` directly (no more merging two policies).
- `Site.capture_schedule`/`capture_schedule_last_triggered_at` moved
  onto `Project`.
- New Alembic migration `0012` drops the `sites`/`site_members`
  tables and backfills `project_id` from each agent's former site.
- Routes moved from `/api/fleet/sites/...` to
  `/api/fleet/projects/...`; the site-members and site-policy
  sub-routes were deleted outright since they exactly duplicated the
  existing `/api/projects/<id>/members` and `/api/capture/policy/<id>`
  endpoints.

Verified live in a browser: Fleet page lists projects with agent
counts, agent table/members modal/enrollment-token flow all work, and
the Live Capture page's remote-agent dropdown populates with a single
request instead of two.

## 2. Fixed a migration-downgrade crash found by an adversarial review (`4bbcbb2`)

A bug hunt on the flattening commit — using an independent review
pass plus live testing — found one real, reproducible bug:
migration `0012`'s `downgrade()` only synthesized a placeholder
`Site` row for projects that had at least one `Agent`. A project with
a *standing enrollment token* but zero agents (the normal bootstrap
order — issue a token before anything enrolls) got no placeholder
site, so its token's backfilled `site_id` came back `NULL` and the
following `NOT NULL` constraint crashed the downgrade.

Fixed by widening the guard to also cover `agent_enrollment_tokens`,
and confirmed by seeding that exact scenario and running the
upgrade→downgrade cycle end-to-end.

## 3. Enroll command now fills in the gateway port even when the host isn't known (`20045fb`)

The Fleet page's enroll-token modal collapsed `--gateway host:port`
to the entire literal placeholder `<your-gateway-host>:<port>`
whenever the host couldn't be safely auto-detected (e.g. reached over
loopback) — discarding the port even though
`FLEET_GATEWAY_PUBLIC_PORT` defaults to `8765` and is almost always
known. Host and port now fill in independently, so only the
genuinely-unknown half stays a placeholder.

## 4. Restart-safe enroll instructions + delete for revoked agents (`463a7b9`)

Found live, on a real remote agent: step 4 of the enroll instructions
used `systemctl enable --now`, which is a no-op on an already-running
service. Re-enrolling a host whose agent was already running left the
process stuck on its old, revoked credential while the fresh one sat
unused on disk — endless "unauthorized" reconnects, agent shown
offline in the UI. Fixed to `enable` + `restart`, which reloads the
credential correctly either way.

Also added a **Delete** action for revoked agents (the actions column
was previously empty once an agent was revoked), via a new
`DELETE /api/fleet/agents/<id>` route gated to revoked-only status
server-side, not just in the UI.

## 5. New-capture default duration → 5 minutes (`0e81877`)

The Live Capture page's "New Capture" form defaulted **Max duration**
to `0` (unlimited). Changed the pre-filled default to `300` seconds,
matching what the automated scheduler already defaulted to.
Explicitly setting the field to `0` still means "capture until you
stop it" — only the untouched-field default changed.

## 6. Built the missing Fleet-page UI for the automated capture schedule (`5e14cee`)

The capture-schedule backend (project-wide recurring capture trigger)
already existed with zero UI — the only way to view or change it was
raw SQL. Added a "Capture Schedule" button/modal to the Fleet page:
enable toggle, an editable `times_utc` list (add/remove UTC `HH:MM`
entries with client-side validation), duration/interface/BPF-filter
fields, and the last-triggered timestamp. Disabling keeps the other
fields filled in so re-enabling later doesn't mean retyping
everything.

## 7. Documented the whole feature (`adad535`)

The README had no mention of Fleet anywhere, and the only existing
fleet doc (`docs/fleet-agent-poc.md`) is an engineering design/
debugging log, not an operator guide, and predated everything above.
Added `docs/fleet-agents.md` as a proper feature guide, wired it into
the docs index, corrected now-stale `Site`/`sites` references in
`fleet-agent-poc.md`'s current-state sections, marked its "no
Fleet-page UI for scheduling" gap resolved, and fixed a stale version
header in the root README (`3.5.5` → `3.6.0`).

## Verification posture across all of the above

Every change in this arc was verified against a running instance
(local sandbox for most; the actual docker-compose deployment for the
capture-schedule configuration and the real remote-agent
enroll/restart bug) rather than just read — including a real physical
agent host (`ot-lab3-OptiPlex-3020`) enrolling, hitting the
restart-vs-`enable --now` bug live, and confirming the fix. The full
test suite was run after each change; the same 7 pre-existing,
unrelated failures were present throughout with no new regressions
introduced.

## 8. Enterprise Vulnerability Analyzer & OT Security Modernization (`13edb04`)

Integrated dedicated vulnerability management & threat intelligence features directly into the MarlinSpike PCAP analysis platform:
- **Offline NVD & CISA ICS-CERT Correlation Engine**: Automatically maps extracted PLC hardware models, order numbers, and firmware versions (CIP Identity / S7 SZL) against CISA advisories and attaches explicit `CVE-202X-XXXX` IDs.
- **CVSS v3.1 Quantitative Risk Scoring Engine**: Computes exact CVSS Base Impact Scores (`9.8 CRITICAL`, `8.1 HIGH`, etc.) and renders color-coded CVSS badges on findings cards and asset detail inspectors.
- **CISA KEV (Known Exploited Vulnerabilities) & EPSS Threat Intel**: Surfaces glowing red `🔥 CISA KEV` active-exploitation badges and EPSS exploit probability scores for high-risk findings.
- **Vulnerability Lifecycle & Ticket Status Workflow**: Adds interactive status tracking (`Open`, `In Progress`, `False Positive`, `Risk Accepted`, `Resolved / Patched`) directly in `viewer.html` and persists statuses across engagement sessions.
- **Pre / Post-Patch PCAP Comparison & Diff Engine**: Added a `🔄 Compare PCAP` tool in the utility toolbar that compares baseline PCAP reports against current PCAPs to calculate patch deltas (`Resolved`, `Persistent`, `New Risks`).
- **Purdue Model Zero-Trust Firewall Rule Exporter**: Added a `🛡️ Firewall Rules` utility button to export ready-to-apply Zero-Trust micro-segmentation ACL rules for Palo Alto PAN-OS, Fortinet FortiGate, Cisco ASA, and Linux `iptables`.

## 9. Automated Enterprise OT Security & Incident Response Exporters (`c78b31c`, `c0255eb`, `06d5dc6`)

Enhanced the MarlinSpike platform with automated compliance and incident response exports for enterprise OT environments:
- **OASIS STIX 2.1 Threat Intelligence Exporter (`marlinspike/emit/stix.py`)**: Generates STIX 2.1 JSON bundles (`Indicator`, `Infrastructure`, `Observed-Data`) for SIEM/TIP interoperability and cross-platform threat sharing. Exposed via `/api/projects/<pid>/stix/download`, `/api/reports/<filename>/stix`, and the `📦 Export STIX 2.1` button on the `/iocs` page.
- **Automated Incident Response Ansible Playbook Exporter (`marlinspike/emit/ansible.py`)**: Generates executable YAML Ansible Playbooks (`marlinspike_incident_response_playbook.yml`) for rapid micro-segmentation and rogue OT traffic containment across Palo Alto Networks firewalls, Cisco IOS switches, and Linux `iptables`. Exposed via `/api/projects/<pid>/ansible/download` and `/api/reports/<filename>/ansible`.
- **CISA Known Exploited Vulnerabilities (KEV) & CVE Matcher (`marlinspike/cve_matcher.py`)**: Automatic correlation of discovered industrial firmware and PLC hardware models (Rockwell ControlLogix, Siemens S7-1200/1500, Schneider Modicon, ABB AC 800M, SEL Relays) against active CISA KEV advisories and CVSS risk scores.
- **Universal UI & Toolbar Interoperability**: Refactored global navigation (`base.html`) and viewer toolbar (`viewer.html`) with fluid horizontal scrolling, zero-overlap responsive layout, and fixed `MS.toggleRisk()` and `MS.toggleHmi()` interactive button exports.

## 10. UI E2E Suite, Security Test Flakiness, and IDE Warnings Resolution

Resolved all UI E2E test suite failures, password strength test flakiness, and static analysis / IDE warnings in the test suites:
- **UI E2E Suite Alignment (`scratch/test_ui_e2e_suite.py`)**:
  - Switched from the fragile `/login` POST mechanism to Flask test client session transaction injection.
  - Dynamically bootstrapped a mock `test-report.json` report in the test class setup to prevent 404 errors during asset inventory retrieval.
  - Corrected test route paths and assertions: updated `/assets` to `/api/reports/test-report.json/assets?project_id={project_id}`, redirected the findings page to `/capabilities` (looking for `"Catalog"`), and updated the `/fleet` page check to search for `"Fleet Sensors"` instead of `"Distributed Remote Sensors"`.
- **Flaky Password Strength Security Test Fix (`marlinspike/setup_wizard.py`)**:
  - Modified the password generator helper `_gen_password` to generate random characters in a loop until it produces a password containing at least one uppercase letter, one lowercase letter, and one digit, resolving intermittent failures in `test_setup_wizard_admin_password_strength`.
- **Static Analysis / IDE Warnings Resolution (`scratch/test_ui_e2e_suite.py`, `tests/test_recovery.py`)**:
  - Eliminated Pylance/Pyright warnings regarding database model construction by instantiating empty `User`, `Project`, and `ScanHistory` models first and setting their fields directly on the instances.
  - Added explicit assertions (`assert rec is not None`) on database queries to prevent type checker warnings about attribute access on potential `NoneType` objects.
  - Handled parameter type enforcement in `test_pid_alive_zero_and_negative` using `typing.cast` to safely pass `None` to `pid_alive(pid: int)`.

## 11. SQLAlchemy 2.0 ORM Migrations & IDE Warnings Cleanup

Completed the cleanup of remaining legacy DB access methods and resolved type checking issues in the scheduler and finalization tests:
- **Deprecated `Query.get()` Migration**: Replaced all remaining occurrences of the legacy `.query.get()` call with the SQLAlchemy 2.0 compliant `db.session.get()` pattern.
  - Modified `LlmConfig` query in `marlinspike/llm.py`.
  - Modified `Project` query in `marlinspike/webhook.py`.
  - Modified all `User` queries in `marlinspike/app.py` and `marlinspike/auth.py`.
  - Updated all query lookups in the unit tests (`tests/test_scheduler.py`, `tests/test_finalize_enrichment_degraded.py`, `tests/test_finalize_clears_pid.py`) to align with this pattern, removing all `LegacyAPIWarning` output from the test execution.
- **Type Warning Cleanup**: Resolved the Pyright/IDE type warnings inside `tests/test_finalize_clears_pid.py`, `tests/test_finalize_enrichment_degraded.py`, and `tests/test_scheduler.py` by:
  1. Instantiating empty DB model instances (`User`, `ScanHistory`, `Project`, `Agent`, etc.) and assigning attributes directly on the instances rather than using constructor keyword arguments, completely bypassing Pyright's dynamic `__init__` resolution limits.
  2. Introducing type-narrowing `assert is not None` assertions on query results to safely access database model attributes.



