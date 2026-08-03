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
