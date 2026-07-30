# Remote Fleet Agent + Live Capture — Proof of Concept

**Status:** validated end-to-end on real hardware, then re-architected (§6)
so the agent forwards raw traffic instead of analyzing it locally, plus
automated capture scheduling. §1-2 below describe the original design
(now superseded by §6 but kept for context — the bug history there is
real and the underlying capture-control/enrollment plumbing is unchanged).
§3-5 (the original design's verification/gaps/regression sections) are
superseded by §7-9 and not reproduced. See the code itself
(`marlinspike/fleet/`, `marlinspike-agent/`, `marlinspike-capd/`) and each
package's own README for anything not covered here.

**Purpose of this document:** record what was concretely proven to work
(with real commands and real numbers, not just code review), what bugs
were found and fixed to get there, and — most importantly — what is still
genuinely missing before this is a production-ready capability rather
than a validated proof of concept. Treat §8 ("Known gaps") as the punch
list for whoever picks this up next.

## 1. What the original design proved (superseded by §6 — kept for context)

A remote sensor host, with `marlinspike-agent` and `marlinspike-capd`
installed via `apt install ./*.deb` (either order) and nothing else, could:

1. Enroll itself against a central MarlinSpike server over mTLS, using a
   one-time site enrollment token.
2. Maintain an authenticated heartbeat connection, surfaced as
   online/offline status on the Fleet page.
3. Have a live packet capture started and stopped on it *from the central
   console* — the operator never touches the remote host directly.
4. Run the full analysis engine **locally** on each rotated capture — the
   engine, its plugins, rule packs, and `tshark` were all either bundled
   into the agent's own `.deb` or pulled in automatically as an apt
   dependency — and ship only the resulting JSON report back to the
   server, never the raw PCAP.
5. Have that report land in the server's normal Reports page, in the right
   project, indistinguishable from a locally-uploaded-and-scanned capture.

§6 reverses point 4 and 5: the agent no longer analyzes anything locally;
it forwards raw pcap bytes and the server analyzes them. Points 1-3 are
unchanged by that pivot.

## 2. Bugs found and fixed getting the original design working

These surfaced in order, each only becoming visible once the previous one
was fixed — a real "peel the onion" deployment debugging arc, not a
designed test plan. Kept here as historical context; none of this
plumbing changed in §6's pivot.

| # | Symptom | Root cause | Fix |
|---|---|---|---|
| 1 | `--gateway http://host:port` silently connected to the wrong host | naive `rpartition(":")` parsed the whole `http://host` as the hostname | strip a `scheme://` prefix before splitting (`f2fcf90`) |
| 2 | App unreachable via LAN IP | port mapping hardcoded to `127.0.0.1` | `APP_BIND_HOST`, now defaults to `0.0.0.0` (`18f8cea`, `fee8d3f`) |
| 3 | Login silently failed after LAN exposure | browsers refuse a `Secure`-flagged cookie over plain HTTP to a non-localhost host | `SESSION_COOKIE_SECURE=false` shipped paired with the LAN default |
| 4 | `fleet-gateway` never started | required a separate `--profile fleet` flag | starts automatically now (`555208f`) |
| 5 | `fleet-gateway` crash-looped | no TLS certs, no automated generation | `certs-init` one-shot service auto-generates them (`e5715d3`) — deliberately *not* a baked-in default cert, since that would mean every deployment shares one private key |
| 6 | Real cert verification (not `--insecure-skip-verify`) failed: *"CA cert does not include key usage extension"* | `openssl req -x509`'s implicit defaults for `keyUsage`/`basicConstraints` aren't reliable across OpenSSL versions | explicit `-addext` flags on both CA and leaf cert (`4965921`) |
| 7 | *"IP address mismatch"* enrolling against the server's real LAN IP | generated cert's SAN only ever covered `localhost`/`127.0.0.1`/`marlinspike-fleet-gateway` | `FLEET_GATEWAY_PUBLIC_HOST` now baked into the cert's SAN at generation time (`821767f`) — **note**: only takes effect on first generation (the step is idempotent); setting this env var after `./certs` already exists needs `./certs/gateway.crt`/`gateway.key` deleted and `certs-init` re-run to actually pick it up, which bit us again live during this pass (see §7) |
| 8 | `marlinspike-agent.service` failed with `226/NAMESPACE` | `ReadWritePaths=/var/run/marlinspike-capd` required that path to exist, but `marlinspike-capd` isn't installed on every agent host | made the path tolerant of being absent with systemd's `-` prefix (`87cc73b`) |
| 9 | `credential.json`'s `ca_cert` path broke under the sandboxed unit | a relative `--ca-cert ./fleet-ca.crt` resolves against the wrong directory once systemd's `ProtectHome=true` hides `/home` entirely | embed the CA cert's **PEM content** directly in `credential.json` instead of a path reference (`85d451a`) |
| 10 | `marlinspike-capd` failed every capture: `dumpcap not found on PATH` | Debian/Ubuntu restrict `dumpcap` execution to `root`/`wireshark` group | `systemd/install.sh` now auto-adds the `wireshark` group if present (`a45c943`) |
| 11 | An allow-listed uid still couldn't reach capd's socket at all | `RuntimeDirectoryMode=0750` blocked traversal before SO_PEERCRED ever ran | loosened to `0755` — the socket file itself is already `0666` (`a45c943`) |
| 12 | Live capture "disabled" on the server itself | the `capd` sidecar was opt-in, separate from `LIVE_CAPTURE_ENABLED` | `capd` now starts with the rest of the stack by default (`0600786`) |
| 13 | No easy way to get `marlinspike-capd` onto a remote sensor host | only a manual `pip install` path existed | added a downloadable, pre-built `.deb` (`0600786`) |
| 14 | A stopped-then-restarted agent kept getting `unauthorized` after re-enrolling | the running process held the *old* credential in memory | not a bug — `systemctl restart marlinspike-agent` after any re-enrollment picks up the current file |
| 15 | Agent-side scan failed: `No module named marlinspike` | the agent needed the full engine package + `tshark` installed locally | (then-)fixed by bundling the engine into the agent `.deb`; **fully removed in §6** instead, since the agent no longer analyzes anything |
| 16 | Even after bundling the engine, scans failed reading the rotated PCAP | `capd`'s `StateDirectoryMode=0750` blocked the agent user's group membership | both `.deb`s' `postinst` wire group membership automatically |
| 17 | Docker image build failed: `cp: cannot stat '/app/data/oui.json'` | Dockerfile copied `oui.json`/MITRE data *after* the step that bundled them into the agent `.deb` | reordered the `COPY` steps; **reverted again in §6** since nothing needs bundling into the agent anymore |
| 18 | `--allow-uid` required a manual `systemctl edit --full` every install | no automated way for either installer to know which uid needed access | `capd serve --allow-uid-file`, re-read on every connection with no restart needed; both `.deb`'s `postinst` write it automatically |

## 3-5. (original verification/gaps/regression sections — superseded)

See §7-9 for the current design's verification, known gaps, and
regression testing. The original §3's live commands, §4's punch list, and
§5's test counts described the local-analysis design that §6 replaces.

## 6. The pivot: raw pcap forwarding + server-side analysis + scheduling

Two things changed here, both explicit user requests:

1. **The agent stops analyzing anything locally.** It captures via capd
   and forwards each rotated pcap's raw bytes to `fleet-gateway`, which
   runs the actual analysis engine and produces the report. Before this,
   the agent bundled the whole engine (+ `tshark`) and shipped only a
   small JSON report — reversed because the operator wants the
   **traffic itself**, mirrored from a SPAN port, analyzable centrally
   rather than trusting each remote agent to run (and keep updated) its
   own copy of the analysis pipeline.
2. **Automated 2×/day capture scheduling**, triggered by the server, not
   an operator manually clicking start each time.

### Why reuse the existing connection instead of a new upload endpoint

The agent already holds a persistent mTLS+bearer-credential TLS
connection to the gateway (port 8765). The old `report_chunk`/
`report_complete` chunked-JSON-event mechanism became `pcap_chunk`/
`pcap_complete` — same idea, base64-encoded per chunk now (mandatory:
raw pcap bytes aren't valid UTF-8, unlike JSON report text). Rejected: a
new HTTP upload endpoint (a second open port/firewall rule at every
remote site, plus a whole new auth story for the agent to talk to Flask
directly) and true non-JSON binary framing (needs a protocol-level
frame-type tag, more risk than this pass needed).

### Positional writes, not in-memory reassembly

The gateway seeks each decoded chunk directly to
`chunk_index * _PCAP_CHUNK_RAW_BYTES` in an open file handle — correct
regardless of arrival order, no in-memory reordering buffer, and
per-connection memory cost is O(a few in-flight chunks) rather than
O(file size). `config.PCAP_MAX_SIZE` (5GB, already governing manual
uploads) is reused as the chunk-count ceiling for this path too.

### A gateway that can launch subprocesses

`fleet/gateway/scan.py` mirrors `app.py`'s manual-upload scan-launch
pattern (CLI arg building, `run_store.record_start`/`record_finish`
sequencing) but uses `asyncio.create_subprocess_exec` + `await
proc.wait()` instead of a blocking `Popen.wait()` — the gateway's own
asyncio loop can't afford to block for a scan's entire duration, since
that would freeze every other agent's connection too. `chain` already
runs enrichment (MITRE/ARP/APT/CISA) internally before it exits, so no
separate `enrich.run_all()` call is needed on this happy path (that stays
a `recovery.py`-reaper-only defensive step for a narrow crash window).

### Two separate PID namespaces, two separate reapers

`app` and `fleet-gateway` are separate Docker containers with no `pid:`
sharing directive — a PID the gateway records is meaningless to the main
app's own reaper. `run_store.get_active_for_recovery()` already excluded
`agent_id`-set rows (originally because no PID ever existed for those
rows under the old design); under the new design it's still correct to
exclude them, just for a different reason now (namespace mismatch, not
absence). A **second, separately-scoped reaper**
(`run_store.get_active_agent_scans_for_recovery`) runs at gateway startup
(`fleet/gateway/cli.py`), reusing `recovery.reap_orphan_runs`'s entire
multi-worker-claim/deadline/PID-reuse-defense logic via an injectable
`get_active` callable rather than duplicating ~130 lines of subtle logic.

### Spool-by-reference, not spool-by-copy

The old spool copied a small JSON report's text into a spool file when
the link dropped mid-send. A multi-GB pcap can't be copied that way
without doubling agent-local disk usage on every reconnect, so the agent
tracks a reference (original path + small JSON sidecar) instead. The
agent has only **read** access to capd's capture directories (confirmed:
parent dir `0750`, per-session subdir `0755`, both `capd:capd` —
group gets `r-x`, never `w`), so it can't rename the file out of the
ring-buffer's path to protect it from reclaim; `_flush_spool` detects a
since-reclaimed file (`os.path.isfile` check) and drops the stale
reference cleanly rather than erroring forever. Documented residual risk,
not a silent bug — size `ring_files` generously if long outages are a
real concern for a given deployment.

### Breaking wire-protocol change, handled gracefully

Once `report_chunk`/`report_complete` handlers were removed, an
old (pre-pivot) agent's reports would otherwise be silently dropped —
`_handle_event` has no `else` branch. Added a throttled (once per
connection, via `conn.warned_deprecated`, not once per event)
deprecation-warning stub instead of silence.

### The agent goes back to being lightweight

All engine-bundling work (`_BUNDLED_ENGINE_DIR`, `tshark` `Depends`,
`marlinspike`/`plugins`/`rules`/`presets`/`oui.json` baked into the
`.deb`) is removed — the agent is a small, dependency-light transport
tool again (32KB `.deb`, was 1.7MB with the engine bundled; zero
third-party Python dependencies).

### Automated scheduling reuses almost everything already built

`CaptureSession.max_duration_s` is already a real, tested, self-expiring
mechanism (`capture/api.py`'s `_make_session_finalizer`) — a capture
started with `max_duration_s=300` already auto-stops itself and
finalizes the DB row with zero new code. Combined with the pcap-forwarding
pivot above, the final rotation's ship→analyze→report flow already
happens automatically on session end — "automated N-minute scan" only
needed the **start** trigger automated.

`capture/api.py`'s `start_session` route had everything (policy gates,
session creation, client dispatch) inline. Extracted into
`_start_capture_session(*, user_id, project, agent, interface,
bpf_filter, ring_filesize_kb, ring_files, max_duration_s,
actor_username=None)` — a plain function with no Flask
`request`/`session` dependency — so the HTTP route and
`marlinspike/scheduler.py`'s automated trigger share the identical
policy-gated core logic (interface allowlist, duration cap,
retained-bytes cap all still apply to an automated trigger, not bypassed).

`marlinspike/scheduler.py` is a plain `threading.Thread` + 60s
sleep-loop, matching the existing `recovery.py`-watcher pattern — no new
dependency (no APScheduler/Celery in `requirements.txt`) is justified for
something this simple, and the deployment is a single process today
(`Dockerfile`'s `CMD` runs plain `app.run()`, not gunicorn). Started only
from `app.py`'s `if __name__ == "__main__":` block, never from
`create_app()` itself — every test calls `create_app()` directly, and a
persistent thread started there would leak across the whole suite.

`Site.capture_schedule` (JSON: `enabled`/`times_utc`/`duration_s`/
`interface`/`bpf_filter`) + `Site.capture_schedule_last_triggered_at`
(dedup guard against double-firing a slot, survives app restarts near a
scheduled time) are new nullable columns (migration `0011`). A future
multi-worker deployment would need an additional DB-level claim
(mirroring `run_store.claim_for_recovery`'s pattern) — out of scope while
the deployment model is single-process.

### Three real concurrency bugs found via live testing (not caught by unit tests)

`_handle_event` dispatches every incoming event as its own independent
asyncio task (`self._spawn`), not a sequential queue — a design already
in place before this pivot, but the old `report_chunk` reassembly (a
plain dict keyed by chunk index, tolerant of clobbering since a resend
was harmless) never exposed how dangerous that is for something that
opens a **file handle** on first sight of a new filename.

**Bug 1 — chunk-vs-chunk creation race.** The first live test after this
pivot shipped a real capture — 8 chunks — and the gateway only ever
recorded 3 of them: `pcap ... incomplete or invalid (got 3/8 chunks) —
dropping`. Several `pcap_chunk` events for a brand-new filename arriving
back-to-back each observed "no transfer yet" across the `await` on
`db.begin_pcap_upload`, and each independently opened its own file
handle — clobbering each other in `conn.pcap_transfers`. Fixed with a
per-connection `asyncio.Lock` (`pcap_create_lock`, double-checked:
re-verify `pcap_transfers.get(filename)` after acquiring the lock, since
another task may have finished creating it while this one waited)
guarding just the transfer-creation moment. Regression test
(`test_concurrent_chunk_events_for_new_file_dont_race`) fires all 8 chunk
events as real concurrent tasks (`asyncio.create_task` + `gather`) to
catch it — every other test in the file used sequential awaits and could
not have caught this.

**Bug 2 — chunk-vs-complete race.** Re-running live after bug 1's fix, the
scheduler's first automated (single-chunk) capture immediately hit a
second, deeper instance of the same class of race: the agent logged
`shipped pcap ... (1 chunks)`, the gateway logged `sent pcap_complete for
unknown transfer ... — dropping`. Bug 1's lock only serialized
*chunk-vs-chunk* creation; `pcap_complete`'s handler did a bare
`conn.pcap_transfers.pop(filename, None)` with **no lock at all**, so it
could run while the first (and only) chunk's task was still suspended on
its own `await db.begin_pcap_upload(...)`. `_reader_loop` only creates the
`pcap_complete` task *after* the chunk frame has been read off the wire
(TCP guarantees in-order bytes on one connection), but that only
guarantees *task creation* order, not *handler body execution* order —
asyncio interleaves freely at await points. Fixed by having
`pcap_complete` also acquire `conn.pcap_create_lock` before its `pop()`,
forcing it to wait behind any in-flight creation for that filename.
Regression test (`test_complete_racing_inflight_first_chunk_creation_waits`)
artificially widens `begin_pcap_upload`'s latency and fires both events as
concurrent tasks to reproduce this deterministically — re-running the
same scheduled single-chunk capture live afterward confirmed a clean
`launching scan ... -> scan completed ...` pair.

**Bug 3 — a stale gateway TLS cert misses a later `FLEET_GATEWAY_PUBLIC_HOST`.**
Not a code bug, an operational trap already implied by bug #7's own
"only takes effect on first generation" caveat (§2) — it bit us for real
during this pass anyway. A remote agent enrolling against the server's
real LAN IP got `ssl.SSLCertVerificationError: ... IP address mismatch,
certificate is not valid for '<ip>'` even though `.env`'s
`FLEET_GATEWAY_PUBLIC_HOST` was already correctly set to that IP —
because `./certs/gateway.crt` had been generated at some earlier point
before that env var existed, and `certs-init`'s idempotent skip-if-exists
check meant it was never regenerated since. Fixed operationally (not a
code change): delete `certs/gateway.crt`/`gateway.key` only (**not**
`fleet-ca.crt`/`.key` — keeps the same CA, so no already-enrolled agent's
client cert is invalidated), re-run `certs-init`, restart `fleet-gateway`.
Confirmed the regenerated cert's SAN then correctly included the LAN IP
and the same enroll command succeeded. Also worth knowing separately: an
already-enrolled agent's `credential.json` stores `gateway_host`/
`gateway_port` from `enroll` time and reads it back on every `run` start
(there's no `--gateway` flag on `run`) — if the gateway's IP ever changes
for real (not just a stale cert), every already-enrolled agent needs its
`credential.json` updated too, not just the server-side cert.

## 7. How the current design was verified (reproducible)

Same box, both packages reinstalled from freshly-built `.deb`s
(`0.4.0`/agent, unchanged capd), full stack rebuilt:

```bash
sudo apt install ./marlinspike-agent_0.4.0_all.deb   # 32KB, no tshark dep now
sudo marlinspike-agent enroll --gateway <server-ip>:8765 --token <token> \
    --ca-cert ./fleet-ca.crt --name my-agent \
    --credential-file /etc/marlinspike-agent/credential.json
sudo chown marlinspike-agent:marlinspike-agent /etc/marlinspike-agent/credential.json
sudo systemctl enable --now marlinspike-agent

curl -X POST http://<server>:5001/api/capture/sessions \
    -d '{"project_id":1,"agent_id":<id>,"interface":"enp2s0","duration_s":8}'
# ... wait, then stop it ...
sudo journalctl -u marlinspike-agent -f
# -> "shipped pcap cap_00001_....pcapng (3929468 bytes, 8 chunks)"
```

Gateway log, same run:

```
agent <uuid> authenticated from (...)
fleet.gateway.scan: session=<uuid> launching scan for /app/data/uploads/1/1/cap_....pcapng -> /app/data/reports/1/1/cap_...-marlinspike-<id>.json
fleet.gateway.scan: session=<uuid> scan completed for ... -> ...
```

Confirmed server-side: a `ScanHistory` row with `agent_id` set,
`status=completed`, `engine_pid` populated while running then cleared on
completion (`record_finish` already did this — same code path as a local
scan); the report fully enriched (MITRE/ARP/APT/CISA/OCSF/STIX sidecar
files all present, confirming `chain`'s internal enrichment ran with no
extra step needed) and visible via `/api/reports?project_id=1` exactly
like a manual upload.

**Scheduling**, verified separately: `PUT
/api/fleet/sites/1/capture-schedule` with a `times_utc` slot ~2 minutes in
the future, then confirmed (no manual action) `Site
.capture_schedule_last_triggered_at` became non-null and a
`CaptureSession` appeared for the online agent at that site once the
slot's grace window opened — driven entirely by `marlinspike/scheduler.py`'s
background thread, reusing the exact same `_start_capture_session` code
path (and every policy gate) as a manual click would. Re-run after bug 2's
fix (§6): the resulting single-chunk capture's full
ship→analyze→report pipeline completed cleanly with no dropped-transfer
warning.

**Gateway-startup reaper**, verified by seeding a synthetic orphaned row
directly in `scan_history` (`status=running`, `agent_id` set, a
definitely-dead `engine_pid`) and restarting the `fleet-gateway`
container: the new agent-scoped reaper (`recovery.reap_orphan_runs
(get_app(), get_active=run_store.get_active_agent_scans_for_recovery)`,
called from `fleet/gateway/cli.py` at startup) correctly reaped it
(`status=failed`, `recovery_state=reaped_failed`, logged `reaped failed
run ... (engine pid=None dead, no report)`) — and, seeded alongside it, a
plain local-scan orphan row (`agent_id IS NULL`) was left completely
untouched, confirming the two reapers stay correctly scoped to their own
rows.

**Old-agent deprecation path**: covered by
`test_deprecated_report_chunk_warns_once_per_connection`, which exercises
the exact code path the real wire protocol would hit; not separately
re-verified against a real pre-pivot agent binary this pass.

## 8. Known gaps — the actual punch list for future work

Ranked by how much they block real deployment, most important first.

### 8.1 TLS CA is dev-grade by design

`scripts/gen_dev_tls_cert.sh` says so directly in its own header comment:
"LOCAL/DEV TESTING ONLY." A real production rollout needs either a real
internal CA or a documented, supported process for bringing your own
certs — today there's no path other than hand-editing what `certs-init`
generates. Relatedly (§6, bug 3, §2 #7): a cert regeneration is required
any time `FLEET_GATEWAY_PUBLIC_HOST` changes or is set after the fact —
`certs-init` has no way to detect "this value changed" on its own.

### 8.2 No visibility into *why* an online agent's capture fails

If an agent is online but its local `capd` isn't reachable (not
installed, crashed, wrong `--allow-uid`), the only way to find out is to
SSH into the agent host and read its journal. Surfacing agent-side capd
reachability as a status badge next to the agent on the Fleet page would
close a real diagnostic gap.

### 8.3 Group-membership fixes need a service restart to take effect

The automatic `postinst` group wiring only helps a process that starts
*after* the group membership change — if `marlinspike-agent` was already
running when `marlinspike-capd` gets installed afterward, the
already-running agent process won't see its new group membership until
restarted. `capd`'s `postinst` prints a reminder when it detects this
case, but it's still a manual restart, not automatic.

### 8.4 Spool-by-reference can lose data to ring rotation on a sustained outage

If the link to the gateway is down long enough that capd's own ring
buffer (`ring_files`) wraps around and overwrites a not-yet-shipped
rotated pcap before a retry ever gets to it, that capture is gone —
`_flush_spool` detects this (`os.path.isfile` check) and drops the stale
reference cleanly rather than erroring forever, but the underlying data
loss isn't prevented, just handled gracefully. Documented tradeoff, not a
silent bug — the agent has no write access to capd's capture directories
to protect the file some other way (see §6). Size `ring_files` generously
if long outages are a real risk for a given deployment.

### 8.5 Automated scheduling is single-process-only

`marlinspike/scheduler.py`'s dedup guard
(`Site.capture_schedule_last_triggered_at`) prevents a slot from
double-firing across app restarts, but a true multi-worker deployment
(gunicorn with >1 worker) would need an additional DB-level claim
(mirroring `run_store.claim_for_recovery`'s pattern) to guarantee only one
worker actually fires a given slot. Out of scope while the deployment
model is a single process (`Dockerfile`'s `CMD`, plain `app.run()`).

### 8.6 No Fleet-page UI for capture scheduling

`PUT /api/fleet/sites/<id>/capture-schedule` is API-only — there's no form
on the Fleet page to configure it, matching (not regressing from) the
existing `capture_policy` feature, which is also API-only today with no
UI either.

### 8.7 Environment resets during this validation

Multiple times during this session, the Docker stack, the systemd units,
or the repo checkout itself were found reset/recreated with no action
taken by either the user or this assistant — on one occasion severely
enough to lose two full commits of this pivot's work from git history
entirely (never pushed, so unrecoverable via `git reflog`; the entire
implementation had to be reconstructed from the session's own record of
what was built and re-verified). Not a code bug — noted here only because
it makes "is this actually still working, and still committed" a
question worth re-asking rather than assuming, if you're picking this up
after any gap in time. **Push commits promptly once they're approved for
it** — an uncommitted or unpushed local commit is not a durable record.

## 9. Regression testing performed (current design)

- **Main app** (`tests/`): same pre-existing, order-dependent flaky set as
  every prior pass — `test_audit_failure_visibility.py`,
  `test_extract_timeline.py` (multiple), `test_inmemory_db_warning.py`,
  `test_reset_token_delivery.py`, and intermittently
  `test_security_v352.py`. A new caplog-based test
  (`test_fleet_gateway_pcap.py::test_deprecated_report_chunk_warns_once_per_connection`)
  joined this same order-dependent flaky class (passes standalone, same
  root cause as the others) — not a code bug, confirmed by isolated runs.
  Zero *new-kind* of failure introduced by this pass.
- New coverage added: `tests/test_fleet_gateway_pcap.py` (chunk
  reassembly — order, duplicate, oversized, invalid base64, the
  concurrent-creation race, the complete-vs-in-flight-creation race,
  deprecation throttling), `tests/test_fleet_gateway_db_pcap.py`
  (`begin_pcap_upload`/`finish_pcap_upload` ownership + path-safety),
  `tests/test_scheduler.py` (due-slot detection, DB-driven
  trigger/skip/dedup), `tests/test_fleet_capture_schedule_validation.py`,
  plus additions to `tests/test_run_store.py`/`tests/test_recovery.py`
  for the `agent_id` param and the injectable-`get_active` reaper
  refactor.
- **`marlinspike-agent`**: 14/14 passing (7 pre-existing `cli.py` tests +
  7 new in `tests/test_client_pcap.py` — chunked send byte-identical
  reassembly, fixed chunk sizing, spool-by-reference, ring-reclaim
  handling).
- **`marlinspike-capd`**: unaffected by this pass, unchanged from the
  prior pass.

Beyond the automated suite: full `docker compose build && up -d` from a
clean image, a real capture through the new pipeline confirmed byte-exact
end to end (including both concurrent-chunk races, found and fixed via
live testing — see §6), and the scheduler's automated trigger confirmed
firing with no manual action.
