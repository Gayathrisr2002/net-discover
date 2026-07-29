# Remote Fleet Agent + Live Capture — Proof of Concept

**Status:** validated end-to-end on real hardware. This document is a snapshot of
a hardening/validation pass over the existing distributed fleet-agent
architecture (introduced in `f4d3083`, "Add distributed agent architecture:
fleet management, remote capture control (Phases 1-3)", and built out further
in the commits since). It is not a from-scratch description of the
architecture — see the code itself (`marlinspike/fleet/`, `marlinspike-agent/`,
`marlinspike-capd/`) and each package's own README for that.

**Purpose of this document:** record what was concretely proven to work (with
real commands and real numbers, not just code review), what bugs were found
and fixed to get there, and — most importantly — what is still genuinely
missing before this is a production-ready capability rather than a validated
proof of concept. Treat the "Known gaps" section as the punch list for
whoever picks this up next.

## 1. What this proves

A remote sensor host, with nothing but `marlinspike-agent` installed, can:

1. Enroll itself against a central MarlinSpike server over mTLS, using a
   one-time site enrollment token.
2. Maintain an authenticated heartbeat connection, surfaced as
   online/offline status on the Fleet page.
3. Have a live packet capture started and stopped on it *from the central
   console* — the operator never touches the remote host directly.
4. Run the **full analysis engine locally** on each rotated capture and ship
   only the resulting JSON report back to the server — not the raw PCAP.
5. Have that report land in the server's normal Reports page, in the right
   project, indistinguishable from a locally-uploaded-and-scanned capture.

Every one of these was exercised for real on the same physical box acting as
both the MarlinSpike server and the remote agent — not simulated, not
mocked. See §3 for the actual commands and output.

## 2. Bugs found and fixed to get here

These surfaced in order, each only becoming visible once the previous one was
fixed — a real "peel the onion" deployment debugging arc, not a designed test
plan:

| # | Symptom | Root cause | Fix |
|---|---|---|---|
| 1 | `--gateway http://host:port` silently connected to the wrong host | naive `rpartition(":")` parsed the whole `http://host` as the hostname | strip a `scheme://` prefix before splitting (`f2fcf90`) |
| 2 | App unreachable via LAN IP | port mapping hardcoded to `127.0.0.1` | `APP_BIND_HOST`, now defaults to `0.0.0.0` (`18f8cea`, `fee8d3f`) |
| 3 | Login silently failed after LAN exposure | browsers refuse a `Secure`-flagged cookie over plain HTTP to a non-localhost host | `SESSION_COOKIE_SECURE=false` shipped paired with the LAN default |
| 4 | `fleet-gateway` never started | required a separate `--profile fleet` flag | starts automatically now (`555208f`) |
| 5 | `fleet-gateway` crash-looped | no TLS certs, no automated generation | `certs-init` one-shot service auto-generates them (`e5715d3`) — deliberately *not* a baked-in default cert, since that would mean every deployment shares one private key |
| 6 | Real cert verification (not `--insecure-skip-verify`) failed: *"CA cert does not include key usage extension"* | `openssl req -x509`'s implicit defaults for `keyUsage`/`basicConstraints` aren't reliable across OpenSSL versions | explicit `-addext` flags on both CA and leaf cert (`4965921`) — found because this was the first time a *real* agent used real chain verification instead of `--insecure-skip-verify` in all prior testing |
| 7 | *"IP address mismatch"* enrolling against the server's real LAN IP | generated cert's SAN only ever covered `localhost`/`127.0.0.1`/`marlinspike-fleet-gateway` | `FLEET_GATEWAY_PUBLIC_HOST` now baked into the cert's SAN at generation time (`821767f`) |
| 8 | `marlinspike-agent.service` failed with `226/NAMESPACE` | `ReadWritePaths=/var/run/marlinspike-capd` required that path to exist, but `marlinspike-capd` isn't installed on every agent host | made the path tolerant of being absent with systemd's `-` prefix (`87cc73b`) |
| 9 | `credential.json`'s `ca_cert` path broke under the sandboxed unit | a relative `--ca-cert ./fleet-ca.crt` (naturally typed from `~/Downloads`) resolves against the wrong directory once systemd's `ProtectHome=true` hides `/home` entirely — true even once resolved to an absolute path, since `ReadOnlyPaths` only allow-lists `/etc/marlinspike-agent` | embed the CA cert's **PEM content** directly in `credential.json` instead of a path reference, loaded via `ssl.load_verify_locations(cadata=...)` (`85d451a`) |
| 10 | `marlinspike-capd` failed every capture: `dumpcap not found on PATH` | Debian/Ubuntu restrict `dumpcap` execution to `root`/`wireshark` group; capd's own unprivileged system user wasn't a member | `systemd/install.sh` now auto-adds the `wireshark` group if present (`a45c943`) |
| 11 | An allow-listed uid still couldn't reach capd's socket at all | `RuntimeDirectoryMode=0750` blocked traversal into the socket's directory before SO_PEERCRED (the actual intended auth boundary) ever ran | loosened to `0755` to match `server.py`'s own security model — the socket file itself is already `0666` (`a45c943`) |
| 12 | Live capture "disabled" on the server itself | the `capd` sidecar was opt-in (`docker compose --profile capture up`), separate from the `LIVE_CAPTURE_ENABLED` flag that actually gates it | `capd` now starts with the rest of the stack by default (`0600786`) |
| 13 | No easy way to get `marlinspike-capd` onto a remote sensor host | only a manual `pip install` + `systemd/install.sh` path existed | added a downloadable, pre-built `.deb` (`scripts/build_capd_deb.sh`, `0600786`), mirroring the agent's own `.deb` |
| 14 | A stopped-then-restarted agent kept getting `unauthorized` after re-enrolling | the running process held the *old* (now-revoked) credential in memory — re-running `enroll` writes a fresh `credential.json`, but a live process never re-reads it | not a bug — `systemctl restart marlinspike-agent` after any re-enrollment (revoke, rotate-credential) picks up the current file |
| 15 | Agent-side scan failed: `No module named marlinspike` | **the single biggest gap found** — the agent needs the full `marlinspike` engine package (+ `tshark`) installed locally to run its analysis chain, and nothing packages that for a remote host today | worked around manually for this validation (see §3); **this is the top item in §4**, not yet fixed properly |

## 3. How this was actually verified (reproducible)

On a single box running both the server stack (`docker compose up -d`) and a
bare-metal `marlinspike-agent` + `marlinspike-capd`:

```bash
# 1. Enroll + start the agent
sudo marlinspike-agent enroll --gateway <server-ip>:8765 --token <token> \
    --ca-cert ./fleet-ca.crt --name my-agent \
    --credential-file /etc/marlinspike-agent/credential.json
sudo chown marlinspike-agent:marlinspike-agent /etc/marlinspike-agent/credential.json
sudo systemctl enable --now marlinspike-agent
# -> "authenticated as <uuid>" in journalctl, Fleet page shows it online

# 2. Start a live capture on it from the server's API (same as the UI does)
curl -X POST http://<server>:5001/api/capture/sessions \
    -d '{"project_id":1,"agent_id":<id>,"interface":"enp2s0"}'
# -> real bytes/packets accumulate (~2.7MB / 2,775 packets over ~20s in one run)

# 3. Stop it, and the agent scans + ships the report on its own
sudo journalctl -u marlinspike-agent -f
# -> "scan complete: ..." then "shipped report ... (50517 bytes, 1 chunks)"
```

Confirmed server-side afterward:

```sql
SELECT id, agent_id, status, pcap_source FROM scan_history ORDER BY id DESC LIMIT 1;
--  id | agent_id |  status   |           pcap_source
-- ----+----------+-----------+---------------------------------
--   1 |        1 | completed | cap_00001_20260729155014.pcapng
```

...and the same report visible through `/api/reports?project_id=1`, exactly
like a manually-uploaded PCAP would be.

## 4. Known gaps — the actual punch list for future work

Ranked by how much they block real deployment, most important first.

### 4.1 No packaging for the agent-side analysis engine (critical)

`marlinspike-agent/agent/consumer.py` explicitly documents that a remote
agent host needs the full `marlinspike` Python package (`engine.py` +
`plugins/` + `rules/` + `presets/`) *and* `tshark` installed and importable
locally, to run `python -m marlinspike ... chain` on each rotated capture.
Nothing today builds or ships that for a bare remote host — `marlinspike-agent`
and `marlinspike-capd` both have proper `.deb`s; the engine itself has none.

For this validation, the engine's package tree was manually copied to
`/opt/marlinspike-engine` and wired in via a systemd drop-in
(`PYTHONPATH`/`MARLINSPIKE_PROJECT_ROOT`), and `tshark` was installed
separately with `apt-get install tshark` (present on the server image's
Dockerfile, but not assumed on a bare agent host). This is not a
repeatable, supportable install path.

**Recommended fix:** a `scripts/build_engine_deb.sh` (or a plain tarball,
mirroring `build_agent_deb.sh`'s approach) that packages `marlinspike/`,
`plugins/`, `rules/`, `presets/`, `data/oui.json` as their own installable
unit, declares `tshark` as a Depends, and is downloadable from the Fleet
page alongside the agent and capd `.deb`s. `engine.py` and `__main__.py`
are confirmed to have zero Flask/SQLAlchemy/DB imports (verified directly:
`python3 -c "import marlinspike.engine"` succeeds with no web-app
dependencies installed) — so this genuinely can be a lightweight package,
not a repackaging of the whole web app.

### 4.2 TLS CA is dev-grade by design

`scripts/gen_dev_tls_cert.sh` says so directly in its own header comment:
"LOCAL/DEV TESTING ONLY." A real production rollout needs either a real
internal CA or a documented, supported process for bringing your own
certs — today there's no path other than hand-editing what `certs-init`
generates.

### 4.3 `--allow-uid` still needs a manual systemd edit

Both the source-install (`systemd/install.sh`) and the new `.deb`'s
`postinst` print instructions to manually `systemctl edit --full` and add
`--allow-uid=<uid>` — there's no automated way for the installer to know
which uid needs access (the web app's container uid, or `marlinspike-agent`'s
uid, depending on deployment). A config-file-driven approach (capd reads an
allow-list file instead of a command-line flag) would let both `.deb`
postinst scripts wire this up automatically instead of leaving it as a
manual step every single time.

### 4.4 No visibility into *why* an online agent's capture fails

Right now, if an agent is online but its local `capd` isn't reachable (not
installed, crashed, wrong `--allow-uid`), the only way to find out is to
SSH into the agent host and read its journal — the Fleet page shows the
agent as online with no indication that live capture specifically is
broken there. Surfacing agent-side capd reachability (the agent already
knows this — see `client.py`'s `list_interfaces` relay) as a status badge
next to the agent would close a real diagnostic gap.

### 4.5 Environment resets during this validation

Multiple times during this session, the Docker stack, the systemd units,
or the repo checkout itself were found reset/recreated with no action
taken by either the user or this assistant. Not a code bug — noted here
only because it makes "is this actually still working" a question worth
re-asking rather than assuming, if you're picking this up after any gap in
time.

## 5. Regression testing performed

Full suite run after every change in this pass, `pytest -q` from the repo
root plus each sub-package:

- **Main app** (`tests/`, ~483 collected): 6 pre-existing, order-dependent
  failures — `test_audit_failure_visibility.py`,
  `test_extract_timeline.py` (multiple), `test_inmemory_db_warning.py`,
  `test_reset_token_delivery.py`, and intermittently
  `test_security_v352.py::test_setup_wizard_admin_password_strength`.
  Every one of these passes in isolation (confirmed individually) — they
  fail only under full-suite execution ordering, a pre-existing
  characteristic of this suite, not something introduced by this pass.
  Zero new failures attributable to any change described in this
  document.
- **`marlinspike-agent`**: 7/7 passing.
- **`marlinspike-capd`**: 17/17 passing.

Beyond the automated suite, §3's live end-to-end run (enroll → heartbeat →
remote capture start/stop → local scan → report shipped → visible in
Reports) was re-verified after every code change in this pass, including a
full `docker compose build && docker compose up -d` from a clean image to
confirm nothing regressed for a brand-new deployment.
