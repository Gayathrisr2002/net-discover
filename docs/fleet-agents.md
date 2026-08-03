# Fleet — Remote Sensor Agents

MarlinSpike can drive live capture on hosts it never touches directly.
A small `marlinspike-agent` process runs on a remote sensor host,
authenticates to your MarlinSpike server over TLS, and forwards raw
capture traffic back for analysis — the server runs the actual
MarlinSpike engine, the remote host just captures and ships bytes.

This document is for the operator enrolling and managing remote
agents from the Fleet page. For deployment/packaging of the gateway
itself, see [INSTALL.md](../INSTALL.md). For the underlying design
history and known gaps, see
[fleet-agent-poc.md](fleet-agent-poc.md).

---

## When to use it

Fleet agents replace the workflow of "walk over to the remote switch,
plug in a laptop, capture, walk back, upload." It's the right call
when:

- You have OT/IT sites you can't physically sit at, but can put a
  small always-on host at (a NUC, an old laptop, a Raspberry Pi with
  a NIC on the SPAN port).
- You want captures **centrally analyzed and reported** rather than
  trusting each remote host to run its own copy of the engine.
- You want a **recurring, unattended** capture (see [Automated
  capture schedule](#automated-capture-schedule)) instead of someone
  remembering to start one.

It's the wrong call when:

- You already have physical/SPAN access to the host running
  MarlinSpike itself — use [Live Capture](live-capture.md) directly,
  no agent needed.
- You need true multi-site, hierarchical, always-on centralized
  monitoring at scale — that's what FATHOM is for. Fleet agents give
  you remote-triggered capture, not continuous monitoring.

## How it works

```
┌─ remote sensor host ─────────────┐        ┌─ MarlinSpike server ──────────────┐
│                                   │        │                                    │
│  marlinspike-agent                │  TLS   │  fleet-gateway (port 8765)         │
│  (mTLS + bearer credential)  ─────┼───────►│  authenticates, tracks online/     │
│                                   │        │  offline status, relays capture    │
│  marlinspike-capd (optional)      │        │  start/stop commands               │
│  (privileged capture sidecar)     │        │                                    │
└───────────────────────────────────┘        │  receives rotated pcaps as raw     │
                                              │  bytes, runs the normal analysis   │
                                              │  chain, reports land in the        │
                                              │  agent's project like any other    │
                                              │  scan                              │
                                              └────────────────────────────────────┘
```

The agent never analyzes anything locally — it only captures (via its
own local `capd` sidecar) and forwards raw pcap bytes over the same
authenticated connection it uses for enrollment and heartbeats. This
means a compromised or out-of-date agent can't produce a wrong report:
the server always runs the current, real analysis pipeline.

## Agents belong to a Project

Every agent is enrolled directly under an existing **Project** —
there's no separate "site" concept to manage. This means:

- An agent's project determines who can see and manage it: anyone who
  can access that Project (owner, or a viewer/editor/owner via
  [project sharing](projects-and-engagements.md)) can see its agents;
  editors and owners can revoke, rotate, or delete them.
- An agent's captures land in that same project's Reports, exactly
  like a local upload or a Live Capture session — no separate
  "fleet reports" view to check.
- The project's existing **capture policy** (`GET/PUT
  /api/capture/policy/<id>`) governs what a remote agent's capture is
  allowed to do (enabled interfaces, max duration, max retained
  bytes) — the same policy that gates local/Live Capture sessions,
  not a separate per-agent one.

If you need agents from two engagements kept separate, put them under
two different Projects.

## Enrolling an agent

From the **Fleet** page:

1. Select (or create, via the **Projects** page) the project this
   agent should belong to.
2. Click **Rotate Enrollment Token**. This mints a standing,
   reusable enrollment token for the project — reusable for any
   number of agents until you explicitly rotate it again (rotating
   revokes the old one; already-enrolled agents keep working).
3. Follow the four steps shown in the modal:
   1. **Install the agent** — download the `.deb` (Debian/Ubuntu) or
      the source tarball (other Linux) from the buttons on the Fleet
      page.
   2. **Get the gateway's CA certificate** — download it if your
      deployment has one configured, or use
      `--insecure-skip-verify` for testing only.
   3. **Enroll** — a ready-to-copy `marlinspike-agent enroll` command
      with the token, gateway address, and CA-cert flag already
      filled in. The gateway host/port are auto-detected from how you
      reached the Fleet page when possible (see [Gateway host
      auto-detection](#gateway-host-auto-detection) below) — the port
      is essentially always correct (`FLEET_GATEWAY_PUBLIC_PORT`
      defaults to `8765`); only the host may need manual correction if
      auto-detection couldn't determine it.
   4. **Start it**:
      ```bash
      sudo chown marlinspike-agent:marlinspike-agent /etc/marlinspike-agent/credential.json
      sudo systemctl enable marlinspike-agent
      sudo systemctl restart marlinspike-agent
      ```
      Uses `restart`, not `enable --now` — see
      [Troubleshooting](#troubleshooting) for why that distinction
      matters if you ever re-run enrollment against a host that
      already has the agent running.
4. Optionally, install `marlinspike-capd` (step 5 in the modal) if you
   want to start/stop live captures on this agent from the console.
   Without it, the agent still enrolls, heartbeats, and reports fine
   — it just can't be told to start a capture.

Once running, the agent authenticates and starts heartbeating —
within a few seconds it should show **online** in the agent table
on the Fleet page. An agent that stops heartbeating for 90 seconds is
marked **offline** automatically.

## Managing agents

Each agent row in the Fleet page's agent table shows its status,
health, resource usage (from its last heartbeat), uptime, agent
version, and last-seen time, plus these actions:

- **Rotate Credential** — invalidates the agent's current credential
  (and mTLS cert, if any) and mints a one-time rotation token. Redeem
  it with `marlinspike-agent enroll --token ...` on the same host —
  the agent keeps its identity and history (same row, same
  `agent_uuid`), only the credential changes. Use this if a
  credential may have been compromised, without losing the agent's
  event history.
- **Revoke** — permanently disconnects the agent and invalidates its
  credential. A revoked agent can't reconnect; re-enrolling it (with a
  fresh standing token) creates a brand-new agent row rather than
  reviving this one.
- **Delete** — only available once an agent is revoked. Permanently
  removes it from the list. Any reports or captures it was ever
  attributed to are kept — they're just no longer linked to an agent
  record.

### Project members

The **Members** button manages who else can access this project (and
therefore its agents) — the same viewer/editor/owner sharing model
used everywhere else in MarlinSpike. See
[projects-and-engagements.md](projects-and-engagements.md) for the
role semantics.

## Running a capture on a remote agent

From the **Live Capture** page, the "Run on" dropdown next to the
project picker lists every **online** agent under the selected
project (offline/revoked agents are never offered). Pick one instead
of "Local (this server)" and the rest of the workflow — interface,
BPF filter, ring size, duration — is identical to a local capture.
Progress and stats stream back the same way; when the agent rotates a
pcap, it's forwarded and analyzed exactly like a local rotation, and
the resulting report lands in the project.

## Automated capture schedule

Instead of manually starting a capture each time, a project can have
a recurring schedule: at each configured time of day (UTC), MarlinSpike
automatically starts a capture on **every currently online agent**
under that project.

From the Fleet page, select a project and click **Capture Schedule**:

- **Enabled** — turns the schedule on/off. Disabling keeps your
  times/interface/filter filled in, so re-enabling later doesn't mean
  retyping everything.
- **Times (UTC)** — add/remove HH:MM times. At least one is required
  to enable the schedule.
- **Duration (seconds)** — how long each triggered capture runs.
- **Interface** — which NIC name to capture on (must exist on the
  agent(s) — check the Live Capture page's interface dropdown for a
  given agent if you're not sure of the exact name).
- **BPF Filter** — optional, leave blank to capture everything.
- The modal also shows when the schedule last actually fired, so you
  can confirm it's working.

Mechanically: a background thread checks every 60 seconds for a due
time slot, with a 3-minute grace window (so a slot isn't missed just
because the app was briefly restarting exactly then) — a slot missed
by more than that is simply skipped until its next occurrence rather
than firing hours late. This applies to the whole project: any agent
enrolled under it later is automatically included, with no per-agent
schedule to configure.

## Gateway host auto-detection

The enroll command's `--gateway host:port` needs to be an address the
remote agent can actually reach — not necessarily the address you're
browsing the Fleet page from. MarlinSpike fills this in automatically
when it safely can:

- If the operator has set `FLEET_GATEWAY_PUBLIC_HOST` (recommended for
  production), that value always wins.
- Otherwise, it guesses from the host you reached the Fleet page on —
  correct in the common case where you and the agent reach the
  deployment the same way, but deliberately **never** guessed from
  `localhost`/`127.0.0.1`/`::1`, since a loopback address is only
  correct if the agent happens to run on the exact same box as your
  browser. An honest `<your-gateway-host>` placeholder beats a
  confidently wrong guess.
- The port almost always fills in correctly either way
  (`FLEET_GATEWAY_PUBLIC_PORT` defaults to `8765`).

If you always see the placeholder instead of a real address, set
`FLEET_GATEWAY_PUBLIC_HOST` in your deployment's environment.

## Troubleshooting

**Agent shows "unauthorized" reconnect errors in its logs, and stays
offline in the UI, even though enrollment succeeded.**
This almost always means the `marlinspike-agent` systemd service was
already running from an earlier enrollment attempt, and you re-ran
`enroll` (writing a fresh `credential.json`) without restarting it.
`systemctl enable --now` on an **already-running** service does
nothing — it's a no-op if the unit is active, so the running process
keeps using its old, possibly-now-revoked credential in memory while
the new one sits unused on disk. Fix:
```bash
sudo systemctl restart marlinspike-agent
```
This is exactly why step 4 above uses `restart` rather than
`enable --now` — it's correct whether the agent is starting for the
first time or already running.

**Agent enrolled but never appears in the Fleet page's agent list.**
Confirm you're looking at the same project the enrollment token was
issued for — agents are project-scoped, and enrolling with one
project's token always creates the agent under that project, not
whichever one happens to be selected in the UI at the time.

**The enroll command's `--gateway` value is a bracket placeholder.**
See [Gateway host auto-detection](#gateway-host-auto-detection) above
— set `FLEET_GATEWAY_PUBLIC_HOST` explicitly.

**A real TLS handshake (not `--insecure-skip-verify`) fails with `CA
cert does not include key usage extension`.**
This is a certificate-generation issue on the server side, not
something to fix on the agent — see
[fleet-agent-poc.md](fleet-agent-poc.md) for the root cause and fix if
you're generating your own gateway CA.

**Live Capture's "Run on" dropdown doesn't show an agent I know is
online.**
It only lists agents under the **currently selected project** on the
Live Capture page — switch to the project the agent is enrolled
under.
