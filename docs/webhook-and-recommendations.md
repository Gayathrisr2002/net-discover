# Outbound Webhook, Ticketing Integrations & LLM Recommendations

Two related, independently-optional features that turn findings into
action outside the workbench:

1. **Outbound delivery** — push every risk finding from a completed scan
   into an external system: a generic signed webhook, or direct
   ticket/issue creation in **Zammad** or **Jira**.
2. **LLM-generated recommendations** — an admin-configured LLM produces a
   concise, actionable remediation suggestion for each deduplicated
   finding in a project, shown on a per-project **Recommendations** tab.

Both build on the same cross-report finding **dedup_key** (a stable hash
of project + category + description + affected assets) — the identifier
that appears in webhook payloads, ticket bodies, the findings API, and
cached recommendations, so anything consuming more than one of these
surfaces can correlate them.

---

## Outbound webhook / ticketing

Configured per-project, owner-only, under **Projects → (select a
project) → Settings**.

### Platform: Generic webhook

Fires one signed HTTP `POST` per completed scan containing every risk
finding at or above the configured minimum severity. Works with any
receiver that can parse JSON.

**Config fields:** URL, an optional signing secret, minimum severity.

**Payload:**

```json
{
  "event": "scan.completed",
  "project_id": 3,
  "project_name": "Plant Floor A",
  "run_id": "b3f1...",
  "capture_info": { "packet_count": 48213, "duration_s": 1800 },
  "finding_count": 2,
  "findings_truncated": false,
  "findings": [
    {
      "dedup_key": "9c2a...",
      "severity": "HIGH",
      "category": "CLEARTEXT_ENG",
      "description": "...",
      "affected_nodes": ["10.0.1.5"],
      "affected_edges": [],
      "cvss_impact": 7.4,
      "remediation": "..."
    }
  ]
}
```

If a secret is set, the request carries:

```
X-MarlinSpike-Event: scan.completed
X-MarlinSpike-Signature: sha256=<hmac-sha256 of the raw request body, hex-encoded>
```

Verify it (Python):

```python
import hmac, hashlib

expected = "sha256=" + hmac.new(secret.encode(), request_body, hashlib.sha256).hexdigest()
hmac.compare_digest(expected, received_signature_header)
```

A finding delivered more than once (e.g. it persists across scans)
carries the *same* `dedup_key` each time — a generic receiver should key
off that to avoid acting on the same finding twice, since this mode
delivers every qualifying finding on every completed scan rather than
tracking what it already sent.

### Platform: Zammad

Calls Zammad's own ticket API directly (`POST /api/v1/tickets`) — one
ticket per **new** finding. A finding that persists across scans does
**not** get a new ticket every time; delivery is deduplicated against a
ledger of dedup_key → ticket already tracked per project.

**Config fields:**

| Field | Notes |
|---|---|
| Zammad base URL | e.g. `https://yourcompany.zammad.com`, no trailing path |
| Zammad API token | Zammad → Profile → Token Access, with ticket read/write permission |
| Zammad group | the target group/queue — must already exist |
| Zammad customer email | **required on most instances** — Zammad's ticket API rejects a create call with no customer |
| Minimum severity | as above |

Ticket priority is resolved by name against the instance's own
`/api/v1/ticket_priorities` (not hardcoded IDs, since priorities are
admin-editable) and simply omitted if no match is found.

**Common setup issues (both surfaced with a specific error, not a raw
codec/HTTP error page):**

- *"...codec can't encode character..."* — a pasted value (usually the
  API token) contains a stray non-ASCII character, most often a literal
  `…` picked up from copy-pasting a page that displayed the value
  truncated. Re-copy the full value.
- *403 "Token authorization failed"* — check the token has a permission
  scope selected, hasn't been revoked, and that Token Access itself is
  enabled system-wide in Zammad's admin settings.
- *422 "Missing required value for field 'customer_id'"* — the customer
  email field is empty; fill it in.

### Platform: Jira

Calls Jira's REST API directly (`POST /rest/api/2/issue`) — one issue per
new finding, deduplicated the same way as Zammad. Supports both
deployment styles through one config:

| Field | Notes |
|---|---|
| Jira base URL | Cloud: `https://yourcompany.atlassian.net`; Server/Data Center: your own base URL |
| API token / personal access token | see below |
| Jira project key | the short key (e.g. `SEC`), not the project's full name |
| Jira issue type | optional, defaults to `Task` |
| Jira account email | **Cloud only** — set this to use Basic auth (email + API token); leave blank for Server/Data Center Bearer-token auth |

- **Jira Cloud**: create an API token at
  `id.atlassian.com/manage-profile/security/api-tokens`, and set the
  email field.
- **Jira Server/Data Center**: create a Personal Access Token in your
  Jira profile, and leave the email field blank.

Issue priority is resolved by name against `/rest/api/2/priority`
(matching common schemes: Highest/Critical/Blocker → high, Medium/Major
→ medium, Low/Minor/Trivial → low) and omitted if no match is found.

### Sending a test delivery

Every platform has a **Send Test Webhook** button. For the generic
platform it posts a synthetic payload; for Zammad/Jira it creates one
real, clearly-labeled test ticket/issue — the most convincing proof the
receiver actually works, and it never touches the dedup ledger (so it
never blocks a real future finding with the same content from
ticketing).

### Security notes

- Webhook/ticket URLs are SSRF-checked by default: a URL that resolves
  to a private/loopback/link-local/reserved address is rejected. A
  self-hosted receiver on an internal network needs
  `MARLINSPIKE_WEBHOOK_ALLOW_PRIVATE_TARGETS=true` set on the server.
- All of this configuration (GET/PUT/test) requires **project owner**,
  matching the same gate as project rename/delete.
- Delivery is best-effort and wrapped so a slow/unreachable/misconfigured
  receiver never breaks scan finalization.

### Findings API (poll instead of / in addition to push)

`GET /api/projects/<id>/findings` returns every deduplicated finding in
a project — the read counterpart to the webhook, useful for a
ticketing/SIEM system's own sync job instead of relying solely on push
delivery. Query params: `severity` (comma-separated, e.g.
`HIGH,CRITICAL`) and `since` (ISO-8601, filters by report-modified
time). Requires project **viewer** access. Each finding carries the same
`dedup_key` a webhook delivery for it would.

---

## LLM-generated remediation recommendations

### 1. Connect an LLM (admin, one-time, system-wide)

**System page → LLM Connectivity.** A single shared credential for the
whole deployment — an LLM API key is an org-level resource, not
something each project owner separately provisions.

Talks to any **OpenAI-compatible Chat Completions endpoint**
(`POST {base_url}/chat/completions`) — this one shape covers OpenAI
itself, Azure OpenAI, and most self-hosted options (Ollama, vLLM, LM
Studio, llama.cpp's server) without a provider-specific integration.

| Field | Example |
|---|---|
| Base URL | `https://api.openai.com/v1`, or `http://localhost:11434/v1` for a local Ollama |
| API key | your provider's key |
| Model | `gpt-4o-mini`, `llama3.1`, etc. — whatever your endpoint expects |

Click **Send Test Prompt** to confirm connectivity before relying on it.

### 2. Generate recommendations (any project member with editor+ access)

**Projects → (select a project) → Recommendations.** Lists every
deduplicated finding in the project. Click **Generate** on one finding,
or **Generate All Missing** to sequentially fill in every finding that
doesn't have one yet.

A generated recommendation is **cached** (keyed by project + dedup_key)
— it's produced once per finding and reused on every later view, not
re-requested from the LLM every time the tab is opened. **Regenerate**
overwrites the cached text if you want a fresh take.

The Recommendations tab is visible to every project member (viewer and
up) so everyone can read what's there; only editor+ can trigger
generation, matching the gate on other mutating project actions.

### Prompt design

The system prompt instructs the model to act as a Senior Principal OT/IT Cybersecurity Specialist and produce a 4-section Security Advisory:
1. **Executive & Technical Overview**: Detailed vulnerability explanation, protocol mechanics, and CVE/CWE references.
2. **Potential Security & Operational Impact**: Exploitation feasibility, Purdue Model blast radius, and physical/digital consequences.
3. **Step-by-Step Mitigation & Remediation Plan**: Immediate containment (segmentation/firewalls) and long-term fix (patching/firmware/hardening) with explicit commands and configuration snippets.
4. **Official Advisories & Reference Documentation**: Direct links to vendor advisories (CISA ICS-CERT, Siemens SSA, Rockwell, NVD, MITRE ATT&CK).

It also explicitly instructs the model to prioritize non-disruptive compensating controls (such as micro-segmentation and DPI firewalling) over immediate host reboots or aggressive patching for critical infrastructure and OT assets that cannot tolerate downtime.

### What gets sent to the LLM

Full finding context: category, severity level, engine description, CVSS impact, affected assets (IPs/MACs), affected communication paths (flow edges), MITRE ATT&CK techniques, engine baseline guidance, detection engine/plugin source, historical project occurrences, and first/last observed timestamps. No raw PCAP contents or sensitive credentials are sent.

---

## Deploying this feature

Three Alembic migrations, one env var:

```sh
python -m marlinspike.db upgrade head   # migrations 0014 (webhook_config),
                                         # 0015 (webhook_tickets),
                                         # 0016 (llm_config, finding_recommendations)
docker compose up -d --build app
```

Optional env var (only if your webhook/Zammad/Jira receiver lives on a
private network reachable from the app container):

```
MARLINSPIKE_WEBHOOK_ALLOW_PRIVATE_TARGETS=true
```
