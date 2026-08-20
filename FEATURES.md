# MarlinSpike — Features & Capabilities

> **What it is:** a **passive OT/ICS network analysis platform** — a standalone
> PCAP/PCAPNG analysis engine wrapped in a multi-user Flask web workbench.
> Capture files go in; **no packets are ever sent back onto the network.** It
> builds a topology graph, infers Purdue levels, fingerprints vendors, surfaces
> responder-grade risk findings, and exports portable artifacts for SIEMs and
> threat-intel platforms.
>
> This repository (`net-discover`) is an AGPLv3 derivative of
> [eris-ot/marlinspike](https://github.com/eris-ot/marlinspike) with bug-fix and
> security-hardening changes — see [`TRACEABILITY_MATRIX.md`](TRACEABILITY_MATRIX.md).

---

## 1. Analysis engine
- **5-stage pipeline:** ingest → dissect → topology → risk → inline malware IOC matching. Runs as one `chain` command or each stage individually.
- **Two dissection backends:** a fast Rust DPI engine (`marlinspike-dpi`, ~34 dissectors, Bronze v2 events, default `--dpi-engine auto`) with a Python/tshark fallback — ~14× faster on large captures.
- **Large-capture handling:** `--chunk-size` splits huge PCAPs into memory-bounded chunks (editcap) and merges the results, so multi-GB captures don't OOM the box.
- **Headless-capable:** the whole engine runs as a CLI with no Flask/DB dependency and emits a portable, contract-versioned JSON report.

## 2. OT/ICS protocol awareness
Native parsing/classification for **Modbus TCP, EtherNet/IP (CIP), S7comm, DNP3, IEC 60870-5-104, BACnet/IP, OPC-UA, PROFINET RT/IO, GE SRTP, Niagara Fox, OMRON FINS, Mitsubishi MELSEC, CODESYS**, plus MMS and GOOSE (IEC 61850) and DNS. Per-protocol evidence (function codes, identities, program access, etc.) is surfaced in the workbench's **Protocol Drilldown**.

## 3. Topology & fingerprinting
- Topology reconstruction (nodes / edges / conversations) from passive traffic.
- **Purdue-level inference** (with a user-supplied `--subnet-map` override).
- **Vendor fingerprinting** via an ICS OUI database (+ IEEE OUI DB), device-type and role inference (PLC, HMI, EWS, historian, …), and CIP identity-object mapping.
- **L2/ARP anomaly surface:** MAC-spoof, ARP-spoof, MAC-flap detections.

## 4. Risk detection (21 finding categories)
- **Segmentation / zoning:** `CROSS_PURDUE`, `ICS_EXTERNAL_COMMS`, `EXTERNAL_IPS_OBSERVED`, `IT_SERVICE_ON_OT_DEVICE`
- **Cleartext / weak auth:** `CLEARTEXT_ENG`, `CLEARTEXT_REMOTE_ACCESS`, `NO_AUTH_OBSERVED`, `OPC_NO_SECURITY`
- **C2 / exfil:** `C2_BEACONING`, `C2_SUSPECT_CHANNEL`, `C2_PERSISTENCE`, `C2_DATA_EXFIL`, `C2_DNS_EXFIL`, `C2_DNS_TUNNEL_SUSPECT`, `C2_DNS_HIGH_ENTROPY` (Shannon-entropy DNS analysis, length-normalized)
- **ICS abuse:** `MODBUS_WRITE_ANON`, `S7_PROGRAM_ACCESS`
- **Recon / services:** `PORT_SCAN_TARGET`, `HIGH_PORT_SERVICE`, `UNKNOWN_SERVICE_PORT`
- **Malware:** `MALWARE_IOC_MATCH`

Beaconing uses jitter-resistant interval analysis; IEC 62443 SR-oriented remediation is attached to findings.

## 5. Threat intel & enrichment (plugin surfaces)
- **MITRE ATT&CK mapping** (`marlinspike-mitre`): ICS + Enterprise domains, tactics, sub-techniques, matrix views, response guidance, YAML rule packs (with a `severity` gate).
- **Malware IOC** matching (Stage 4b, `marlinspike-malware` + rules).
- **ARP, APT, and CISA advisory** enrichment plugins, merged as report extensions.
- Enrichment is degradation-aware: if a plugin fails, the run is flagged **degraded** rather than silently reported "complete."

## 6. IOC threat hunting
- Bulk-paste IOC ingestion with auto-type detection.
- Supported IOC types: **IP, MAC, OUI, domain (incl. `*.wildcard`), SHA-256, MD5**.
- Cross-report scanning across an entire project.

## 7. Multi-user web workbench
- **Map-first analyst UI:** persistent topology canvas with a **lens strip** (Comms / Findings / IOC / ATT&CK / Baseline / Peers), a dockable inspector, and a slide-up drawer with 7 tabbed tables (Findings / Conversations / Assets / IOCs / Anomalies / ATT&CK / DNS).
- **Traffic Statistics** pane: capture KPIs, top talkers, protocol byte distribution, conversation-anomaly flags.
- **HP-HMI mode:** ISA-101 / ASM discipline — color reserved for actionable abnormality; control-room-friendly.
- **Bilingual (English / Français)** across chrome, JS panes, and engine-emitted finding text.
- **Zero-JS core:** primary triage flows work from rendered HTML.
- Pages: dashboard, projects, scans, reports, IOCs, capture, audit, **`/capabilities`** (source-backed detection-coverage catalog), system, users, profile.

## 8. Projects, collaboration & reporting
- Projects → scans → reports → workbench → triage-actions workflow.
- **Sharing** with `viewer / editor / owner` roles.
- **Project Overview:** cross-report roll-up — dedupes assets (MAC-first, IP-fallback) and findings, promotes severity to highest seen, ATT&CK coverage chips.
- Asset inventory, **asset tags / context**, finding notes, scan history.
- **Baseline / drift comparison** across captures.
- Report diffing (node / edge / protocol deltas between two reports).

## 9. Exports / interoperability
- **OCSF v1.4.0** Detection Findings (NDJSON, SIEM-ready)
- **STIX 2.1** bundles (indicators, attack-patterns, sightings)
- **Sigma** rules (Zeek / Suricata log-event detections)
- **MITRE ATT&CK Navigator** layers (ICS + Enterprise)
- Portable JSON report artifact, YAML relationship map, and the `msbundle` package format.

## 10. Live capture (optional, Linux-only, off by default)
- `marlinspike-capd` privileged sidecar over a unix socket; the unprivileged web app drives it.
- Supervises `dumpcap` with a rolling ring buffer, live BPF-filter validation, NIC enumeration, per-project saved-filter library, **per-interface locking**, and admin-override stop; rotated PCAPs feed the pipeline automatically.

## 11. Time-scrubbing & packet extraction
- Carve packets by time window / extract sub-captures for focused analysis (tshark / editcap backed).

## 12. Operations & reliability
- **Mid-scan recovery:** Flask restarts don't lose scans — the reaper re-attaches to reparented engine subprocesses (PID + argv reuse-defense), ingests finished reports, and marks genuinely-dead ones failed; multi-worker-safe via atomic claims.
- **Run-store** (`MARLINSPIKE_RUN_STORE=db`) for cross-worker concurrency correctness.
- **Audit log** with a dedicated `/audit` compliance page (write failures preserved, not swallowed).
- Per-tier scan concurrency limits.

## 13. Security & hardening
Authentication + sessions, RBAC project sharing, CSRF (full-origin), CSP / security headers, password policy + reset-token delivery, rate limiting on auth **and** expensive endpoints, `MAX_CONTENT_LENGTH` upload cap with streaming magic-byte validation, path-traversal-safe preset/filename handling, IDOR-safe run/report/ownership checks, and XSS-safe templating.

## 14. Deployment & extensibility
- **Docker Compose + PostgreSQL + Redis** (primary), headless **CLI**, and a **pip package** (`from marlinspike import create_app, db`).
- Extension hooks (`csrf_exempt`, `set_concurrent_check_fn`, reset-token delivery) so wrappers extend without forking.
- Three extension surfaces: Rust engines (subprocess JSON), Python report plugins, and declarative YAML rule packs.
- A **taxonomy module** (12 entities + 12 relationships) is the single UI source of truth; homegrown JSON-dictionary i18n; a preset sample-PCAP library.

## 15. Ticketing integrations & AI remediation recommendations
- **Outbound webhook** (per-project, owner-only): one signed HTTP POST per completed scan carrying every qualifying risk finding, with a stable `dedup_key` for receiver-side deduplication.
- **Direct ticket creation** in **Zammad** and **Jira** — calls each platform's own REST API to file one ticket/issue per *new* finding, deduplicated against a persistent ledger so a recurring finding doesn't spawn a fresh ticket every scan. Ticket/issue priority is resolved by name against the target instance's own priority scheme rather than hardcoded IDs.
- **Findings API** (`GET /api/projects/<id>/findings`) — a polling read counterpart to the webhook, for a ticketing/SIEM system's own sync job, filterable by severity and a since-timestamp.
- **LLM-generated remediation recommendations**: an admin-configured, OpenAI-compatible LLM connection (OpenAI, Azure OpenAI, or a self-hosted Ollama/vLLM/LM Studio endpoint) generates a concise, ICS/OT-aware remediation suggestion per deduplicated finding, cached per project so it's produced once and reused. Shown on each project's **Recommendations** tab.
- SSRF-guarded by default: a configured URL that resolves to a private/loopback/reserved address is rejected unless explicitly allowed for a self-hosted receiver.

## 16. Enterprise OT Vulnerability Analysis & Threat Intelligence
- **Passive CISA ICS-CERT & NVD CVE Correlation Engine:** Correlates extracted PLC model, serial numbers, and firmware versions (CIP Identity, S7 SZL) against an offline CISA ICS-CERT vulnerability database to attach explicit CVE IDs.
- **CVSS v3.1 Quantitative Scoring:** Calculates numeric CVSS impact scores (`9.8 CRITICAL`, `8.1 HIGH`, etc.) with color-coded risk indicators across all finding cards.
- **CISA KEV (Known Exploited Vulnerabilities) & Threat Intel:** Flags active threats with glowing red `🔥 CISA KEV: Actively Exploited` badges and EPSS exploit likelihood scores.
- **Vulnerability Lifecycle Status Workflow:** Interactive finding triage statuses (`Open`, `In Progress`, `False Positive`, `Risk Accepted`, `Resolved / Patched`) persisted across audit runs.

## 17. Patch Verification Diff Engine & Purdue Zero-Trust Firewall Exporter
- **Pre / Post-Patch PCAP Diff Engine:** Interactively compares baseline PCAP reports against current PCAP runs to compute vulnerability patch deltas (`Resolved Findings`, `Persistent Vulnerabilities`, `New Unmitigated Risks`).
- **Purdue Model Firewall Rule Exporter:** Generates ready-to-apply Zero-Trust micro-segmentation ACL policies (`Palo Alto PAN-OS`, `Fortinet FortiGate`, `Cisco ASA`, `Linux iptables`) to block unauthorized cross-Purdue flows observed in PCAPs.

## 18. STIX 2.1 Threat Intel & Automated Ansible Incident Response
- **STIX 2.1 Threat Intel Exporter:** OASIS STIX 2.1 JSON bundle generation (`Indicator`, `Infrastructure`, `Observed-Data`) for SIEM/TIP integration and cross-platform sharing.
- **Automated Incident Response Ansible Playbooks:** Generates executable YAML Ansible Playbooks (`marlinspike_incident_response_playbook.yml`) to automate OT threat isolation across Palo Alto Networks firewalls, Cisco switches, and Linux `iptables`.
- **Automated CISA KEV Vulnerability Matcher:** Real-time matching of discovered industrial firmware and PLC hardware models (Rockwell, Siemens, Schneider, ABB, SEL) against active CISA Known Exploited Vulnerabilities.

---

*For deeper docs on any capability, see the [`docs/`](docs/) directory (getting-started, cli-and-headless, workbench-guide, mitre-attack-guide, ioc-threat-hunting, live-capture, ocsf-emit, taxonomy, webhook-and-recommendations, and more).*
