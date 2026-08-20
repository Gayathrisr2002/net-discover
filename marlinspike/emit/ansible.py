"""Ansible Incident Response Playbook Exporter for MarlinSpike.

Generates executable YAML Ansible Playbooks designed to isolate compromised OT assets,
block rogue command write paths, and enforce switch-port micro-segmentation.
"""

from __future__ import annotations

from typing import Any


def export_ansible_playbook(
    capture_id: str,
    findings: list[dict[str, Any]] | None = None,
    purdue_violations: list[dict[str, Any]] | None = None,
) -> str:
    """Generate an Ansible YAML playbook for automated OT incident containment."""
    findings_list = findings or []
    violations_list = purdue_violations or []

    # Extract unique malicious source IPs needing quarantine
    isolated_ips: set[str] = set()
    for f in findings_list:
        src = f.get("src_ip") or f.get("source_ip")
        sev = str(f.get("severity") or "").upper()
        if src and sev in ("CRITICAL", "HIGH"):
            isolated_ips.add(src)

    for v in violations_list:
        src = v.get("src_ip") or v.get("source_ip")
        if src:
            isolated_ips.add(src)

    ip_list = sorted(isolated_ips) or ["192.168.1.100"]

    playbook_yaml = f"""# ==============================================================================
# MarlinSpike Automated OT Incident Containment Playbook
# Generated For Capture: {capture_id}
# Target: Emergency Network Micro-Segmentation & Threat Isolation
# Standards: IEC 62443-3-3 / CISA OT Incident Response Guidelines
# ==============================================================================

- name: MarlinSpike Emergency OT Isolation Playbook
  hosts: ot_firewalls, ot_switches
  gather_facts: no
  vars:
    capture_id: "{capture_id}"
    quarantine_ips:
"""
    for ip in ip_list:
        playbook_yaml += f"      - {ip}\n"

    playbook_yaml += """
  tasks:
    - name: Display Incident Response Banner
      ansible.builtin.debug:
        msg: "Executing emergency containment for {{ quarantine_ips | length }} threat sources identified by MarlinSpike."

    # --------------------------------------------------------------------------
    # Task 1: Palo Alto Networks Firewall Rule Insertion
    # --------------------------------------------------------------------------
    - name: Quarantine Threat Source IPs on Palo Alto Firewall
      paloaltonetworks.panos.panos_address_object:
        provider: "{{ panos_provider }}"
        name: "MS_QUARANTINE_{{ item | replace('.', '_') }}"
        value: "{{ item }}"
        address_type: "ip-netmask"
        description: "Auto-isolated by MarlinSpike OT Security Engine"
      loop: "{{ quarantine_ips }}"
      when: "'paloalto' in group_names"
      ignore_errors: yes

    - name: Block Purdue Conduit Violation Group on Palo Alto
      paloaltonetworks.panos.panos_security_rule:
        provider: "{{ panos_provider }}"
        rule_name: "MS_EMERGENCY_DENY_OT_THREATS"
        source_ip: "{{ quarantine_ips }}"
        destination_ip: ["any"]
        action: "deny"
        log_end: yes
      when: "'paloalto' in group_names"
      ignore_errors: yes

    # --------------------------------------------------------------------------
    # Task 2: Cisco IOS Switch Port Micro-Segmentation & ACL Block
    # --------------------------------------------------------------------------
    - name: Apply Emergency Isolation ACL on Cisco Switches
      cisco.ios.ios_config:
        lines:
"""
    for ip in ip_list:
        playbook_yaml += f"          - access-list 150 deny ip host {ip} any\n"

    playbook_yaml += """          - access-list 150 permit ip any any
          - interface GigabitEthernet1/0/1
          - ip access-group 150 in
      when: "'cisco_switches' in group_names"
      ignore_errors: yes

    # --------------------------------------------------------------------------
    # Task 3: Linux Gateway iptables / nftables Immediate Drop
    # --------------------------------------------------------------------------
    - name: Apply Immediate Drop Rules on Linux Gateway Router
      ansible.builtin.iptables:
        chain: FORWARD
        source: "{{ item }}"
        jump: DROP
        comment: "MarlinSpike OT Threat Containment"
      loop: "{{ quarantine_ips }}"
      when: "'linux_gateways' in group_names"
      ignore_errors: yes

    # --------------------------------------------------------------------------
    # Task 4: Log Remediation Event to SIEM
    # --------------------------------------------------------------------------
    - name: Notify Enterprise SIEM of Containment Execution
      ansible.builtin.syslog:
        msg: "MarlinSpike Incident Response Playbook executed successfully. Isolated IPs: {{ quarantine_ips | join(', ') }}"
        facility: local0
        priority: alert
"""
    return playbook_yaml
