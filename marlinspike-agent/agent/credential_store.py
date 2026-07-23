"""Local credential file — the agent's persisted identity after enrollment.

Written once by `marlinspike-agent enroll`, read on every `marlinspike-agent
run`. Hardened the same way capd's systemd unit hardens its own state
(dedicated system user, restrictive file mode) — this file is effectively
a bearer credential for this agent's identity in the fleet.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CREDENTIAL_PATH = "/etc/marlinspike-agent/credential.json"


@dataclass
class AgentCredentials:
    gateway_host: str
    gateway_port: int
    ca_cert: str | None
    insecure_skip_verify: bool
    agent_uuid: str
    credential: str
    # mTLS client identity (Phase 6), present only when the gateway had a
    # fleet CA configured at enrollment time — client_key_pem never leaves
    # this file (generated locally by certs.py, never sent to the gateway).
    # Both None for agents enrolled before this upgrade or against a
    # gateway with no CA set up; build_ssl_context treats that as "no
    # client cert to present" and falls back to bearer-credential-only auth.
    client_cert_pem: str | None = None
    client_key_pem: str | None = None

    @classmethod
    def load(cls, path: str) -> "AgentCredentials":
        with open(path, "r") as f:
            data = json.load(f)
        return cls(
            gateway_host=data["gateway_host"],
            gateway_port=int(data["gateway_port"]),
            ca_cert=data.get("ca_cert"),
            insecure_skip_verify=bool(data.get("insecure_skip_verify", False)),
            agent_uuid=data["agent_uuid"],
            credential=data["credential"],
            client_cert_pem=data.get("client_cert_pem"),
            client_key_pem=data.get("client_key_pem"),
        )

    def save(self, path: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "gateway_host": self.gateway_host,
            "gateway_port": self.gateway_port,
            "ca_cert": self.ca_cert,
            "insecure_skip_verify": self.insecure_skip_verify,
            "agent_uuid": self.agent_uuid,
            "credential": self.credential,
            "client_cert_pem": self.client_cert_pem,
            "client_key_pem": self.client_key_pem,
        }
        # Write then chmod, rather than relying on umask, so the credential
        # is never briefly world-readable between create and chmod.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
        finally:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600, belt-and-suspenders
