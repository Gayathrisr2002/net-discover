"""Local key/CSR generation for mTLS enrollment (Phase 6).

The agent's private key is generated here and never leaves this host —
only the CSR (a public key plus a self-chosen, untrusted CN) is sent to
the gateway during enrollment. The gateway signs it with the fleet CA and
returns a client cert bound to the *server-issued* agent_uuid, overriding
whatever CN the CSR carried (see marlinspike/fleet/gateway/db.py:_sign_csr)
— so the throwaway CN used here is never actually trusted by anything.

Shells out to the openssl CLI rather than adding a `cryptography` dependency
— this package is deliberately dependency-free (see client.py's docstring)
so it stays installable on a bare remote box with nothing else present,
and openssl is as close to universally available on Linux as anything.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


class CertError(RuntimeError):
    pass


def generate_key_and_csr(cn: str = "pending-enrollment") -> tuple[str, str]:
    """Return (private_key_pem, csr_pem). Caller is responsible for
    persisting the key securely (credential_store.py writes it 0600
    alongside the bearer credential) — it's never transmitted anywhere."""
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "agent.key"
        csr_path = Path(tmp) / "agent.csr"
        try:
            subprocess.run(
                [
                    "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key_path),
                    "-out", str(csr_path),
                    "-subj", f"/CN={cn}",
                ],
                check=True, capture_output=True, timeout=10,
            )
        except FileNotFoundError:
            raise CertError("openssl binary not found — required for mTLS enrollment")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise CertError(f"failed to generate key/CSR: {exc}")

        return key_path.read_text(encoding="utf-8"), csr_path.read_text(encoding="utf-8")
