# marlinspike-capd

Privileged sidecar capture daemon for MarlinSpike. Owns `CAP_NET_RAW` /
`CAP_NET_ADMIN`, supervises `dumpcap`, and exposes a small uds JSON-RPC
API to the unprivileged MarlinSpike web app.

## Why a sidecar

MarlinSpike's web app runs unprivileged. Live capture needs raw-packet
access, which would otherwise force the web process to inherit dangerous
capabilities. capd isolates that surface: it does only three things —
enumerate interfaces, validate BPF filters, and run `dumpcap` with
rotation — and talks to the web app exclusively over a unix-domain
socket guarded by SO_PEERCRED.

## Install

```bash
pip install -e ./marlinspike-capd
```

`dumpcap` (Wireshark) and `libpcap` must be present on the host.

On Debian/Ubuntu, `dumpcap` ships non-setuid and is only executable by
`root` or members of the `wireshark` group (`dpkg -L wireshark-common`
installs it `rwxr-x---`-ish — no execute bit for "other"). If capd runs
as its own unprivileged system user (as `systemd/install.sh` sets up),
that user needs adding to the `wireshark` group, or every capture
attempt fails with a confusing `RuntimeError: dumpcap not found on
PATH` — despite `which dumpcap`/`dumpcap --version` working fine as
root. `systemd/install.sh` does this automatically if the `wireshark`
group exists.

## CLI

```bash
# List physical interfaces (filters out docker*, veth*, br-*, tun*, wg*, tailscale*).
python -m capd list-interfaces
python -m capd list-interfaces --all

# Validate a BPF filter without opening any interface.
python -m capd validate-bpf "tcp port 502 or tcp port 102"

# Run the daemon.
sudo python -m capd serve --socket /var/run/marlinspike-capd.sock

# The web app (or, on a remote sensor host, a locally installed
# marlinspike-agent) connects as some other, unprivileged uid -- capd
# only trusts its own uid (root) by default, so that other uid must be
# explicitly allowed or every request from it fails with "unauthorized".
# --allow-uid is a static, one-shot list baked into the command line:
sudo python -m capd serve --socket /var/run/marlinspike-capd.sock --allow-uid=1000

# --allow-uid-file is the dynamic alternative (what the shipped systemd
# unit and both .deb postinst scripts actually use) -- one uid per line,
# re-read on every connection attempt (cheap mtime check), so appending
# a uid takes effect immediately with no restart:
sudo python -m capd serve --socket /var/run/marlinspike-capd.sock \
    --allow-uid-file=/etc/marlinspike-capd/allowed-uids
```

JSON over uds, length-prefixed (4-byte big-endian length, then UTF-8
JSON). One request → one response, except `stats` which streams. See
`capd/server.py` for the canonical schema.

## License

AGPL-3.0-or-later. See repo root `LICENSE`.
