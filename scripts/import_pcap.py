#!/usr/bin/env python3
"""Import a PCAP directly into a project's upload directory.

Emergency escape hatch for when the browser upload path is broken: writes
straight into the same directory the web app's /api/files and scan-start
routes read from (the marlinspike-data Docker volume), so the file shows up
in the dashboard's file list — ready to scan — without going through HTTP,
CSRF, or the browser at all.

Run this on the Docker host (not inside a container), as a user with
permission to run `docker exec`/`docker volume inspect` and to write to the
Docker volume's backing directory (root, typically).

Usage:
    python3 scripts/import_pcap.py --project-id 1 /path/to/capture.pcap

Find the project id in the dashboard URL or via:
    docker exec marlinspike-db psql -U marlinspike -d marlinspike \\
        -c "SELECT id, name, user_id FROM projects;"
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",  # pcap LE, microsecond
    b"\xa1\xb2\xc3\xd4",  # pcap BE, microsecond
    b"\xa1\xb2\x3c\x4d",  # pcap nanosecond variant
    b"\x4d\x3c\xb2\xa1",  # pcap nanosecond variant
    b"\x0a\x0d\x0d\x0a",  # pcapng
}

VOLUME = "net-discover_marlinspike-data"
DB_CONTAINER = "marlinspike-db"
APP_UID = 1000
APP_GID = 1000


def volume_mountpoint() -> str:
    out = subprocess.run(
        ["docker", "volume", "inspect", VOLUME, "-f", "{{.Mountpoint}}"],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def project_owner_uid(project_id: int) -> int:
    sql = f"SELECT user_id FROM projects WHERE id = {int(project_id)};"
    out = subprocess.run(
        ["docker", "exec", DB_CONTAINER, "psql", "-U", "marlinspike", "-d", "marlinspike", "-tA", "-c", sql],
        capture_output=True, text=True, check=True,
    )
    value = out.stdout.strip()
    if not value:
        raise SystemExit(f"No project with id={project_id}")
    return int(value)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="Path to the PCAP/PCAPNG file to import")
    ap.add_argument("--project-id", type=int, required=True, help="Destination project id")
    args = ap.parse_args()

    src = args.file
    if not os.path.isfile(src):
        print(f"No such file: {src}", file=sys.stderr)
        return 1

    with open(src, "rb") as f:
        magic = f.read(4)
    if magic not in PCAP_MAGIC:
        print(f"Not a valid PCAP/PCAPNG file (magic bytes: {magic.hex()})", file=sys.stderr)
        return 1

    uid = project_owner_uid(args.project_id)
    mountpoint = volume_mountpoint()
    dest_dir = os.path.join(mountpoint, "uploads", str(uid), str(args.project_id))
    os.makedirs(dest_dir, exist_ok=True)

    dest = os.path.join(dest_dir, os.path.basename(src))
    shutil.copyfile(src, dest)
    os.chown(dest, APP_UID, APP_GID)
    os.chmod(dest, 0o644)

    print(f"Imported: {src}")
    print(f"       -> {dest}")
    print("Refresh the dashboard — the file should now appear in the project's file list, ready to scan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
