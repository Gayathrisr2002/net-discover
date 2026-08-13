"""Distributed Remote Sensor Agent for MarlinSpike.

Captures network traffic at remote edge subnets (substations, plant floors, DIN-rail PCs,
Cisco IE switches) and securely transmits compressed PCAP streams & telemetry to the
central MarlinSpike server.

Usage:
    python -m marlinspike.sensor_agent --server http://10.0.0.5:5000 --token SENSOR_TOKEN --interface eth0
    python -m marlinspike.sensor_agent --server http://10.0.0.5:5000 --token SENSOR_TOKEN --pcap capture.pcap
"""

import argparse
import gzip
import json
import logging
import os
import sys
import time
import urllib.request
import urllib.error
import socket

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("marlinspike.sensor_agent")


def send_payload(
    server_url: str,
    token: str,
    sensor_name: str,
    pcap_bytes: bytes,
    pcap_filename: str = "remote_capture.pcap",
    project_id: str | None = None,
) -> dict:
    """Compresses and posts PCAP payload to central MarlinSpike ingest API."""
    url = server_url.rstrip("/") + "/api/fleet/sensor/ingest"
    compressed = gzip.compress(pcap_bytes)
    
    headers = {
        "User-Agent": "MarlinsSpike-RemoteSensor/1.0",
        "X-Sensor-Token": token,
        "X-Sensor-Name": sensor_name,
        "X-Pcap-Filename": pcap_filename,
        "Content-Type": "application/octet-stream",
        "Content-Encoding": "gzip",
    }
    if project_id:
        headers["X-Project-ID"] = project_id

    req = urllib.request.Request(url, data=compressed, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8")
            return json.loads(resp_body)
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        log.error("Sensor payload rejection HTTP %d: %s", exc.code, err_body)
        raise RuntimeError(f"HTTP {exc.code}: {err_body}")
    except Exception as exc:
        log.error("Failed to connect to central MarlinSpike server: %s", exc)
        raise


def run_sensor(
    server_url: str,
    token: str,
    sensor_name: str,
    interface: str | None = None,
    pcap_path: str | None = None,
    interval: int = 60,
    project_id: str | None = None,
):
    """Main sensor capture loop."""
    log.info("Initializing MarlinSpike Edge Sensor: '%s'", sensor_name)
    log.info("Central Server: %s", server_url)

    if pcap_path:
        if not os.path.isfile(pcap_path):
            log.error("Specified PCAP file does not exist: %s", pcap_path)
            sys.exit(1)
        log.info("Reading fixed PCAP capture: %s", pcap_path)
        with open(pcap_path, "rb") as f:
            data = f.read()
        log.info("Transmitting %d bytes capture to central server...", len(data))
        res = send_payload(server_url, token, sensor_name, data, os.path.basename(pcap_path), project_id)
        log.info("Server Ingest Response: %s", res)
        return

    if not interface:
        log.error("Either --interface or --pcap must be specified.")
        sys.exit(1)

    log.info("Starting live capture on interface '%s' (upload interval=%ds)...", interface, interval)
    try:
        import subprocess
        tmp_pcap = f"/tmp/sensor_{sensor_name}_{int(time.time())}.pcap"
        while True:
            log.info("Capturing live traffic snapshot for %d seconds...", interval)
            cmd = ["dumpcap", "-i", interface, "-a", f"duration:{interval}", "-w", tmp_pcap]
            proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if proc.returncode == 0 and os.path.isfile(tmp_pcap):
                with open(tmp_pcap, "rb") as f:
                    payload = f.read()
                if len(payload) > 24:
                    log.info("Uploading %d bytes capture snapshot to central server...", len(payload))
                    try:
                        res = send_payload(server_url, token, sensor_name, payload, f"live_{interface}_{int(time.time())}.pcap", project_id)
                        log.info("Upload successful! Run ID: %s", res.get("run_id"))
                    except Exception as exc:
                        log.warning("Upload failed: %s", exc)
                try:
                    os.remove(tmp_pcap)
                except OSError:
                    pass
            else:
                time.sleep(5)
    except KeyboardInterrupt:
        log.info("Sensor capture stopped by user.")


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="MarlinsSpike Distributed Edge Sensor Agent")
    parser.add_argument("--server", required=True, help="Central MarlinSpike server URL (e.g. http://10.0.0.5:5000)")
    parser.add_argument("--token", required=True, help="Fleet Sensor API Authentication Token")
    parser.add_argument("--sensor-name", default=socket.gethostname(), help="Friendly Sensor Name")
    parser.add_argument("--interface", help="Network interface to capture (e.g. eth0)")
    parser.add_argument("--pcap", help="Path to static PCAP/PCAPNG file to upload")
    parser.add_argument("--interval", type=int, default=60, help="Live capture upload interval in seconds")
    parser.add_argument("--project-id", help="Optional target Project ID")

    args = parser.parse_args(argv)
    run_sensor(
        server_url=args.server,
        token=args.token,
        sensor_name=args.sensor_name,
        interface=args.interface,
        pcap_path=args.pcap,
        interval=args.interval,
        project_id=args.project_id,
    )


if __name__ == "__main__":
    main()
