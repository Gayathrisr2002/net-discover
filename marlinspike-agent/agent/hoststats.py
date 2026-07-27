"""Lightweight host resource sampling — stdlib only.

Deliberately not psutil: this package's whole point is zero third-party
dependencies (see agent/__init__.py) so it installs on a bare remote box
with nothing else present. CPU/memory/disk are simple enough to read
straight from /proc and shutil on the Linux hosts this agent targets.
Every read degrades to None on failure (non-Linux, /proc not mounted,
permission denied) rather than raising — health reporting must never be
the reason a heartbeat fails.
"""

from __future__ import annotations

import shutil
import time


class HostStats:
    """One instance per AgentClient, created at process start. cpu_percent()
    is delta-based (busy/total jiffies since the *previous* call), so the
    very first call after construction always returns None — there's
    nothing to diff against yet."""

    def __init__(self) -> None:
        self._start_time = time.monotonic()
        self._last_cpu_times: tuple[int, int] | None = None  # (busy, total)

    def uptime_s(self) -> int:
        return int(time.monotonic() - self._start_time)

    def cpu_percent(self) -> float | None:
        try:
            with open("/proc/stat", "r", encoding="ascii") as f:
                line = f.readline()
        except OSError:
            return None
        parts = line.split()
        if len(parts) < 5 or parts[0] != "cpu":
            return None
        try:
            values = [int(x) for x in parts[1:8]]
        except ValueError:
            return None
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        busy = total - idle

        prev = self._last_cpu_times
        self._last_cpu_times = (busy, total)
        if prev is None:
            return None
        prev_busy, prev_total = prev
        delta_total = total - prev_total
        if delta_total <= 0:
            return None
        return round(100.0 * (busy - prev_busy) / delta_total, 1)

    def memory_percent(self) -> float | None:
        try:
            with open("/proc/meminfo", "r", encoding="ascii") as f:
                lines = f.readlines()
        except OSError:
            return None
        info = {}
        for raw_line in lines:
            key, _, rest = raw_line.partition(":")
            try:
                info[key] = int(rest.strip().split()[0])
            except (ValueError, IndexError):
                continue
        total = info.get("MemTotal")
        available = info.get("MemAvailable")
        if not total or available is None:
            return None
        return round(100.0 * (total - available) / total, 1)

    def disk_percent(self, path: str = "/") -> float | None:
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            return None
        if usage.total <= 0:
            return None
        return round(100.0 * usage.used / usage.total, 1)
