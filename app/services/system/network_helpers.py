"""Network/interface helper services for WiFiAngel."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional

from adapters.system_tools import managed_name_from_monitor


def ensure_wireless_iface_exists(app, preferred: str) -> str:
    """Return a wireless netdev that exists under /sys/class/net."""
    net_base = Path("/sys/class/net")
    candidates: list[str] = []
    if preferred:
        candidates.append(preferred)
        base = managed_name_from_monitor(preferred)
        if base != preferred:
            candidates.append(base)
    try:
        mon = app.wifi_adapter.find_monitor_interface()
        if mon and mon not in candidates:
            candidates.append(mon)
    except Exception:
        pass
    for iface in app.wifi_adapter.list_wireless_interfaces():
        if iface not in candidates:
            candidates.append(iface)
    seen: set[str] = set()
    for name in candidates:
        if not name or name in seen:
            continue
        seen.add(name)
        if (net_base / name).is_dir():
            return name
    raise FileNotFoundError(
        f"No wireless interface found (expected {preferred!r}). "
        "Check `ip link` / `iw dev`, or replug the adapter."
    )


def default_ipv4_uplink_interface(*, exclude: Optional[set[str]] = None) -> Optional[str]:
    """Device from `ip -4 route show default`, excluding AP iface(s)."""
    skip = exclude or set()
    try:
        result = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        net_base = Path("/sys/class/net")
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line.startswith("default"):
                continue
            parts = line.split()
            if "dev" not in parts:
                continue
            idx = parts.index("dev")
            if idx + 1 >= len(parts):
                continue
            dev = parts[idx + 1]
            if dev in skip:
                continue
            if (net_base / dev).is_dir():
                return dev
        return None
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None


def renew_dhcp_on_interface(iface: str) -> None:
    """Try to refresh DHCP on an interface after NetworkManager stops."""
    if not iface or not (Path("/sys/class/net") / iface).is_dir():
        return
    if shutil.which("dhclient"):
        subprocess.run(
            ["dhclient", "-1", iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
        return
    if shutil.which("dhcpcd"):
        subprocess.run(
            ["dhcpcd", "-n", iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )


def interface_is_wireless(iface: str) -> bool:
    """True if iface is an 802.11 netdev."""
    if not iface:
        return False
    try:
        return (Path("/sys/class/net") / iface / "wireless").is_dir()
    except OSError:
        return False


def evil_twin_nonwifi_internet_uplink_ok(app, uplink: Optional[str]) -> tuple[bool, str]:
    """
    Evil Twin internet sharing expects a non-Wi-Fi default route.
    Returns (True, "") if uplink exists and is not wireless; else (False, reason).
    """
    if not uplink:
        return False, "no_uplink"
    if app._interface_is_wireless(uplink):
        return False, "wifi_uplink"
    return True, ""
