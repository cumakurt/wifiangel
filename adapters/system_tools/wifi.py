"""Wireless adapter system operations."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Callable, Iterable, List, Optional

from .runner import CommandRunner


def list_wireless_interfaces_sysfs(sys_class_net: Optional[Path] = None) -> List[str]:
    """Find Wi-Fi interfaces via /sys (no wireless-tools required)."""
    net = sys_class_net or Path("/sys/class/net")
    if not net.is_dir():
        return []
    names: List[str] = []
    for entry in net.iterdir():
        try:
            if entry.is_dir() and (entry / "wireless").is_dir():
                names.append(entry.name)
        except OSError:
            continue
    return sorted(names)


def parse_iw_dev_interfaces(output: str) -> List[str]:
    """Parse `iw dev` output for interface names."""
    names: List[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Interface "):
            parts = stripped.split()
            if len(parts) >= 2:
                names.append(parts[1])
    return names


def parse_iw_dev_monitor_interface(output: str) -> Optional[str]:
    """Return the first `iw dev` interface block that has ``type monitor``."""
    current: Optional[str] = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Interface "):
            parts = stripped.split()
            current = parts[1] if len(parts) >= 2 else None
        elif stripped.startswith("type monitor") and current:
            return current
    return None


def parse_iwconfig_wireless_interfaces(output: str) -> List[str]:
    interfaces = []
    for line in output.splitlines():
        if "IEEE 802.11" in line:
            parts = line.split()
            if parts:
                interfaces.append(parts[0])
    return interfaces


def parse_iwconfig_monitor_interface(output: str) -> Optional[str]:
    for line in output.splitlines():
        if "Mode:Monitor" in line:
            parts = line.split()
            if parts:
                return parts[0]
    return None


def managed_name_from_monitor(interface: str) -> str:
    if interface.endswith("mon"):
        return interface[:-3]
    return interface


class WiFiAdapterManager:
    def __init__(
        self,
        runner: CommandRunner,
        sleep: Callable[[float], None] = time.sleep,
        sys_class_net: Optional[Path] = None,
    ):
        self.runner = runner
        self.sleep = sleep
        self._sys_class_net = sys_class_net or Path("/sys/class/net")

    def list_wireless_interfaces(self) -> List[str]:
        names = list_wireless_interfaces_sysfs(self._sys_class_net)
        if names:
            return names

        try:
            output = self.runner.check_output(["iwconfig"], stderr=subprocess.STDOUT)
            names = parse_iwconfig_wireless_interfaces(output)
            if names:
                return names
        except (FileNotFoundError, subprocess.CalledProcessError, OSError):
            pass

        try:
            output = self.runner.check_output(["iw", "dev"], stderr=subprocess.DEVNULL)
            names = parse_iw_dev_interfaces(output)
            if names:
                return sorted(set(names))
        except (FileNotFoundError, subprocess.CalledProcessError, OSError):
            pass

        return []

    def find_monitor_interface(self) -> Optional[str]:
        try:
            output = self.runner.check_output(["iw", "dev"], stderr=subprocess.DEVNULL)
            name = parse_iw_dev_monitor_interface(output)
            if name:
                return name
        except (FileNotFoundError, subprocess.CalledProcessError, OSError):
            pass
        try:
            output = self.runner.check_output(["iwconfig"], stderr=subprocess.STDOUT)
            return parse_iwconfig_monitor_interface(output)
        except (FileNotFoundError, subprocess.CalledProcessError, OSError):
            return None

    def start_monitor_mode(self, interface: str) -> str:
        self.runner.run(["systemctl", "stop", "NetworkManager"], stdout=subprocess.PIPE)
        self.sleep(1)

        self.runner.run(["airmon-ng", "check", "kill"], stdout=subprocess.PIPE)
        self.runner.run(["airmon-ng", "start", interface], stdout=subprocess.PIPE)

        net_base = self._sys_class_net
        mon_suffixed = f"{interface}mon"

        # airmon-ng often renames to wlan0mon while iwconfig/iw may still report wlan0 briefly;
        # prefer the *mon netdev if it appears, and poll — avoids Scapy ENODEV on stale names.
        for _ in range(12):
            self.sleep(0.2)
            if (net_base / mon_suffixed).is_dir():
                return mon_suffixed
            found = self.find_monitor_interface()
            if found and (net_base / found).is_dir() and found != interface:
                return found

        found = self.find_monitor_interface()
        if found and (net_base / found).is_dir():
            return found

        if (net_base / mon_suffixed).is_dir():
            return mon_suffixed

        if not (net_base / interface).is_dir():
            mon_names: List[str] = []
            for entry in net_base.iterdir():
                try:
                    if (
                        entry.is_dir()
                        and (entry / "wireless").is_dir()
                        and entry.name.endswith("mon")
                    ):
                        mon_names.append(entry.name)
                except OSError:
                    continue
            if mon_names:
                return sorted(mon_names)[0]

        return interface

    def set_managed_mode(self, interface: str, *, restart_network_manager: bool = True) -> str:
        self.runner.run(["airmon-ng", "stop", interface], stdout=subprocess.PIPE)
        managed_interface = managed_name_from_monitor(interface)

        self.set_link_down(managed_interface)
        self.runner.run(["iw", managed_interface, "set", "type", "managed"], stdout=subprocess.PIPE)
        self.set_link_up(managed_interface)

        if restart_network_manager:
            self.runner.run(["systemctl", "restart", "NetworkManager"], stdout=subprocess.PIPE)

        return managed_interface

    def set_link_down(self, interface: str) -> None:
        self.runner.run(
            ["ip", "link", "set", interface, "down"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def set_link_up(self, interface: str) -> None:
        self.runner.run(
            ["ip", "link", "set", interface, "up"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def missing_tools(self, tools: Iterable[str]) -> List[str]:
        return [tool for tool in tools if self.runner.which(tool) is None]
