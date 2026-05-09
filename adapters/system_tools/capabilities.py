"""Wireless interface capability parsing."""

from __future__ import annotations

import re
import subprocess
from dataclasses import asdict, dataclass
from typing import Any

from adapters.system_tools.runner import CommandRunner


@dataclass(frozen=True)
class InterfaceCapabilities:
    interface: str
    interface_type: str
    supported_modes: tuple[str, ...]
    channels: tuple[int, ...]
    supports_monitor: bool
    supports_ap: bool
    supports_5ghz: bool
    supports_ht: bool
    supports_vht: bool
    supports_he: bool
    recommended_modules: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_iw_list_capabilities(output: str, *, interface: str = "", interface_type: str = "") -> InterfaceCapabilities:
    modes = _parse_supported_modes(output)
    channels = _parse_channels(output)
    supports_monitor = "monitor" in modes
    supports_ap = "AP" in modes or "ap" in modes
    supports_5ghz = any(channel > 14 for channel in channels)
    supports_ht = "HT Capabilities" in output
    supports_vht = "VHT Capabilities" in output
    supports_he = "HE Iftypes" in output or "HE MAC Capabilities" in output
    recommended = _recommended_modules(supports_monitor=supports_monitor, supports_ap=supports_ap)
    return InterfaceCapabilities(
        interface=interface,
        interface_type=interface_type or "unknown",
        supported_modes=tuple(sorted(modes)),
        channels=tuple(sorted(channels)),
        supports_monitor=supports_monitor,
        supports_ap=supports_ap,
        supports_5ghz=supports_5ghz,
        supports_ht=supports_ht,
        supports_vht=supports_vht,
        supports_he=supports_he,
        recommended_modules=tuple(recommended),
    )


def collect_interface_capabilities(runner: CommandRunner, interface: str) -> InterfaceCapabilities:
    iw_list = runner.run(["iw", "list"], capture_output=True, stderr=subprocess.DEVNULL)
    iw_info = runner.run(["iw", "dev", interface, "info"], capture_output=True, stderr=subprocess.DEVNULL)
    interface_type = _parse_interface_type(iw_info.stdout) if iw_info.ok else "unknown"
    return parse_iw_list_capabilities(iw_list.stdout if iw_list.ok else "", interface=interface, interface_type=interface_type)


def _parse_supported_modes(output: str) -> set[str]:
    modes: set[str] = set()
    in_modes = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Supported interface modes:"):
            in_modes = True
            continue
        if in_modes and stripped.startswith("* "):
            modes.add(stripped[2:].strip())
            continue
        if in_modes and stripped and not stripped.startswith("* "):
            break
    return modes


def _parse_channels(output: str) -> set[int]:
    channels: set[int] = set()
    for line in output.splitlines():
        match = re.search(r"\[(\d+)\]", line)
        if match:
            channels.add(int(match.group(1)))
    return channels


def _parse_interface_type(output: str) -> str:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("type "):
            return stripped[5:].strip().lower()
    return "unknown"


def _recommended_modules(*, supports_monitor: bool, supports_ap: bool) -> list[str]:
    modules = ["Network scan", "Security audit"]
    if supports_monitor:
        modules.extend(["Handshake capture", "PMKID capture", "Packet telemetry"])
    if supports_ap:
        modules.append("Evil Twin lab")
    return modules
