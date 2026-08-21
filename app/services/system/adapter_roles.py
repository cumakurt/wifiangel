"""Wireless interface roles for capture versus lab AP."""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def resolve_ap_interface(app) -> str:
    """Interface used for hostapd. Falls back to the capture interface."""
    capture = str(getattr(app, "interface_name", "") or "").strip()
    ap = str(getattr(app, "ap_interface", "") or "").strip()
    if ap and ap != capture:
        return ap
    return capture


def dedicated_ap_radio(app) -> bool:
    capture = str(getattr(app, "interface_name", "") or "").strip()
    return bool(capture) and resolve_ap_interface(app) != capture


def role_exclude_ifaces(app) -> set[str]:
    names = {str(getattr(app, "interface_name", "") or "").strip(), resolve_ap_interface(app)}
    return {name for name in names if name}


def iface_present(name: str, *, sys_class_net: Optional[Path] = None) -> bool:
    if not name:
        return False
    net = sys_class_net or Path("/sys/class/net")
    return (net / name).is_dir()
