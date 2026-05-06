"""Network command builders and parsers."""

from __future__ import annotations

import re
from typing import List, Optional


MAC_ADDRESS_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"
    r"|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b"
    r"|\b[0-9A-Fa-f]{12}\b"
)


def arp_lookup_command(ip_address: str) -> List[str]:
    return ["arp", "-a", ip_address]


def ping_probe_command(ip_address: str, *, count: int = 1, timeout_seconds: int = 1) -> List[str]:
    return ["ping", "-c", str(count), "-W", str(timeout_seconds), ip_address]


def normalize_mac_address(mac_address: str) -> str:
    hex_digits = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(hex_digits) != 12:
        return mac_address.lower()

    pairs = [hex_digits[index : index + 2] for index in range(0, 12, 2)]
    return ":".join(pair.lower() for pair in pairs)


def parse_mac_from_arp_output(output: str) -> Optional[str]:
    match = MAC_ADDRESS_RE.search(output)
    if not match:
        return None
    return normalize_mac_address(match.group(0))
