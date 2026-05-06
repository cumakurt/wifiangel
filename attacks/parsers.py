"""Parsers for attack tool output."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Optional, Sequence


@dataclass(frozen=True)
class AircrackNetworkInfo:
    bssid: str
    essid: str
    is_wpa3: bool = False


PASSWORD_PATTERNS = (
    re.compile(r"KEY FOUND!\s*\[\s*([^\]]+?)\s*\]"),
    re.compile(r"KEY FOUND:\s*\[\s*([^\]]+?)\s*\]"),
    re.compile(r'The password is "([^"]+?)"'),
    re.compile(r"Password:\s*([^\s]+)"),
    re.compile(r"FOUND KEY:\s*([^\s]+)"),
)


def has_aircrack_handshake(output: str, bssid: Optional[str] = None) -> bool:
    if "1 handshake" not in output:
        return False
    if bssid and bssid.lower() not in output.lower():
        return False
    return True


def parse_aircrack_network_info(output: str) -> Optional[AircrackNetworkInfo]:
    lines = output.splitlines()
    header_line_idx = -1

    for i, line in enumerate(lines):
        if "BSSID" in line and "ESSID" in line:
            header_line_idx = i
            break

    if header_line_idx < 0:
        return None

    for line in lines[header_line_idx + 1 : header_line_idx + 5]:
        data_line = line.strip()
        if not data_line or data_line.startswith("Choosing"):
            continue

        parts = data_line.split(None, 1)
        if len(parts) >= 2 and _looks_like_mac(parts[0]):
            essid = parts[1].strip()
            if essid and essid != "ESSID" and "Encryption" not in essid:
                return AircrackNetworkInfo(
                    bssid=parts[0].strip(),
                    essid=essid,
                    is_wpa3="WPA3" in output,
                )

    return None


def extract_wifi_password(output: str, *, include_hashcat: bool = True) -> Optional[str]:
    for pattern in PASSWORD_PATTERNS:
        match = pattern.search(output)
        if match:
            password = match.group(1).strip()
            if is_valid_wifi_password(password):
                return password

    if include_hashcat:
        password = _extract_hashcat_password(output)
        if password:
            return password

    return _extract_context_password(output.splitlines())


def extract_hashcat_password_for_bssid(output: str, bssid: str) -> Optional[str]:
    bssid_plain = bssid.replace(":", "").lower()
    for line in output.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if not stripped or (bssid.lower() not in lower and bssid_plain not in lower):
            continue
        password = _extract_hashcat_line_password(stripped)
        if is_valid_wifi_password(password):
            return password
    return None


def _extract_hashcat_line_password(line: str) -> str:
    """Extract password from hashcat line while keeping ':' inside password."""
    if ":" not in line:
        return ""

    # Hashcat often emits:
    # - 3-field: <bssid_plain>:<handshake_or_client>:<password>
    # - 4-field: <bssid_plain>:<client_or_hash>:<essid>:<password>
    # Password may itself contain ':', so limit splitting.
    parts = line.split(":", 3)
    if len(parts) >= 4:
        return parts[3].strip()
    if len(parts) == 3:
        return parts[2].strip()
    return ""


def is_valid_wifi_password(password: str) -> bool:
    if not password or len(password) < 8 or len(password) > 63:
        return False

    lower = password.lower()
    invalid_markers = (
        "second",
        "minute",
        "hour",
        "progress",
        "remaining",
        "tested",
        "decrypting",
        "master",
    )
    if any(marker in lower for marker in invalid_markers):
        return False

    if re.search(r"\d+\s*(?:second|minute|hour)", password, re.IGNORECASE):
        return False
    if re.search(r"\d+[:.]\d+[:.]\d+", password):
        return False
    if re.search(r"\d+\.\d+%", password):
        return False
    if re.search(r"\[.*\d+[\.:]\d+.*\]", password):
        return False

    return True


def _extract_hashcat_password(output: str) -> Optional[str]:
    hash_target_match = re.search(r"Hash\.Target\.+:\s*(.+?):(.+)$", output, re.MULTILINE)
    if hash_target_match:
        password = hash_target_match.group(2).strip()
        if is_valid_wifi_password(password):
            return password

    if "Status" in output and "Cracked" in output:
        for line in output.splitlines():
            if ":" not in line:
                continue
            password = line.split(":")[-1].strip()
            if is_valid_wifi_password(password):
                return password

    return None


def _extract_context_password(lines: Sequence[str]) -> Optional[str]:
    for i, line in enumerate(lines):
        if not any(marker in line for marker in ("KEY FOUND", "FOUND KEY", "Cracked")):
            continue

        for next_line in lines[i : i + 5]:
            colon_parts = next_line.split(":")
            if len(colon_parts) >= 2 and not any(x in next_line for x in ("BSSID", "Index", "second", "%")):
                password = colon_parts[-1].strip()
                if is_valid_wifi_password(password):
                    return password

    full_output = "\n".join(lines)
    bracket_matches = re.findall(r"\[\s*([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>/?]{8,63})\s*\]", full_output)
    for password in bracket_matches:
        if is_valid_wifi_password(password):
            return password

    return None


def _looks_like_mac(value: str) -> bool:
    return bool(re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", value))
