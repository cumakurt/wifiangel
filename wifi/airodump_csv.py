"""Parse airodump-ng CSV exports for network discovery."""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Any


def _norm_mac(mac: str) -> str:
    m = (mac or "").strip().lower().replace("-", ":")
    if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", m):
        return m
    return ""


def _int_field(val: str, default: int = 0) -> int:
    try:
        s = (val or "").strip()
        if not s or s == "-1":
            return default
        return int(float(s))
    except (TypeError, ValueError):
        return default


def _row_dict(raw_row: dict[str, str | None]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in raw_row.items():
        if k is None:
            continue
        key = k.strip()
        if not key:
            continue
        out[key] = (v or "").strip()
    return out


def parse_airodump_csv(path: Path) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """
    Read airodump-ng -w ... --output-format csv (-01.csv) file.

    Returns (access_points, stations).
    """
    if not path.is_file():
        return [], []

    raw_text = path.read_text(encoding="utf-8", errors="replace")
    lines = raw_text.splitlines()
    ap_header_idx = None
    sta_header_idx = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("BSSID") and "ESSID" in stripped:
            ap_header_idx = i
        if stripped.startswith("Station MAC"):
            sta_header_idx = i
            break

    aps: list[dict[str, str]] = []
    stas: list[dict[str, str]] = []

    if ap_header_idx is not None:
        end = sta_header_idx if sta_header_idx is not None else len(lines)
        ap_block = "\n".join(lines[ap_header_idx:end])
        reader = csv.DictReader(io.StringIO(ap_block))
        for raw_row in reader:
            row = _row_dict(raw_row)
            bssid = _norm_mac(row.get("BSSID", ""))
            if not bssid:
                continue
            aps.append(row)

    if sta_header_idx is not None:
        sta_block = "\n".join(lines[sta_header_idx:])
        reader = csv.DictReader(io.StringIO(sta_block))
        for raw_row in reader:
            row = _row_dict(raw_row)
            smac = ""
            for key, val in row.items():
                kl = key.lower()
                if "station" in kl and "mac" in kl:
                    smac = _norm_mac(val)
                    break
            if not smac:
                continue
            stas.append(row)

    return aps, stas


def _col_match(row: dict[str, str], *needles: str) -> str:
    """Return value for first column whose name contains all needles (case-insensitive)."""
    for key, val in row.items():
        k = key.lower()
        if all(n.lower() in k for n in needles):
            return val.strip()
    return ""


def ap_row_to_network_fields(ap: dict[str, str]) -> dict[str, Any] | None:
    """Map airodump AP CSV row to WiFiAngel network dict fields (no clients)."""
    bssid = _norm_mac(ap.get("BSSID", ""))
    if not bssid:
        return None

    essid = (ap.get("ESSID", "") or "").strip() or _col_match(ap, "essid")
    if not essid:
        essid = "<Hidden Network>"

    channel = _int_field(_col_match(ap, "channel") or ap.get("channel", ""), 0)
    power = _int_field(_col_match(ap, "power") or ap.get("Power", ""), -100)
    beacons = _int_field(_col_match(ap, "beacon") or "", 0)
    if beacons <= 0:
        beacons = 1

    privacy = (_col_match(ap, "privacy") or ap.get("Privacy", "")).strip()
    cipher = (_col_match(ap, "cipher") or ap.get("Cipher", "")).strip()
    auth = (_col_match(ap, "authentication") or ap.get("Authentication", "")).strip()
    cipher_parts = [p for p in (privacy, cipher, auth) if p]
    cipher_str = "/".join(cipher_parts) if cipher_parts else "OPEN"

    wps = False
    for col, val in ap.items():
        if "wps" in col.lower() and val and str(val).strip().upper() not in ("0", "NO", "N", ""):
            wps = True
            break
    if not wps:
        blob = " ".join(ap.values()).upper()
        if "WPS" in blob and "NO WPS" not in blob:
            wps = True

    return {
        "bssid": bssid,
        "ssid": essid,
        "channel": channel,
        "signal": power,
        "cipher": cipher_str,
        "beacons": beacons,
        "wps": wps,
    }


def station_client_counts(stations: list[dict[str, str]]) -> dict[str, set[str]]:
    """BSSID -> set of associated station MACs."""
    out: dict[str, set[str]] = {}
    for s in stations:
        smac = ""
        for key, val in s.items():
            kl = key.lower()
            if "station" in kl and "mac" in kl:
                smac = _norm_mac(val)
                break
        if not smac:
            continue
        bssid_raw = s.get("BSSID", "").strip()
        if not bssid_raw or "not associated" in bssid_raw.lower():
            continue
        ap = _norm_mac(bssid_raw)
        if not ap:
            continue
        out.setdefault(ap, set()).add(smac)
    return out
