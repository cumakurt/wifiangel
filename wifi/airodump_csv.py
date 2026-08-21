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
    if lines and lines[-1].count(",") < 3:
        lines = lines[:-1]
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
        privacy_tokens = {token for token in privacy.upper().replace("/", " ").split() if token}
        wps = "WPS" in privacy_tokens

    data_packets = _int_field(
        _col_match(ap, "#", "data") or _col_match(ap, "data") or _col_match(ap, "#", "iv") or _col_match(ap, "iv") or "",
        0,
    )

    return {
        "bssid": bssid,
        "ssid": essid,
        "channel": channel,
        "signal": power,
        "cipher": cipher_str,
        "beacons": beacons,
        "wps": wps,
        "data_packets": data_packets,
    }


def station_client_counts(stations: list[dict[str, str]]) -> dict[str, set[str]]:
    """BSSID -> set of associated station MACs."""
    return {bssid: set(macs) for bssid, macs in station_client_signals(stations).items()}


def station_client_signals(stations: list[dict[str, str]]) -> dict[str, dict[str, int]]:
    """BSSID -> {station MAC: last observed power}."""
    out: dict[str, dict[str, int]] = {}
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
        power = _int_field(_col_match(s, "power") or s.get("Power", ""), -100)
        out.setdefault(ap, {})[smac] = power
    return out


def probed_essids_by_bssid(stations: list[dict[str, str]]) -> dict[str, set[str]]:
    """
    BSSID -> unique non-empty probe SSIDs from airodump-ng station rows.

    Same CSV export as parse_airodump_csv(); associates probes only with the
    station row's BSSID (not broadcast to unrelated APs).
    """
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
        bssid_raw = (s.get("BSSID", "") or "").strip()
        if not bssid_raw or "not associated" in bssid_raw.lower():
            continue
        ap = _norm_mac(bssid_raw)
        if not ap:
            continue
        probed = _col_match(s, "probed", "essid") or (s.get("Probed ESSIDs", "") or "").strip()
        names = parse_probed_essid_field(probed)
        if not names:
            continue
        out.setdefault(ap, set()).update(names)
    return out


def parse_probed_essid_field(value: str) -> tuple[str, ...]:
    """Split an airodump-ng Probed ESSIDs cell into unique names."""
    names: list[str] = []
    seen: set[str] = set()
    for part in str(value or "").replace(";", ",").split(","):
        name = part.strip().strip('"').strip("'")
        if not name or name.lower() in {"<hidden network>", "(not associated)"}:
            continue
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
    return tuple(names)


def station_probe_rows(stations: list[dict[str, str]]) -> list[tuple[str, str | None, tuple[str, ...]]]:
    """Return (station_mac, associated_bssid_or_none, probed_ssids) for each station."""
    rows: list[tuple[str, str | None, tuple[str, ...]]] = []
    for station in stations:
        station_mac = ""
        for key, val in station.items():
            kl = key.lower()
            if "station" in kl and "mac" in kl:
                station_mac = _norm_mac(val)
                break
        if not station_mac:
            continue
        names = parse_probed_essid_field(
            _col_match(station, "probed", "essid") or (station.get("Probed ESSIDs", "") or "")
        )
        if not names:
            continue
        bssid_raw = (station.get("BSSID", "") or "").strip()
        associated = None
        if bssid_raw and "not associated" not in bssid_raw.lower():
            associated = _norm_mac(bssid_raw) or None
        rows.append((station_mac, associated, names))
    return rows
