"""Client profiling helpers for observed Wi-Fi stations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


DEFAULT_OUI_MAP = {
    "001A11": "Google",
    "3C5A37": "Google",
    "F4F5D8": "Google",
    "001B63": "Apple",
    "3C0754": "Apple",
    "A4C361": "Apple",
    "D850E6": "Apple",
    "001DD8": "Microsoft",
    "7C1E52": "Microsoft",
    "001A79": "Samsung",
    "5C0A5B": "Samsung",
    "B827EB": "Raspberry Pi",
}


@dataclass(frozen=True)
class ClientProfile:
    mac: str
    vendor: str
    associated_networks: tuple[str, ...]
    associated_bssids: tuple[str, ...]
    association_count: int
    best_signal: int
    target_score: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def vendor_from_mac(mac: str, oui_map: dict[str, str] | None = None) -> str:
    oui_map = oui_map or DEFAULT_OUI_MAP
    plain = "".join(ch for ch in str(mac).upper() if ch in "0123456789ABCDEF")
    if len(plain) < 6:
        return "Unknown"
    return oui_map.get(plain[:6], "Unknown")


def build_client_profiles(
    networks: dict[str, dict[str, Any]],
    *,
    oui_map: dict[str, str] | None = None,
) -> list[ClientProfile]:
    grouped: dict[str, dict[str, Any]] = {}
    for bssid, network in networks.items():
        clients = network.get("clients", []) or []
        for client in clients:
            mac = _norm_mac(client)
            if not mac:
                continue
            entry = grouped.setdefault(
                mac,
                {
                    "networks": set(),
                    "bssids": set(),
                    "best_signal": -100,
                    "client_hits": 0,
                },
            )
            entry["networks"].add(str(network.get("ssid", "Unknown")))
            entry["bssids"].add(str(bssid))
            entry["best_signal"] = max(entry["best_signal"], _safe_int(network.get("signal", -100), -100))
            entry["client_hits"] += 1

    profiles = []
    for mac, data in grouped.items():
        association_count = len(data["bssids"])
        best_signal = int(data["best_signal"])
        signal_score = max(0.0, min(1.0, (100 + best_signal) / 70.0))
        target_score = round((association_count * 2.0) + signal_score + (data["client_hits"] * 0.25), 2)
        profiles.append(
            ClientProfile(
                mac=mac,
                vendor=vendor_from_mac(mac, oui_map),
                associated_networks=tuple(sorted(data["networks"])),
                associated_bssids=tuple(sorted(data["bssids"])),
                association_count=association_count,
                best_signal=best_signal,
                target_score=target_score,
            )
        )
    return sorted(profiles, key=lambda profile: (-profile.target_score, profile.mac))


def _safe_int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _norm_mac(value: object) -> str:
    mac = str(value or "").strip().lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) == 6 and all(len(part) == 2 for part in parts):
        return mac
    return ""
