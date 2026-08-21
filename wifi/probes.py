"""Preferred-network-list (probe SSID) helpers from airodump-ng station rows."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Sequence

from wifi.airodump_csv import station_probe_rows

_HIDDEN_LABELS = {"<hidden network>", "hidden", "any"}


@dataclass(frozen=True)
class ProbeSsidStat:
    ssid: str
    station_count: int
    associated_bssids: tuple[str, ...]

    @property
    def usable(self) -> bool:
        return usable_lab_ssid(self.ssid)


def usable_lab_ssid(ssid: str) -> bool:
    """True when the name is safe for hostapd (1-32 UTF-8 bytes, no line breaks)."""
    name = str(ssid or "").strip()
    if not name or "\n" in name or "\r" in name:
        return False
    if name.lower() in _HIDDEN_LABELS:
        return False
    return 1 <= len(name.encode("utf-8", errors="ignore")) <= 32


def summarize_probe_ssids(stations: list[dict[str, str]]) -> tuple[ProbeSsidStat, ...]:
    """Rank SSIDs by how many distinct stations listed them in Probed ESSIDs."""
    stations_by_ssid: dict[str, set[str]] = defaultdict(set)
    bssids_by_ssid: dict[str, set[str]] = defaultdict(set)
    for station_mac, associated, names in station_probe_rows(stations):
        for ssid in names:
            stations_by_ssid[ssid].add(station_mac)
            if associated:
                bssids_by_ssid[ssid].add(associated)
    stats = [
        ProbeSsidStat(
            ssid=ssid,
            station_count=len(macs),
            associated_bssids=tuple(sorted(bssids_by_ssid.get(ssid, ()))),
        )
        for ssid, macs in stations_by_ssid.items()
    ]
    stats.sort(key=lambda item: (-item.station_count, item.ssid.lower()))
    return tuple(stats)


def preferred_evil_twin_ssid(
    *,
    selected_ssid: str = "",
    probe_stats: Sequence[ProbeSsidStat] = (),
) -> tuple[str, str]:
    """Return (ssid, source) for the Evil Twin prompt.

    source is ``selected`` when the current target has a broadcast SSID,
    otherwise ``probe`` for the most-observed probe name, else empty.
    """
    selected = str(selected_ssid or "").strip()
    if usable_lab_ssid(selected):
        return selected, "selected"
    for stat in probe_stats:
        if stat.usable:
            return stat.ssid, "probe"
    return "", ""


def probe_stats_from_app(app) -> tuple[ProbeSsidStat, ...]:
    raw = getattr(app, "probe_ssids", ()) or ()
    if isinstance(raw, Sequence):
        return tuple(item for item in raw if isinstance(item, ProbeSsidStat))
    return ()
