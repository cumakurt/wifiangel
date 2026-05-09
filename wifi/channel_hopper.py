"""Adaptive channel hopping plan helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable

from config.defaults import CHANNELS_2GHZ_SCAN_ORDER, CHANNELS_5GHZ


@dataclass(frozen=True)
class ChannelPlanEntry:
    channel: int
    band: str
    score: float
    dwell_ms: int
    networks: int
    clients: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_adaptive_channel_plan(
    networks: dict[str, dict[str, Any]],
    *,
    include_5ghz: bool = True,
    min_dwell_ms: int = 250,
    max_dwell_ms: int = 3000,
) -> list[ChannelPlanEntry]:
    """Rank channels by observed value and assign dynamic dwell times."""
    channels: Iterable[int] = CHANNELS_2GHZ_SCAN_ORDER + (CHANNELS_5GHZ if include_5ghz else ())
    stats: dict[int, dict[str, Any]] = {
        int(channel): {"score": 0.05, "networks": 0, "clients": 0, "wps": 0, "strong": 0}
        for channel in channels
    }

    for network in networks.values():
        try:
            channel = int(network.get("channel", 0))
        except (TypeError, ValueError):
            continue
        if channel <= 0:
            continue
        stats.setdefault(channel, {"score": 0.05, "networks": 0, "clients": 0, "wps": 0, "strong": 0})
        clients = len(network.get("clients", []) or [])
        signal = _safe_int(network.get("signal", -100), -100)
        strength = max(0.0, min(1.0, (100 + signal) / 70.0))
        score = 1.0 + (clients * 2.5) + (strength * 2.0)
        if network.get("wps"):
            score += 0.75
            stats[channel]["wps"] += 1
        if signal >= -60:
            stats[channel]["strong"] += 1
        stats[channel]["score"] += score
        stats[channel]["networks"] += 1
        stats[channel]["clients"] += clients

        if channel <= 14:
            for adjacent in range(max(1, channel - 2), min(13, channel + 2) + 1):
                if adjacent == channel:
                    continue
                stats.setdefault(adjacent, {"score": 0.05, "networks": 0, "clients": 0, "wps": 0, "strong": 0})
                stats[adjacent]["score"] += score * 0.25

    entries = []
    for channel, data in stats.items():
        score = float(data["score"])
        dwell_ms = int(min(max_dwell_ms, max(min_dwell_ms, 250 + (score * 220))))
        reason_parts = []
        if data["clients"]:
            reason_parts.append(f"{data['clients']} client(s)")
        if data["strong"]:
            reason_parts.append(f"{data['strong']} strong AP(s)")
        if data["wps"]:
            reason_parts.append("WPS observed")
        if not reason_parts:
            reason_parts.append("baseline sweep")
        entries.append(
            ChannelPlanEntry(
                channel=channel,
                band="2.4GHz" if channel <= 14 else "5GHz",
                score=round(score, 2),
                dwell_ms=dwell_ms,
                networks=int(data["networks"]),
                clients=int(data["clients"]),
                reason=", ".join(reason_parts),
            )
        )

    return sorted(entries, key=lambda item: (-item.score, item.channel))


def _safe_int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
