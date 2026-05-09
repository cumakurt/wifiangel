"""Live packet-rate telemetry primitives."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

from wifi.frame_intelligence import classify_dot11_packet


@dataclass(frozen=True)
class PacketRateSnapshot:
    elapsed_seconds: float
    total_packets: int
    rates_per_second: dict[str, float]
    counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PacketRateCounter:
    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.total_packets = 0

    def observe_packet(self, pkt: Any) -> str:
        frame_type = classify_dot11_packet(pkt)
        self.counts[frame_type] += 1
        self.total_packets += 1
        return frame_type

    def snapshot(self, elapsed_seconds: float) -> PacketRateSnapshot:
        elapsed = max(float(elapsed_seconds), 0.001)
        return PacketRateSnapshot(
            elapsed_seconds=round(elapsed, 3),
            total_packets=self.total_packets,
            rates_per_second={
                frame_type: round(count / elapsed, 2)
                for frame_type, count in sorted(self.counts.items())
            },
            counts=dict(sorted(self.counts.items())),
        )
