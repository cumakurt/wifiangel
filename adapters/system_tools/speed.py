"""Helpers for network speed test commands and calculations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


DOWNLOAD_TEST_BYTES = 100_000_000
UPLOAD_TEST_BYTES = 500_000
DEFAULT_PING_HOST = "8.8.8.8"
DOWNLOAD_URL_TEMPLATE = "https://speed.cloudflare.com/__down?bytes={bytes}"
UPLOAD_URL = "https://tmpfiles.org/api/v1/upload"


@dataclass(frozen=True)
class PingStats:
    raw: str
    minimum_ms: float
    average_ms: float
    maximum_ms: float
    deviation_ms: Optional[float] = None


def ping_command(
    *,
    count: int,
    host: str = DEFAULT_PING_HOST,
    timeout_seconds: Optional[int] = None,
    quiet: bool = False,
) -> List[str]:
    command = ["ping", "-c", str(count)]
    if timeout_seconds is not None:
        command.extend(["-W", str(timeout_seconds)])
    if quiet:
        command.append("-q")
    command.append(host)
    return command


def curl_download_command(byte_count: int = DOWNLOAD_TEST_BYTES) -> List[str]:
    return [
        "curl",
        "-s",
        "-o",
        "/dev/null",
        DOWNLOAD_URL_TEMPLATE.format(bytes=byte_count),
    ]


def curl_upload_command(file_path: str, url: str = UPLOAD_URL) -> List[str]:
    return [
        "curl",
        "-s",
        "--connect-timeout",
        "3",
        "--max-time",
        "5",
        "-F",
        f"file=@{file_path}",
        url,
    ]


def bytes_to_mbytes_per_second(byte_count: int, elapsed_seconds: float) -> float:
    if elapsed_seconds <= 0 or byte_count <= 0:
        return 0.0
    return byte_count / elapsed_seconds / (1024 * 1024)


def estimate_upload_mbytes_per_second(
    byte_count: int,
    elapsed_seconds: float,
    *,
    multiplier: float = 2.5,
) -> float:
    return bytes_to_mbytes_per_second(byte_count, elapsed_seconds) * multiplier


def fallback_upload_mbytes_per_second(
    download_mbytes_per_second: float,
    *,
    ratio: float = 0.3,
    default_mbytes_per_second: float = 1.5,
) -> float:
    if download_mbytes_per_second > 0:
        return download_mbytes_per_second * ratio
    return default_mbytes_per_second


def mbytes_to_mbits(mbytes_per_second: float) -> float:
    return max(mbytes_per_second, 0.0) * 8


def parse_ping_stats(output: str) -> Optional[PingStats]:
    for line in output.splitlines():
        if "min/avg/max" not in line or "=" not in line:
            continue

        stats = line.split("=", 1)[1].replace("ms", "").strip()
        parts = [part.strip() for part in stats.split("/") if part.strip()]
        if len(parts) < 3:
            return None

        try:
            values = [float(part) for part in parts[:4]]
        except ValueError:
            return None

        deviation = values[3] if len(values) > 3 else None
        return PingStats(
            raw="/".join(parts),
            minimum_ms=values[0],
            average_ms=values[1],
            maximum_ms=values[2],
            deviation_ms=deviation,
        )

    return None


def speed_gauge_blocks(mbps: float, scale_mbps: float, *, width: int = 10) -> int:
    if mbps <= 0 or scale_mbps <= 0 or width <= 0:
        return 0
    return min(int((mbps / scale_mbps) * width), width)


def download_speed_rating(mbps: float) -> str:
    if mbps < 5:
        return "[red]Very Slow[/]"
    if mbps < 20:
        return "[yellow]Slow[/]"
    if mbps < 50:
        return "[yellow]Average[/]"
    if mbps < 100:
        return "[green]Good[/]"
    return "[bold green]Excellent[/]"


def upload_speed_rating(mbps: float) -> str:
    if mbps < 1:
        return "[red]Very Slow[/]"
    if mbps < 5:
        return "[yellow]Slow[/]"
    if mbps < 20:
        return "[yellow]Average[/]"
    if mbps < 50:
        return "[green]Good[/]"
    return "[bold green]Excellent[/]"


def build_speed_recommendations(
    download_mbps: float,
    upload_mbps: float,
    ping_average_ms: Optional[float],
) -> List[str]:
    recommendations = []

    if download_mbps < 10:
        recommendations.append(
            "Your download speed is slow. This may impact streaming and browsing."
        )

    if upload_mbps < 3:
        recommendations.append(
            "Your upload speed is slow. This may impact video conferencing and file uploads."
        )

    if ping_average_ms is not None and ping_average_ms > 100:
        recommendations.append(
            "Your ping is high. This may cause lag in online gaming and video calls."
        )

    return recommendations
