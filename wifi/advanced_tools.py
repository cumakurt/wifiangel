"""Advanced analysis helpers for the Tools section."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from pathlib import Path
from typing import Any

from adapters.system_tools import CommandRunner
from wifi.capture_quality import analyze_capture_quality
from wifi.channel_hopper import ChannelPlanEntry, build_adaptive_channel_plan
from wifi.client_profiler import vendor_from_mac


_WORDLIST_SUFFIXES = ("", "123", "1234", "2024", "2025", "2026", "!", "@123")


@dataclass(frozen=True)
class RfChannelInsight:
    channel: int
    ap_count: int
    avg_signal: int
    overlap_ap_count: int
    noise_score: float
    interference: str


@dataclass(frozen=True)
class RfEnvironmentReport:
    channels: tuple[RfChannelInsight, ...]
    best_attack_channels: tuple[int, ...]


@dataclass(frozen=True)
class HandshakeValidationReport:
    path: str
    quality_score: int
    quality_verdict: str
    bssid_matched: bool
    aircrack_result: str
    hcx_result: str
    verdict: str
    notes: tuple[str, ...]


@dataclass(frozen=True)
class WordlistSuggestion:
    value: str
    source: str
    score: int


@dataclass(frozen=True)
class CaptureHealthReport:
    path: str
    format: str
    total_records: int
    valid_records: int
    duplicate_records: int
    corrupted_records: int
    verdict: str
    notes: tuple[str, ...]


@dataclass(frozen=True)
class WpsRiskReport:
    ssid: str
    bssid: str
    lock_state: str
    rate_limit_hint: str
    success_window: str
    risk_score: int
    recommendation: str


@dataclass(frozen=True)
class HopperOptimization:
    channel: int
    dwell_ms: int
    hop_interval_ms: int
    reason: str
    score: float


def analyze_rf_environment(networks: dict[str, dict[str, Any]]) -> RfEnvironmentReport:
    stats: dict[int, dict[str, float]] = {}
    for network in networks.values():
        channel = _safe_int(network.get("channel"), 0)
        if channel <= 0:
            continue
        signal = _safe_int(network.get("signal"), -100)
        entry = stats.setdefault(channel, {"ap_count": 0.0, "signal_total": 0.0, "overlap": 0.0})
        entry["ap_count"] += 1
        entry["signal_total"] += signal

    channels = sorted(stats.keys())
    for channel in channels:
        overlap = 0.0
        for other in channels:
            if other == channel:
                continue
            distance = abs(other - channel)
            if channel <= 14 and other <= 14 and distance <= 2:
                overlap += max(0.1, 1.0 - (distance * 0.35)) * stats[other]["ap_count"]
            elif channel > 14 and other > 14 and distance <= 8:
                overlap += max(0.05, 1.0 - (distance * 0.08)) * stats[other]["ap_count"]
        stats[channel]["overlap"] = overlap

    insights: list[RfChannelInsight] = []
    for channel in channels:
        data = stats[channel]
        ap_count = int(data["ap_count"])
        avg_signal = int(data["signal_total"] / max(1, ap_count))
        signal_pressure = min(4.0, max(0.0, (100 + avg_signal) / 30.0))
        noise_score = round((ap_count * 0.8) + data["overlap"] + signal_pressure, 2)
        interference = "high" if noise_score >= 5.5 else "medium" if noise_score >= 3.0 else "low"
        insights.append(
            RfChannelInsight(
                channel=channel,
                ap_count=ap_count,
                avg_signal=avg_signal,
                overlap_ap_count=int(round(data["overlap"])),
                noise_score=noise_score,
                interference=interference,
            )
        )

    best_channels = tuple(item.channel for item in sorted(insights, key=lambda i: (i.noise_score, i.channel))[:5])
    return RfEnvironmentReport(channels=tuple(insights), best_attack_channels=best_channels)


def validate_handshake_pmkid(
    path: Path,
    *,
    expected_bssid: str | None,
    command_runner: CommandRunner,
) -> HandshakeValidationReport:
    quality = analyze_capture_quality(path, bssid=expected_bssid)
    notes: list[str] = list(quality.reasons)

    aircrack_result = "not-run"
    if command_runner.which("aircrack-ng"):
        result = command_runner.run(["aircrack-ng", str(path)], capture_output=True)
        out = f"{result.stdout}\n{result.stderr}".lower()
        if "1 handshake" in out or "handshake" in out:
            aircrack_result = "valid"
            notes.append("aircrack-ng detected handshake material")
        elif result.ok:
            aircrack_result = "no-handshake"
            notes.append("aircrack-ng did not report crackable handshake")
        else:
            aircrack_result = "error"
            notes.append("aircrack-ng execution failed")
    else:
        notes.append("aircrack-ng is not installed")

    hcx_result = "not-run"
    if command_runner.which("hcxhashtool"):
        result = command_runner.run(["hcxhashtool", "-i", str(path)], capture_output=True)
        out = f"{result.stdout}\n{result.stderr}".lower()
        if "pmkid" in out or "eapol" in out:
            hcx_result = "valid"
            notes.append("hcxhashtool found PMKID/EAPOL records")
        elif result.ok:
            hcx_result = "empty"
            notes.append("hcxhashtool did not find usable records")
        else:
            hcx_result = "error"
            notes.append("hcxhashtool execution failed")
    else:
        notes.append("hcxhashtool is not installed")

    external_valid = aircrack_result == "valid" or hcx_result == "valid"
    verdict = "valid" if quality.score >= 70 and (external_valid or (aircrack_result == "not-run" and hcx_result == "not-run")) else "suspect"
    return HandshakeValidationReport(
        path=str(path),
        quality_score=quality.score,
        quality_verdict=quality.verdict,
        bssid_matched=quality.bssid_matched,
        aircrack_result=aircrack_result,
        hcx_result=hcx_result,
        verdict=verdict,
        notes=tuple(dict.fromkeys(notes)),
    )


def build_wordlist_intelligence(
    *,
    ssid: str,
    bssid: str = "",
    extra_keywords: list[str] | None = None,
    max_words: int = 200,
) -> tuple[WordlistSuggestion, ...]:
    vendor = vendor_from_mac(bssid) if bssid else "Unknown"
    base_tokens = _tokenize(ssid) + _tokenize(vendor)
    extra = extra_keywords or []
    base_tokens.extend(token for token in (_tokenize(" ".join(extra))) if token)
    base_tokens.extend(str(datetime.now().year + delta) for delta in (-1, 0, 1))
    base_tokens = [token for token in dict.fromkeys(base_tokens) if len(token) >= 3]

    suggestions: list[WordlistSuggestion] = []
    for token in base_tokens:
        token_score = 30 if token.isdigit() else 45
        suggestions.append(WordlistSuggestion(value=token, source="base-token", score=token_score))
        for suffix in _WORDLIST_SUFFIXES:
            candidate = f"{token}{suffix}"
            suggestions.append(
                WordlistSuggestion(
                    value=candidate,
                    source="token-mutation",
                    score=token_score + (15 if suffix else 0),
                )
            )
            if len(token) >= 4:
                suggestions.append(
                    WordlistSuggestion(
                        value=f"{token.capitalize()}{suffix}",
                        source="case-variant",
                        score=token_score + 10,
                    )
                )

    ranked: dict[str, WordlistSuggestion] = {}
    for item in suggestions:
        existing = ranked.get(item.value)
        if existing is None or item.score > existing.score:
            ranked[item.value] = item
    ordered = sorted(ranked.values(), key=lambda item: (-item.score, len(item.value), item.value))
    return tuple(ordered[:max_words])


def check_capture_health(path: Path) -> CaptureHealthReport:
    suffix = path.suffix.lower()
    if suffix in {".22000", ".16800", ".hash", ".hc22000"}:
        return _check_hash_health(path)
    return _check_pcap_health(path)


def analyze_wps_risk(network: dict[str, Any], *, lock_state: str = "unknown", rate_limit_hint: str = "unknown") -> WpsRiskReport:
    ssid = str(network.get("ssid", "<Hidden>"))
    bssid = str(network.get("bssid", ""))
    signal = _safe_int(network.get("signal"), -100)
    clients = len(network.get("clients", []) or [])
    cipher = str(network.get("cipher", "")).upper()
    wps_enabled = bool(network.get("wps"))

    score = 0
    if wps_enabled:
        score += 55
    if lock_state.lower() in {"unlocked", "open", "no"}:
        score += 20
    elif lock_state.lower() in {"locked", "yes"}:
        score -= 20
    if signal >= -62:
        score += 15
    if clients >= 4:
        score += 10
    if "WPA3" in cipher:
        score -= 10

    score = max(0, min(100, score))
    if score >= 80:
        window = "high"
        recommendation = "Attempt Pixie first, then low-rate PIN cycle."
    elif score >= 55:
        window = "medium"
        recommendation = "Use cautious WPS attempts with lock monitoring."
    else:
        window = "low"
        recommendation = "Prefer non-WPS vectors; lock risk is high."

    return WpsRiskReport(
        ssid=ssid,
        bssid=bssid,
        lock_state=lock_state,
        rate_limit_hint=rate_limit_hint,
        success_window=window,
        risk_score=score,
        recommendation=recommendation,
    )


def optimize_channel_hopper(networks: dict[str, dict[str, Any]]) -> tuple[HopperOptimization, ...]:
    plan: list[ChannelPlanEntry] = build_adaptive_channel_plan(networks)
    if not plan:
        return ()
    peak = max(entry.score for entry in plan) or 1.0
    optimized: list[HopperOptimization] = []
    for entry in plan:
        ratio = entry.score / peak
        hop_interval_ms = int(max(150, min(2500, 220 + ((1.0 - ratio) * 1250))))
        optimized.append(
            HopperOptimization(
                channel=entry.channel,
                dwell_ms=entry.dwell_ms,
                hop_interval_ms=hop_interval_ms,
                reason=entry.reason,
                score=entry.score,
            )
        )
    return tuple(sorted(optimized, key=lambda item: (-item.score, item.channel)))


def _check_hash_health(path: Path) -> CaptureHealthReport:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return CaptureHealthReport(
            path=str(path),
            format="hash",
            total_records=0,
            valid_records=0,
            duplicate_records=0,
            corrupted_records=1,
            verdict="corrupt",
            notes=(f"Cannot read file: {exc}",),
        )

    seen: set[str] = set()
    valid = 0
    duplicates = 0
    corrupted = 0
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("WPA*"):
            corrupted += 1
            continue
        parts = line.split("*")
        if len(parts) < 5 or parts[1] not in {"01", "02"}:
            corrupted += 1
            continue
        valid += 1
        if line in seen:
            duplicates += 1
        seen.add(line)

    verdict = "healthy"
    notes = []
    if corrupted > 0:
        verdict = "warning"
        notes.append("Corrupted hash records detected")
    if duplicates > 0:
        notes.append("Duplicate hash records detected")
    if valid == 0:
        verdict = "corrupt"
        notes.append("No valid WPA hash records found")
    return CaptureHealthReport(
        path=str(path),
        format="hash",
        total_records=len([line for line in lines if line.strip()]),
        valid_records=valid,
        duplicate_records=duplicates,
        corrupted_records=corrupted,
        verdict=verdict,
        notes=tuple(notes or ["Hash file looks consistent"]),
    )


def _check_pcap_health(path: Path) -> CaptureHealthReport:
    try:
        from scapy.all import PcapNgReader, PcapReader
    except Exception as exc:
        return CaptureHealthReport(
            path=str(path),
            format="pcap",
            total_records=0,
            valid_records=0,
            duplicate_records=0,
            corrupted_records=1,
            verdict="warning",
            notes=(f"Scapy is required: {exc}",),
        )

    reader_cls = PcapNgReader if path.suffix.lower() == ".pcapng" else PcapReader
    total = 0
    corrupted = 0
    try:
        with reader_cls(str(path)) as reader:
            for pkt in reader:
                total += 1
                if pkt is None:
                    corrupted += 1
    except Exception as exc:
        return CaptureHealthReport(
            path=str(path),
            format="pcap",
            total_records=0,
            valid_records=0,
            duplicate_records=0,
            corrupted_records=1,
            verdict="corrupt",
            notes=(f"Could not parse pcap: {exc}",),
        )

    valid = max(0, total - corrupted)
    verdict = "healthy" if valid > 0 and corrupted == 0 else "warning" if valid > 0 else "corrupt"
    notes = ("Pcap parse completed",) if verdict != "corrupt" else ("No readable packets found",)
    return CaptureHealthReport(
        path=str(path),
        format="pcap",
        total_records=total,
        valid_records=valid,
        duplicate_records=0,
        corrupted_records=corrupted,
        verdict=verdict,
        notes=notes,
    )


def _tokenize(value: str) -> list[str]:
    tokens = [part.lower() for part in re.split(r"[^a-zA-Z0-9]+", value or "") if part]
    return [token for token in tokens if token not in {"wifi", "wlan", "network"}]


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
