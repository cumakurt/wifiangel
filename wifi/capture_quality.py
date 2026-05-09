"""Capture quality scoring and EAPOL replay validation."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from wifi.frame_intelligence import classify_dot11_packet


@dataclass(frozen=True)
class EapolKeyFrame:
    message: str
    replay_counter: int
    src: str
    dst: str
    bssid: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CaptureQualityReport:
    path: str
    score: int
    verdict: str
    format: str
    frame_counts: dict[str, int]
    eapol_messages: dict[str, int]
    replay_pairs: int
    pmkid_records: int
    eapol_hash_records: int
    bssid_matched: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def analyze_capture_quality(path: Path, *, bssid: str | None = None, essid: str | None = None) -> CaptureQualityReport:
    """Score a capture or hash file for offline WPA/WPA2/WPA3 validation."""
    suffix = path.suffix.lower()
    if suffix in {".22000", ".16800", ".hash", ".hc22000"}:
        return _analyze_hash_file(path, bssid=bssid, essid=essid)
    return _analyze_pcap_file(path, bssid=bssid)


def parse_eapol_key_frame(raw: bytes, *, src: str = "", dst: str = "", bssid: str = "") -> Optional[EapolKeyFrame]:
    """Parse enough EAPOL-Key data to classify message order and replay counters."""
    if len(raw) < 17:
        return None
    try:
        key_info = int.from_bytes(raw[5:7], "big")
        replay_counter = int.from_bytes(raw[9:17], "big")
    except Exception:
        return None

    ack = bool(key_info & (1 << 7))
    mic = bool(key_info & (1 << 8))
    secure = bool(key_info & (1 << 9))

    if ack and not mic:
        message = "M1"
    elif not ack and mic and not secure:
        message = "M2"
    elif ack and mic:
        message = "M3"
    elif not ack and mic and secure:
        message = "M4"
    else:
        message = "EAPOL-Key"

    return EapolKeyFrame(
        message=message,
        replay_counter=replay_counter,
        src=src,
        dst=dst,
        bssid=bssid,
    )


def _analyze_hash_file(path: Path, *, bssid: str | None, essid: str | None) -> CaptureQualityReport:
    reasons: list[str] = []
    pmkid_records = 0
    eapol_records = 0
    bssid_matched = False
    expected_bssid = _plain_bssid(bssid)
    expected_essid_hex = essid.encode("utf-8").hex().lower() if essid else ""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return _empty_report(path, "hash", f"Could not read file: {exc}")

    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("WPA*"):
            continue
        fields = stripped.split("*")
        if len(fields) < 5:
            continue
        if fields[1] == "01":
            pmkid_records += 1
        elif fields[1] == "02":
            eapol_records += 1
        if expected_bssid and any(field.lower() == expected_bssid for field in fields):
            bssid_matched = True
        if expected_essid_hex and any(field.lower() == expected_essid_hex for field in fields):
            reasons.append("ESSID matches hash record")

    score = 0
    if pmkid_records or eapol_records:
        score += 65
        reasons.append("Hashcat WPA record detected")
    if pmkid_records:
        score += 15
        reasons.append("PMKID record is present")
    if eapol_records:
        score += 15
        reasons.append("EAPOL hash record is present")
    if expected_bssid:
        if bssid_matched:
            score += 5
            reasons.append("BSSID matches expected target")
        else:
            score -= 15
            reasons.append("Expected BSSID was not found in hash records")

    return CaptureQualityReport(
        path=str(path),
        score=_clamp_score(score),
        verdict=_verdict(score),
        format="hashcat-22000",
        frame_counts={},
        eapol_messages={},
        replay_pairs=0,
        pmkid_records=pmkid_records,
        eapol_hash_records=eapol_records,
        bssid_matched=bssid_matched if expected_bssid else False,
        reasons=tuple(reasons or ["No valid WPA hash records found"]),
    )


def _analyze_pcap_file(path: Path, *, bssid: str | None) -> CaptureQualityReport:
    reasons: list[str] = []
    frame_counts: Counter[str] = Counter()
    eapol_messages: Counter[str] = Counter()
    replay_by_counter: dict[int, set[str]] = defaultdict(set)
    bssid_norm = _norm_mac(bssid)
    bssid_matched = False

    try:
        from scapy.all import PcapNgReader, PcapReader
    except Exception as exc:
        return _empty_report(path, "pcap", f"Scapy is required for pcap analysis: {exc}")

    try:
        reader_cls = PcapNgReader if path.suffix.lower() == ".pcapng" else PcapReader
        with reader_cls(str(path)) as reader:
            for pkt in reader:
                frame_type = classify_dot11_packet(pkt)
                frame_counts[frame_type] += 1
                dot11 = _get_layer(pkt, "Dot11")
                src = _norm_mac(getattr(dot11, "addr2", "")) if dot11 else ""
                dst = _norm_mac(getattr(dot11, "addr1", "")) if dot11 else ""
                pkt_bssid = _select_bssid(dot11)
                if bssid_norm and pkt_bssid == bssid_norm:
                    bssid_matched = True
                if frame_type != "eapol":
                    continue
                eapol = _get_layer(pkt, "EAPOL")
                key_frame = parse_eapol_key_frame(bytes(eapol), src=src, dst=dst, bssid=pkt_bssid) if eapol else None
                if key_frame:
                    eapol_messages[key_frame.message] += 1
                    replay_by_counter[key_frame.replay_counter].add(key_frame.message)
    except OSError as exc:
        return _empty_report(path, "pcap", f"Could not read pcap: {exc}")
    except Exception as exc:
        return _empty_report(path, "pcap", f"Could not parse pcap: {exc}")

    replay_pairs = sum(1 for messages in replay_by_counter.values() if {"M1", "M2"} <= messages or {"M2", "M3"} <= messages)
    score = 0
    if sum(frame_counts.values()) > 0:
        score += 15
        reasons.append("Capture file is readable")
    if frame_counts.get("beacon", 0) or frame_counts.get("probe_resp", 0):
        score += 10
        reasons.append("Beacon or probe response context is present")
    if frame_counts.get("eapol", 0):
        score += 20
        reasons.append("EAPOL frames are present")
    if len(eapol_messages) >= 2:
        score += 15
        reasons.append("Multiple EAPOL message types observed")
    if replay_pairs:
        score += 25
        reasons.append("Replay counter pairing indicates a crackable exchange")
    if {"M1", "M2"} <= set(eapol_messages) or {"M2", "M3"} <= set(eapol_messages):
        score += 10
        reasons.append("Useful EAPOL message pair found")
    if bssid_norm:
        if bssid_matched:
            score += 5
            reasons.append("BSSID matches expected target")
        else:
            score -= 15
            reasons.append("Expected BSSID was not observed")

    return CaptureQualityReport(
        path=str(path),
        score=_clamp_score(score),
        verdict=_verdict(score),
        format="pcap",
        frame_counts=dict(frame_counts),
        eapol_messages=dict(eapol_messages),
        replay_pairs=replay_pairs,
        pmkid_records=0,
        eapol_hash_records=0,
        bssid_matched=bssid_matched if bssid_norm else False,
        reasons=tuple(reasons or ["No useful WPA capture material found"]),
    )


def _empty_report(path: Path, fmt: str, reason: str) -> CaptureQualityReport:
    return CaptureQualityReport(
        path=str(path),
        score=0,
        verdict="unusable",
        format=fmt,
        frame_counts={},
        eapol_messages={},
        replay_pairs=0,
        pmkid_records=0,
        eapol_hash_records=0,
        bssid_matched=False,
        reasons=(reason,),
    )


def _verdict(score: int) -> str:
    score = _clamp_score(score)
    if score >= 80:
        return "crackable"
    if score >= 50:
        return "partial"
    if score >= 20:
        return "weak"
    return "unusable"


def _clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))


def _get_layer(pkt: Any, layer_name: str):
    try:
        return pkt.getlayer(layer_name)
    except Exception:
        return None


def _select_bssid(dot11: Any) -> str:
    if dot11 is None:
        return ""
    for attr in ("addr3", "addr2", "addr1"):
        mac = _norm_mac(getattr(dot11, attr, ""))
        if mac and mac not in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
            return mac
    return ""


def _plain_bssid(value: str | None) -> str:
    return _norm_mac(value).replace(":", "")


def _norm_mac(value: object) -> str:
    mac = str(value or "").strip().lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) == 6 and all(len(part) == 2 for part in parts):
        return mac
    plain = mac.replace(":", "")
    if len(plain) == 12 and all(ch in "0123456789abcdef" for ch in plain):
        return ":".join(plain[i : i + 2] for i in range(0, 12, 2))
    return ""
