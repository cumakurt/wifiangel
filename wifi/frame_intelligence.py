"""802.11 frame and RSN intelligence helpers."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


_CIPHER_NAMES = {
    0: "Use group cipher",
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP-128",
    5: "WEP-104",
    6: "BIP-CMAC-128",
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256",
}

_AKM_NAMES = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    8: "SAE",
    9: "FT-SAE",
    11: "802.1X-SUITE-B",
    12: "802.1X-SUITE-B-192",
    18: "OWE",
}

_MGMT_SUBTYPES = {
    0: "assoc_req",
    1: "assoc_resp",
    2: "reassoc_req",
    3: "reassoc_resp",
    4: "probe_req",
    5: "probe_resp",
    8: "beacon",
    10: "disassoc",
    11: "auth",
    12: "deauth",
    13: "action",
}


@dataclass(frozen=True)
class RsnProfile:
    version: int
    group_cipher: str
    pairwise_ciphers: tuple[str, ...]
    akm_suites: tuple[str, ...]
    pmf_capable: bool
    pmf_required: bool
    raw_capabilities: int

    @property
    def wpa3_capable(self) -> bool:
        return any(akm in {"SAE", "FT-SAE", "OWE"} for akm in self.akm_suites)

    @property
    def transition_mode(self) -> bool:
        return self.wpa3_capable and any(akm in {"PSK", "PSK-SHA256"} for akm in self.akm_suites)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FrameIntelligenceReport:
    total_frames: int
    frame_counts: dict[str, int]
    bssids: dict[str, int]
    ssids: dict[str, int]
    rsn_profiles: tuple[RsnProfile, ...]
    pmf_required_networks: int
    pmf_capable_networks: int
    wpa3_networks: int

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["rsn_profiles"] = [profile.to_dict() for profile in self.rsn_profiles]
        return data


def parse_rsn_information(info: bytes | bytearray | memoryview) -> Optional[RsnProfile]:
    """Parse an RSN information element payload."""
    data = bytes(info or b"")
    if len(data) < 8:
        return None

    try:
        offset = 0
        version = int.from_bytes(data[offset : offset + 2], "little")
        offset += 2

        group_cipher = _suite_name(data[offset : offset + 4], _CIPHER_NAMES, "cipher")
        offset += 4

        pairwise_count = int.from_bytes(data[offset : offset + 2], "little")
        offset += 2
        pairwise = []
        for _ in range(pairwise_count):
            pairwise.append(_suite_name(data[offset : offset + 4], _CIPHER_NAMES, "cipher"))
            offset += 4

        akm_count = int.from_bytes(data[offset : offset + 2], "little")
        offset += 2
        akms = []
        for _ in range(akm_count):
            akms.append(_suite_name(data[offset : offset + 4], _AKM_NAMES, "akm"))
            offset += 4

        capabilities = 0
        if offset + 2 <= len(data):
            capabilities = int.from_bytes(data[offset : offset + 2], "little")

        return RsnProfile(
            version=version,
            group_cipher=group_cipher,
            pairwise_ciphers=tuple(pairwise),
            akm_suites=tuple(akms),
            pmf_capable=bool(capabilities & (1 << 7)),
            pmf_required=bool(capabilities & (1 << 6)),
            raw_capabilities=capabilities,
        )
    except Exception:
        return None


def summarize_network_security(network: dict[str, Any]) -> dict[str, Any]:
    """Return PMF/WPA3 compatibility hints from a scan network dictionary."""
    cipher = str(network.get("cipher") or network.get("security") or "Unknown")
    cipher_upper = cipher.upper()
    wpa3 = "WPA3" in cipher_upper or "SAE" in cipher_upper or "OWE" in cipher_upper
    wpa2 = "WPA2" in cipher_upper or "PSK" in cipher_upper
    pmf_required = "PMF-REQUIRED" in cipher_upper or "MFPR" in cipher_upper
    pmf_capable = pmf_required or "PMF" in cipher_upper or wpa3

    if wpa3 and wpa2:
        hint = "WPA3 transition mode; deauthentication may work only against WPA2 clients."
    elif wpa3 and pmf_required:
        hint = "PMF required; deauthentication is unlikely to force a usable handshake."
    elif wpa3:
        hint = "WPA3-capable network; prefer PMKID/SAE-aware capture validation."
    elif "WEP" in cipher_upper:
        hint = "Legacy WEP network; treat as critical finding."
    elif "OPEN" in cipher_upper:
        hint = "Open network; no WPA handshake recovery path."
    else:
        hint = "Standard WPA/WPA2 assessment path."

    return {
        "ssid": str(network.get("ssid", "Unknown")),
        "cipher": cipher,
        "wpa3": wpa3,
        "transition_mode": wpa3 and wpa2,
        "pmf_capable": pmf_capable,
        "pmf_required": pmf_required,
        "hint": hint,
    }


def classify_dot11_packet(pkt: Any) -> str:
    """Classify a Scapy-like 802.11 packet without importing Scapy at module import time."""
    if _has_layer(pkt, "EAPOL"):
        return "eapol"

    dot11 = _get_layer(pkt, "Dot11") or pkt
    frame_type = getattr(dot11, "type", getattr(pkt, "type", None))
    subtype = getattr(dot11, "subtype", getattr(pkt, "subtype", None))
    if frame_type == 0:
        return _MGMT_SUBTYPES.get(int(subtype or 0), "mgmt")
    if frame_type == 1:
        return "control"
    if frame_type == 2:
        return "data"
    return "unknown"


def analyze_pcap_frames(path: Path, *, limit: int = 50000) -> FrameIntelligenceReport:
    """Build frame-level telemetry from a pcap/cap/pcapng file."""
    frame_counts: Counter[str] = Counter()
    bssids: Counter[str] = Counter()
    ssids: Counter[str] = Counter()
    profiles: list[RsnProfile] = []

    try:
        from scapy.all import PcapNgReader, PcapReader
    except Exception as exc:
        raise RuntimeError(f"Scapy is required for pcap analysis: {exc}") from exc

    total = 0
    reader_cls = PcapNgReader if path.suffix.lower() == ".pcapng" else PcapReader
    with reader_cls(str(path)) as reader:
        for pkt in reader:
            total += 1
            if total > limit:
                break
            frame_counts[classify_dot11_packet(pkt)] += 1
            dot11 = _get_layer(pkt, "Dot11")
            if dot11 is not None:
                for attr in ("addr3", "addr2", "addr1"):
                    mac = _norm_mac(getattr(dot11, attr, ""))
                    if mac:
                        bssids[mac] += 1
                        break
            ssid = _extract_ssid(pkt)
            if ssid:
                ssids[ssid] += 1
            for profile in _extract_rsn_profiles(pkt):
                profiles.append(profile)

    unique_profiles = _unique_rsn_profiles(profiles)
    return FrameIntelligenceReport(
        total_frames=total,
        frame_counts=dict(frame_counts),
        bssids=dict(bssids.most_common(20)),
        ssids=dict(ssids.most_common(20)),
        rsn_profiles=tuple(unique_profiles),
        pmf_required_networks=sum(1 for profile in unique_profiles if profile.pmf_required),
        pmf_capable_networks=sum(1 for profile in unique_profiles if profile.pmf_capable),
        wpa3_networks=sum(1 for profile in unique_profiles if profile.wpa3_capable),
    )


def _suite_name(suite: bytes, names: dict[int, str], kind: str) -> str:
    if len(suite) != 4:
        return f"Malformed {kind}"
    oui = suite[:3].hex(":")
    suite_type = suite[3]
    if suite[:3] == b"\x00\x0f\xac":
        return names.get(suite_type, f"RSN-{kind}-{suite_type}")
    if suite[:3] == b"\x00P\xf2":
        return names.get(suite_type, f"WPA-{kind}-{suite_type}")
    return f"{oui}-{suite_type}"


def _unique_rsn_profiles(profiles: Iterable[RsnProfile]) -> list[RsnProfile]:
    seen = set()
    out = []
    for profile in profiles:
        key = (
            profile.group_cipher,
            profile.pairwise_ciphers,
            profile.akm_suites,
            profile.pmf_capable,
            profile.pmf_required,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(profile)
    return out


def _extract_rsn_profiles(pkt: Any) -> list[RsnProfile]:
    profiles = []
    for elt in _iter_dot11_elts(pkt):
        if getattr(elt, "ID", None) != 48:
            continue
        profile = parse_rsn_information(_coerce_bytes(getattr(elt, "info", b"")))
        if profile:
            profiles.append(profile)
    return profiles


def _extract_ssid(pkt: Any) -> str:
    for elt in _iter_dot11_elts(pkt):
        if getattr(elt, "ID", None) != 0:
            continue
        raw = _coerce_bytes(getattr(elt, "info", b""))
        if not raw:
            return ""
        try:
            return raw.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            return ""
    return ""


def _iter_dot11_elts(pkt: Any):
    try:
        elt = pkt.getlayer("Dot11Elt")
    except Exception:
        elt = None
    seen = 0
    while elt is not None and hasattr(elt, "ID") and seen < 256:
        yield elt
        elt = getattr(elt, "payload", None)
        seen += 1


def _has_layer(pkt: Any, layer_name: str) -> bool:
    try:
        return bool(pkt.haslayer(layer_name))
    except Exception:
        return _get_layer(pkt, layer_name) is not None


def _get_layer(pkt: Any, layer_name: str):
    try:
        return pkt.getlayer(layer_name)
    except Exception:
        return None


def _coerce_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("latin-1", errors="replace")
    try:
        return bytes(value)
    except Exception:
        return b""


def _norm_mac(value: object) -> str:
    mac = str(value or "").lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) == 6 and all(len(part) == 2 for part in parts):
        return mac
    return ""
