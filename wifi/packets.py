"""Packet parsing helpers for Wi-Fi scan results.

This module deliberately uses Scapy layer names instead of importing Scapy
classes at module import time. Scapy may require privileged socket access on
some systems during import, while these helpers should stay unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class NetworkObservation:
    bssid: str
    ssid: str
    channel: int
    signal: int
    security: tuple[str, ...]
    wps: bool


@dataclass(frozen=True)
class ClientObservation:
    bssid: str
    src: Optional[str]
    dst: Optional[str]


def parse_network_observation(pkt) -> Optional[NetworkObservation]:
    if not (_has_layer(pkt, "Dot11Beacon") or _has_layer(pkt, "Dot11ProbeResp")):
        return None

    dot11 = _get_layer(pkt, "Dot11")
    bssid = getattr(dot11, "addr3", None)
    if not bssid:
        return None

    return NetworkObservation(
        bssid=bssid,
        ssid=get_ssid(pkt),
        channel=get_channel(pkt),
        signal=get_signal(pkt),
        security=tuple(get_security_info(pkt)),
        wps=check_wps(pkt),
    )


def parse_client_observation(pkt) -> Optional[ClientObservation]:
    if not _has_layer(pkt, "Dot11") or getattr(pkt, "type", None) != 2:
        return None

    dot11 = _get_layer(pkt, "Dot11")
    bssid = getattr(dot11, "addr3", None)
    if not bssid:
        return None

    return ClientObservation(
        bssid=bssid,
        src=getattr(dot11, "addr2", None),
        dst=getattr(dot11, "addr1", None),
    )


def get_ssid(pkt) -> str:
    ssid_elt = _find_elt(pkt, 0)
    if not ssid_elt:
        return "<Hidden Network>"

    try:
        ssid = ssid_elt.info.decode("utf-8", errors="ignore")
    except Exception:
        return "<Hidden Network>"

    return ssid or "<Hidden Network>"


def get_channel(pkt) -> int:
    channel_elt = _find_elt(pkt, 3)
    if not channel_elt:
        return 0

    try:
        info = channel_elt.info
        if isinstance(info, int):
            return info
        return int(info[0])
    except Exception:
        return 0


def get_signal(pkt) -> int:
    try:
        return -(256 - ord(pkt.notdecoded[-4:-3]))
    except Exception:
        return -100


def get_security_info(pkt) -> list[str]:
    cap = _get_capability(pkt)
    if not getattr(cap, "privacy", False):
        return ["OPEN"]

    security: list[str] = []
    for elt in _iter_dot11_elts(pkt):
        elt_id = getattr(elt, "ID", None)
        info = getattr(elt, "info", b"") or b""

        if elt_id == 48:
            if "WPA2" not in security:
                security.append("WPA2")
            if _rsn_has_wpa3_akm(info) and "WPA3" not in security:
                security.append("WPA3")
        elif elt_id == 221 and info.startswith(b"\x00P\xf2\x01\x01\x00"):
            if "WPA" not in security:
                security.append("WPA")
        elif elt_id == 221 and info.startswith(b"\x50\x6f\x9a\x1c"):
            if "WPA3" not in security:
                security.append("WPA3")

    return security or ["WEP"]


def check_wps(pkt) -> bool:
    for elt in _iter_dot11_elts(pkt):
        info = getattr(elt, "info", b"") or b""
        if getattr(elt, "ID", None) == 221 and info.startswith(b"\x00P\xf2\x04"):
            return True
    return False


def _rsn_has_wpa3_akm(rsn_info: bytes) -> bool:
    """Return True when RSN AKM suites include SAE or OWE."""
    try:
        offset = 2  # version
        offset += 4  # group cipher suite

        pairwise_count = int.from_bytes(rsn_info[offset : offset + 2], "little")
        offset += 2 + (pairwise_count * 4)

        akm_count = int.from_bytes(rsn_info[offset : offset + 2], "little")
        offset += 2

        for _ in range(akm_count):
            suite = rsn_info[offset : offset + 4]
            offset += 4
            if len(suite) == 4 and suite[:3] == b"\x00\x0f\xac" and suite[3] in {8, 18}:
                return True
    except Exception:
        return False

    return False


def _get_capability(pkt):
    beacon = _get_layer(pkt, "Dot11Beacon")
    if beacon is not None:
        return getattr(beacon, "cap", None)

    probe_resp = _get_layer(pkt, "Dot11ProbeResp")
    return getattr(probe_resp, "cap", None)


def _find_elt(pkt, elt_id: int):
    for elt in _iter_dot11_elts(pkt):
        if getattr(elt, "ID", None) == elt_id:
            return elt
    return None


def _iter_dot11_elts(pkt):
    elt = _get_layer(pkt, "Dot11Elt")
    seen = 0
    while _looks_like_elt(elt) and seen < 128:
        yield elt
        elt = getattr(elt, "payload", None)
        seen += 1


def _has_layer(pkt, layer_name: str) -> bool:
    try:
        return bool(pkt.haslayer(layer_name))
    except Exception:
        return _get_layer(pkt, layer_name) is not None


def _get_layer(pkt, layer_name: str):
    try:
        layer = pkt.getlayer(layer_name)
        if layer is not None:
            return layer
    except Exception:
        pass

    try:
        return pkt[layer_name]
    except Exception:
        return None


def _looks_like_elt(value) -> bool:
    return hasattr(value, "ID") and hasattr(value, "info")
