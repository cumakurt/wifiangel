"""Packet parsing helpers for Wi-Fi scan results.

This module deliberately uses Scapy layer names instead of importing Scapy
classes at module import time. Scapy may require privileged socket access on
some systems during import, while these helpers should stay unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

_IEEE_SSID_MAX = 32


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
    bssid_l = str(bssid).lower().replace("-", ":")
    if bssid_l in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
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


_MGMT_BEACON_PROBE_FIXED_LEN = 12  # timestamp(8) + beacon interval(2) + capabilities(2)


def _raw_ie_blob(pkt) -> Optional[bytes]:
    """IE bytes after fixed beacon/probe header; None if not serializable (e.g. unit-test fakes)."""
    body = _beacon_or_probe_payload(pkt)
    if body is None:
        return None
    try:
        from scapy.packet import raw as scapy_raw

        braw = scapy_raw(body)
    except Exception:
        return None
    if len(braw) <= _MGMT_BEACON_PROBE_FIXED_LEN:
        return None
    return braw[_MGMT_BEACON_PROBE_FIXED_LEN:]


def _iter_ies(blob: bytes):
    """Parse 802.11 information elements: id(1) len(1) data(len)."""
    i = 0
    n = len(blob)
    while i + 2 <= n:
        eid, elen = blob[i], blob[i + 1]
        i += 2
        if i + elen > n:
            break
        yield eid, blob[i : i + elen]
        i += elen


def _ssid_bytes_from_raw_ies(pkt) -> Optional[bytes]:
    """First SSID IE (0) from raw bytes; None → use Scapy element walk (tests)."""
    blob = _raw_ie_blob(pkt)
    if blob is None:
        return None
    for eid, info in _iter_ies(blob):
        if eid == 0:
            return info[: _IEEE_SSID_MAX]
    return None


def get_ssid(pkt) -> str:
    candidate = _ssid_bytes_from_raw_ies(pkt)
    if candidate is None:
        ssid_elt = _find_elt(pkt, 0)
        if not ssid_elt:
            return "<Hidden Network>"
        raw = _ssid_elt_payload_bytes(ssid_elt)
        if raw is None:
            return "<Hidden Network>"
        candidate = raw
    if len(candidate) == 0:
        return "<Hidden Network>"
    ssid = _decode_ssid_for_display(candidate)
    return ssid if ssid else "<Hidden Network>"


def get_channel(pkt) -> int:
    ch = _channel_from_raw_ds(pkt)
    if ch > 0:
        return ch
    ch = _channel_from_ds_param(pkt)
    if ch > 0:
        return ch
    return _channel_from_radiotap(pkt)


def _channel_from_raw_ds(pkt) -> int:
    blob = _raw_ie_blob(pkt)
    if not blob:
        return 0
    for eid, info in _iter_ies(blob):
        if eid == 3 and len(info) >= 1:
            ch = int(info[0])
            if 0 < ch < 256:
                return ch
    return 0


def _channel_from_ds_param(pkt) -> int:
    channel_elt = _find_elt(pkt, 3)
    if not channel_elt:
        return 0
    try:
        info = channel_elt.info
        if isinstance(info, int):
            return int(info) if 0 < info < 256 else 0
        raw = _coerce_elt_info_to_bytes(info)
        if not raw:
            return 0
        return int(raw[0]) if 0 < raw[0] < 256 else 0
    except Exception:
        return 0


def _channel_from_radiotap(pkt) -> int:
    rt = _get_layer(pkt, "RadioTap")
    if rt is None:
        return 0
    try:
        n = getattr(rt, "ChannelPlusNumber", None)
        if n is not None:
            ni = int(n)
            if ni > 0:
                return ni
    except Exception:
        pass
    try:
        for attr in ("ChannelFrequency", "ChannelPlusFrequency"):
            freq = getattr(rt, attr, None)
            if freq is None:
                continue
            fi = int(freq)
            if fi <= 0:
                continue
            ch = _ieee_freq_mhz_to_channel(fi)
            if ch > 0:
                return ch
    except Exception:
        pass
    return 0


def _ieee_freq_mhz_to_channel(freq_mhz: int) -> int:
    if 2412 <= freq_mhz <= 2484:
        if freq_mhz == 2484:
            return 14
        return (freq_mhz - 2407) // 5
    if 5000 <= freq_mhz <= 5900:
        return (freq_mhz - 5000) // 5
    return 0


def get_signal(pkt) -> int:
    rt = _get_layer(pkt, "RadioTap")
    if rt is not None:
        for attr in ("dBm_AntSignal", "dbm_AntSignal"):
            if hasattr(rt, attr):
                val = getattr(rt, attr)
                if val is not None:
                    try:
                        return int(val)
                    except (TypeError, ValueError):
                        pass
    try:
        if getattr(pkt, "notdecoded", None):
            return -(256 - ord(pkt.notdecoded[-4:-3]))
    except Exception:
        pass
    return -100


def get_security_info(pkt) -> list[str]:
    raw_blob = _raw_ie_blob(pkt)
    cap = _get_capability(pkt)
    privacy = bool(cap and getattr(cap, "privacy", False))

    if raw_blob is not None:
        security: list[str] = []
        for eid, info in _iter_ies(raw_blob):
            info_b = info if isinstance(info, (bytes, bytearray)) else _coerce_elt_info_to_bytes(info)
            if eid == 48:
                if "WPA2" not in security:
                    security.append("WPA2")
                if _rsn_has_wpa3_akm(info_b) and "WPA3" not in security:
                    security.append("WPA3")
            elif eid == 221 and info_b.startswith(b"\x00P\xf2\x01\x01\x00"):
                if "WPA" not in security:
                    security.append("WPA")
            elif eid == 221 and info_b.startswith(b"\x50\x6f\x9a\x1c"):
                if "WPA3" not in security:
                    security.append("WPA3")
        if security:
            return security
        if privacy:
            return ["WEP"]
        return ["OPEN"]

    if not privacy:
        return ["OPEN"]

    security = []
    for elt in _iter_dot11_elts(pkt):
        elt_id = getattr(elt, "ID", None)
        info = _coerce_elt_info_to_bytes(getattr(elt, "info", b"") or b"")

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
    raw_blob = _raw_ie_blob(pkt)
    if raw_blob is not None:
        for eid, info in _iter_ies(raw_blob):
            info_b = info if isinstance(info, (bytes, bytearray)) else _coerce_elt_info_to_bytes(info)
            if eid == 221 and info_b.startswith(b"\x00P\xf2\x04"):
                return True
        return False

    for elt in _iter_dot11_elts(pkt):
        info = _coerce_elt_info_to_bytes(getattr(elt, "info", b"") or b"")
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


def _beacon_or_probe_payload(pkt):
    """802.11 management frame body: IE list starts after fixed fields on Beacon / ProbeResp."""
    for name in ("Dot11Beacon", "Dot11ProbeResp"):
        body = _get_layer(pkt, name)
        if body is not None:
            return body
    return None


def _iter_dot11_elts(pkt):
    """Walk only the IE chain attached to this beacon/probe. Avoids unrelated Dot11Elt layers."""
    body = _beacon_or_probe_payload(pkt)
    if body is not None:
        elt = getattr(body, "payload", None)
    else:
        elt = _get_layer(pkt, "Dot11Elt")

    while elt is not None and not _looks_like_elt(elt):
        elt = getattr(elt, "payload", None)

    seen = 0
    while elt is not None and _looks_like_elt(elt) and seen < 128:
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


def _coerce_elt_info_to_bytes(info) -> bytes:
    if info is None:
        return b""
    if isinstance(info, memoryview):
        return bytes(info)
    if isinstance(info, (bytes, bytearray)):
        return bytes(info)
    if isinstance(info, str):
        return info.encode("latin-1", errors="replace")
    try:
        return bytes(info)
    except Exception:
        return b""


def _ssid_elt_payload_bytes(elt) -> Optional[bytes]:
    """SSID (IE 0) payload; clamp to element length so the next IE is not misread as SSID text."""
    if getattr(elt, "ID", None) != 0:
        return None
    blob = _coerce_elt_info_to_bytes(getattr(elt, "info", b""))
    length = getattr(elt, "len", None)
    if isinstance(length, int) and length >= 0:
        take = min(length, _IEEE_SSID_MAX, len(blob))
        return blob[:take]
    return blob[:_IEEE_SSID_MAX]


def _decode_ssid_for_display(raw: bytes) -> str:
    """Wi‑Fi Alliance recommends UTF‑8; anything else is shown as hidden (no hex garbage)."""
    raw = raw.rstrip(b"\x00")
    if not raw:
        return ""
    try:
        s = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ""
    s = s.replace("\x00", "")
    s = "".join(ch if ch.isprintable() else " " for ch in s)
    s = " ".join(s.split())
    return s.strip()
