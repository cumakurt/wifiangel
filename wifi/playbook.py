"""Recommend the next authorized lab module from a scan network record."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from wifi.frame_intelligence import summarize_network_security

MODULE_HANDSHAKE = "handshake_capture"
MODULE_PMKID = "pmkid_capture"
MODULE_WPS = "wps"
MODULE_EVIL_TWIN = "evil_twin"
MODULE_ENTERPRISE = "enterprise_observe"
MODULE_OBSERVE = "observe"

_MENU_LABELS = {
    MODULE_HANDSHAKE: "Attack 1: Handshake capture",
    MODULE_PMKID: "Attack 3: PMKID capture",
    MODULE_WPS: "Attack 6: WPS",
    MODULE_EVIL_TWIN: "Attack 7: Evil Twin lab",
    MODULE_ENTERPRISE: "Tools 17: Technical intelligence (802.1X)",
    MODULE_OBSERVE: "Tools 7: Security audit",
}


@dataclass(frozen=True)
class AssessmentPlaybook:
    module_id: str
    menu_label: str
    capture_mode: str
    akm_label: str
    reason: str
    findings: tuple[str, ...]
    skip_deauth: bool
    skip_psk_capture: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_id": self.module_id,
            "menu_label": self.menu_label,
            "capture_mode": self.capture_mode,
            "akm_label": self.akm_label,
            "reason": self.reason,
            "findings": list(self.findings),
            "skip_deauth": self.skip_deauth,
            "skip_psk_capture": self.skip_psk_capture,
        }


def recommend_assessment(network: Optional[dict[str, Any]]) -> AssessmentPlaybook:
    """Pick the next existing TUI module from scan fields (cipher, WPS, clients)."""
    network = network or {}
    summary = summarize_network_security(network)
    clients = _client_count(network)
    wps = bool(network.get("wps"))
    findings: list[str] = []
    if summary.get("transition_mode"):
        findings.append("WPA3 transition (SAE+PSK); PSK clients may still complete EAPOL")
    if summary.get("pmf_required") or summary.get("passive_capture"):
        findings.append("Protected management frames; active deauth is skipped")
    if wps:
        findings.append("WPS enabled; Attack 6 is an additional path")

    if summary.get("open"):
        return _playbook(
            MODULE_EVIL_TWIN,
            summary,
            capture_mode="n/a",
            reason="Open network; no PSK handshake. Use the Evil Twin lab or MITM on a permitted uplink.",
            findings=tuple(findings),
            skip_deauth=True,
            skip_psk_capture=True,
        )
    if summary.get("wep"):
        return _playbook(
            MODULE_OBSERVE,
            summary,
            capture_mode="n/a",
            reason="Legacy WEP; record it as a finding. WPA handshake/dictionary paths do not apply.",
            findings=tuple(findings),
            skip_deauth=True,
            skip_psk_capture=True,
        )
    if summary.get("enterprise"):
        return _playbook(
            MODULE_ENTERPRISE,
            summary,
            capture_mode="passive",
            reason="802.1X/MGT network; skip PSK capture and dictionary cracking.",
            findings=tuple(findings),
            skip_deauth=True,
            skip_psk_capture=True,
        )
    if wps and clients == 0 and not summary.get("wpa3"):
        return _playbook(
            MODULE_WPS,
            summary,
            capture_mode="n/a",
            reason="WPS is advertised and no stations are associated; WPS is the practical next module.",
            findings=tuple(findings),
            skip_deauth=True,
            skip_psk_capture=False,
        )
    if summary.get("passive_capture"):
        module_id = MODULE_PMKID if clients == 0 else MODULE_HANDSHAKE
        reason = (
            "WPA3/SAE or PMF; capture is passive (no aireplay). "
            + ("No stations seen; PMKID is the better first try." if clients == 0 else "Keep the radio on-channel and wait for a natural reconnect or PMKID.")
        )
        return _playbook(
            module_id,
            summary,
            capture_mode="passive",
            reason=reason,
            findings=tuple(findings),
            skip_deauth=True,
            skip_psk_capture=False,
        )
    if clients:
        return _playbook(
            MODULE_HANDSHAKE,
            summary,
            capture_mode="active",
            reason="WPA/WPA2-PSK with associated clients; handshake capture with targeted deauth.",
            findings=tuple(findings),
            skip_deauth=False,
            skip_psk_capture=False,
        )
    return _playbook(
        MODULE_PMKID,
        summary,
        capture_mode="active",
        reason="PSK network with no associated clients; try PMKID before waiting on EAPOL.",
        findings=tuple(findings),
        skip_deauth=False,
        skip_psk_capture=False,
    )


def _playbook(
    module_id: str,
    summary: dict[str, Any],
    *,
    capture_mode: str,
    reason: str,
    findings: tuple[str, ...],
    skip_deauth: bool,
    skip_psk_capture: bool,
) -> AssessmentPlaybook:
    return AssessmentPlaybook(
        module_id=module_id,
        menu_label=_MENU_LABELS[module_id],
        capture_mode=capture_mode,
        akm_label=str(summary.get("akm_label") or "Unknown"),
        reason=reason,
        findings=findings,
        skip_deauth=skip_deauth,
        skip_psk_capture=skip_psk_capture,
    )


def _client_count(network: dict[str, Any]) -> int:
    clients = network.get("clients")
    if isinstance(clients, (set, list, tuple)):
        return len(clients)
    return 0
