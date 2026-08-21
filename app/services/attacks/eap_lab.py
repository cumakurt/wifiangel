"""Builders for a local hostapd WPA-EAP lab AP (no external RADIUS)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
import subprocess

from app.services.attacks.evil_twin_lab import hostapd_radio_lines

DEFAULT_EAP_SSID = "WiFiAngel-EAP-Lab"
DEFAULT_EAP_IDENTITY = "labuser"
DEFAULT_EAP_PASSWORD = "labpass"
DEFAULT_CERT_CN = "WiFiAngel-EAP-Lab"


def valid_eap_identity(value: str) -> bool:
    text = str(value or "")
    if not text or "\n" in text or "\r" in text or '"' in text:
        return False
    return 1 <= len(text) <= 64


def valid_eap_password(value: str) -> bool:
    text = str(value or "")
    if not text or "\n" in text or "\r" in text or '"' in text:
        return False
    return 1 <= len(text) <= 63


def build_eap_user_file(identity: str, password: str) -> str:
    if not valid_eap_identity(identity) or not valid_eap_password(password):
        raise ValueError("Invalid EAP identity or password")
    return (
        "# Local hostapd EAP users for an authorized lab AP.\n"
        "# This file is not a RADIUS proxy and does not relay to an upstream AAA.\n"
        "* PEAP,TTLS\n"
        f'"{identity}" MSCHAPV2 "{password}" [2]\n'
        f'"{identity}" MD5 "{password}" [2]\n'
    )


def build_eap_hostapd_conf(
    *,
    ap_iface: str,
    ssid: str,
    channel: int,
    eap_user_file: Path,
    ca_cert: Path,
    server_cert: Path,
    private_key: Path,
    isolate_clients: bool = False,
) -> str:
    lines = hostapd_radio_lines(
        ap_iface=ap_iface,
        ssid=ssid,
        channel=channel,
        isolate_clients=isolate_clients,
    )
    lines.extend(
        [
            "ieee8021x=1",
            "eap_server=1",
            f"eap_user_file={eap_user_file}",
            f"ca_cert={ca_cert}",
            f"server_cert={server_cert}",
            f"private_key={private_key}",
            "wpa=2",
            "wpa_key_mgmt=WPA-EAP",
            "wpa_pairwise=CCMP",
            "rsn_pairwise=CCMP",
        ]
    )
    return "\n".join(lines) + "\n"


def openssl_self_signed_command(cert_dir: Path, *, cn: str = DEFAULT_CERT_CN) -> list[str]:
    if "/" in cn or "\n" in cn or "\r" in cn or not cn.strip():
        raise ValueError("Invalid certificate CN")
    key = cert_dir / "server.key"
    pem = cert_dir / "server.pem"
    return [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-days",
        "2",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(pem),
        "-subj",
        f"/CN={cn}",
    ]


@dataclass(frozen=True)
class EapLabMaterial:
    user_file: Path
    ca_cert: Path
    server_cert: Path
    private_key: Path


def write_eap_lab_material(
    cert_dir: Path,
    *,
    identity: str,
    password: str,
    run: Optional[Callable[..., object]] = None,
) -> EapLabMaterial:
    """Write hostapd.eap_user and a short-lived self-signed server cert."""
    if not valid_eap_identity(identity) or not valid_eap_password(password):
        raise ValueError("Invalid EAP identity or password")
    cert_dir.mkdir(parents=True, exist_ok=True)
    key_path = cert_dir / "server.key"
    pem_path = cert_dir / "server.pem"
    argv = openssl_self_signed_command(cert_dir)
    runner = run
    if runner is None:
        completed = subprocess.run(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if int(completed.returncode) != 0:
            err = (completed.stderr or b"").decode("utf-8", errors="replace").strip()
            raise RuntimeError(err or "openssl failed")
    else:
        completed = runner(argv)
        code = getattr(completed, "returncode", completed)
        if int(code) != 0:
            raise RuntimeError("openssl failed")
    user_file = cert_dir / "hostapd.eap_user"
    user_file.write_text(build_eap_user_file(identity, password), encoding="utf-8")
    user_file.chmod(0o600)
    if key_path.exists():
        key_path.chmod(0o600)
    return EapLabMaterial(
        user_file=user_file,
        ca_cert=pem_path,
        server_cert=pem_path,
        private_key=key_path,
    )


def eap_methods_label() -> str:
    return "WPA2-EAP (PEAP/TTLS lab)"
