"""Pure builders and checks for the Evil Twin lab AP."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

PORTAL_IP = "192.168.1.1"


def build_hostapd_conf(
    *,
    ap_iface: str,
    ssid: str,
    channel: int,
    wpa_passphrase: Optional[str] = None,
    isolate_clients: bool = False,
) -> str:
    lines = [
        f"interface={ap_iface}",
        "driver=nl80211",
        f"ssid={ssid}",
        "hw_mode=g",
        f"channel={channel}",
        "macaddr_acl=0",
        "auth_algs=1",
        "ignore_broadcast_ssid=0",
        "wmm_enabled=1",
        "ieee80211n=1",
        "ht_capab=[HT40+][SHORT-GI-40][DSSS_CCK-40]",
    ]
    if isolate_clients:
        lines.append("ap_isolate=1")
    if wpa_passphrase:
        lines.extend(
            [
                "wpa=2",
                "wpa_key_mgmt=WPA-PSK",
                f"wpa_passphrase={wpa_passphrase}",
                "wpa_pairwise=CCMP",
                "rsn_pairwise=CCMP",
            ]
        )
    return "\n".join(lines) + "\n"


def build_dnsmasq_conf(
    *,
    ap_iface: str,
    log_dir: Path,
    portal: bool = False,
    portal_ip: str = PORTAL_IP,
) -> str:
    lines = [
        f"interface={ap_iface}",
        "dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h",
        "dhcp-option=3,192.168.1.1",
        "dhcp-option=6,192.168.1.1",
        "log-queries",
        "log-dhcp",
        f"log-facility={log_dir}/dnsmasq.log",
        "log-async=20",
        f"listen-address={portal_ip}",
        "bind-interfaces",
        "no-resolv",
        f"dhcp-leasefile={log_dir}/dnsmasq.leases",
    ]
    if portal:
        lines.append(f"address=/#/{portal_ip}")
    else:
        lines.extend(["server=8.8.4.4", "server=8.8.8.8"])
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class DhcpLease:
    mac: str
    ip: str
    hostname: str


def parse_dnsmasq_leases(text: str) -> list[DhcpLease]:
    leases: list[DhcpLease] = []
    seen: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        mac, ip = parts[1], parts[2]
        hostname = parts[3] if len(parts) >= 4 else "*"
        if not ip.startswith("192.168.1.") or ip.endswith(".1"):
            continue
        if ip in seen:
            continue
        seen.add(ip)
        leases.append(DhcpLease(mac=mac, ip=ip, hostname=hostname))
    return leases


def isolation_ping_command(ip: str, ap_iface: str) -> list[str]:
    return ["ping", "-c", "1", "-W", "1", "-I", ap_iface, ip]


@dataclass(frozen=True)
class IsolationCheck:
    lease_count: int
    reachable: tuple[str, ...]
    unreachable: tuple[str, ...]
    isolated: bool
    status: str
    detail: str


def evaluate_isolation_check(
    leases: Sequence[DhcpLease],
    ping_ok: dict[str, bool],
    *,
    isolated: bool,
) -> IsolationCheck:
    ips = tuple(lease.ip for lease in leases)
    reachable = tuple(ip for ip in ips if ping_ok.get(ip))
    unreachable = tuple(ip for ip in ips if not ping_ok.get(ip))
    if not isolated:
        return IsolationCheck(
            lease_count=len(ips),
            reachable=reachable,
            unreachable=unreachable,
            isolated=False,
            status="skipped",
            detail="Isolation off",
        )
    if len(ips) < 2:
        return IsolationCheck(
            lease_count=len(ips),
            reachable=reachable,
            unreachable=unreachable,
            isolated=isolated,
            status="pending",
            detail="Need two DHCP leases to verify AP reachability",
        )
    if unreachable:
        return IsolationCheck(
            lease_count=len(ips),
            reachable=reachable,
            unreachable=unreachable,
            isolated=isolated,
            status="fail",
            detail=f"AP could not ping {', '.join(unreachable)}",
        )
    sta = "STA isolation on (ap_isolate + FORWARD DROP)" if isolated else "STA isolation off"
    return IsolationCheck(
        lease_count=len(ips),
        reachable=reachable,
        unreachable=unreachable,
        isolated=isolated,
        status="pass",
        detail=f"AP reached {len(reachable)} leases. {sta}",
    )


def probe_lease_reachability(
    ips: Sequence[str],
    ap_iface: str,
    *,
    run: Optional[Callable[..., object]] = None,
) -> dict[str, bool]:
    runner = run
    results: dict[str, bool] = {}
    for ip in ips:
        argv = isolation_ping_command(ip, ap_iface)
        if runner is None:
            completed = subprocess.run(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
            )
            results[ip] = completed.returncode == 0
        else:
            completed = runner(argv)
            code = getattr(completed, "returncode", completed)
            results[ip] = int(code) == 0
    return results
