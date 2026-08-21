"""Scoped iptables chains for Evil Twin lab NAT and forwarding.

Host filter/nat tables are not flushed. Jump rules point at dedicated
WIFIANGEL_ET_* chains so teardown can remove only this application's rules.
"""

from __future__ import annotations

import re
import subprocess
from typing import Callable, Iterable, Optional, Sequence

FILTER_CHAIN = "WIFIANGEL_ET_FWD"
NAT_CHAIN = "WIFIANGEL_ET_NAT"
PRE_CHAIN = "WIFIANGEL_ET_PRE"
INPUT_CHAIN = "WIFIANGEL_ET_IN"
LAN_CIDR = "192.168.1.0/24"
PORTAL_IP = "192.168.1.1"

_IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,14}$")
_CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

Command = list[str]
Runner = Callable[[Sequence[str]], int]


def evil_twin_nat_setup_commands(
    *,
    ap_iface: str,
    wan_iface: Optional[str] = None,
    lan_cidr: str = LAN_CIDR,
    portal: bool = False,
    isolate_clients: bool = False,
    portal_ip: str = PORTAL_IP,
) -> list[Command]:
    """Return argv lists that install scoped NAT/FORWARD/portal rules."""
    need_filter = bool(wan_iface or isolate_clients)
    need_nat_post = bool(wan_iface)
    need_portal = bool(portal)
    if not (need_filter or need_nat_post or need_portal):
        return []

    ap = _require_iface(ap_iface)
    lan = _require_cidr(lan_cidr)
    commands: list[Command] = []

    if need_filter:
        commands.extend(_ensure_chain_commands("filter", FILTER_CHAIN))
        commands.append(["iptables", "-I", "FORWARD", "1", "-s", lan, "-j", FILTER_CHAIN])
        commands.append(["iptables", "-I", "FORWARD", "1", "-d", lan, "-j", FILTER_CHAIN])
        if isolate_clients:
            commands.append(
                ["iptables", "-A", FILTER_CHAIN, "-i", ap, "-o", ap, "-j", "DROP"]
            )

    if need_nat_post:
        wan = _require_iface(wan_iface)
        commands.extend(_ensure_chain_commands("nat", NAT_CHAIN))
        commands.append(
            ["iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", lan, "-j", NAT_CHAIN]
        )
        commands.append(
            ["iptables", "-A", FILTER_CHAIN, "-i", ap, "-o", wan, "-s", lan, "-j", "ACCEPT"]
        )
        commands.append(
            [
                "iptables",
                "-A",
                FILTER_CHAIN,
                "-i",
                wan,
                "-o",
                ap,
                "-d",
                lan,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )
        commands.append(
            ["iptables", "-t", "nat", "-A", NAT_CHAIN, "-s", lan, "-o", wan, "-j", "MASQUERADE"]
        )

    if need_portal:
        dest = _require_ipv4(portal_ip)
        commands.extend(_ensure_chain_commands("nat", PRE_CHAIN))
        commands.extend(_ensure_chain_commands("filter", INPUT_CHAIN))
        commands.append(
            ["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-s", lan, "-j", PRE_CHAIN]
        )
        commands.append(
            ["iptables", "-I", "INPUT", "1", "-s", lan, "-p", "tcp", "--dport", "80", "-j", INPUT_CHAIN]
        )
        commands.append(["iptables", "-t", "nat", "-A", PRE_CHAIN, "-d", dest, "-j", "RETURN"])
        commands.append(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                PRE_CHAIN,
                "-p",
                "tcp",
                "--dport",
                "80",
                "-j",
                "DNAT",
                "--to-destination",
                f"{dest}:80",
            ]
        )
        commands.append(["iptables", "-A", INPUT_CHAIN, "-j", "ACCEPT"])

    return commands


def evil_twin_nat_teardown_commands(
    *,
    lan_cidr: str = LAN_CIDR,
    jump_retries: int = 8,
) -> list[Command]:
    """Return argv lists that remove WIFIANGEL_ET_* jumps and chains."""
    lan = _require_cidr(lan_cidr)
    commands: list[Command] = []
    for _ in range(max(1, jump_retries)):
        commands.extend(_jump_delete_commands(lan))
    commands.extend(
        [
            ["iptables", "-F", FILTER_CHAIN],
            ["iptables", "-X", FILTER_CHAIN],
            ["iptables", "-F", INPUT_CHAIN],
            ["iptables", "-X", INPUT_CHAIN],
            ["iptables", "-t", "nat", "-F", NAT_CHAIN],
            ["iptables", "-t", "nat", "-X", NAT_CHAIN],
            ["iptables", "-t", "nat", "-F", PRE_CHAIN],
            ["iptables", "-t", "nat", "-X", PRE_CHAIN],
        ]
    )
    return commands


def apply_evil_twin_nat(
    *,
    ap_iface: str,
    wan_iface: Optional[str] = None,
    lan_cidr: str = LAN_CIDR,
    portal: bool = False,
    isolate_clients: bool = False,
    portal_ip: str = PORTAL_IP,
    run: Optional[Runner] = None,
) -> None:
    """Install scoped rules after clearing any previous WIFIANGEL_ET_* state."""
    runner = run or _run_iptables
    remove_evil_twin_nat(lan_cidr=lan_cidr, run=runner)
    setup = evil_twin_nat_setup_commands(
        ap_iface=ap_iface,
        wan_iface=wan_iface,
        lan_cidr=lan_cidr,
        portal=portal,
        isolate_clients=isolate_clients,
        portal_ip=portal_ip,
    )
    if not setup:
        return
    _run_command_groups(setup, run=runner, ignore_create_chain=True)


def remove_evil_twin_nat(
    *,
    lan_cidr: str = LAN_CIDR,
    run: Optional[Runner] = None,
) -> None:
    """Remove WIFIANGEL_ET_* jumps and chains; ignore missing-chain errors."""
    runner = run or _run_iptables
    for command in evil_twin_nat_teardown_commands(lan_cidr=lan_cidr):
        runner(command)


def _jump_delete_commands(lan: str) -> list[Command]:
    return [
        ["iptables", "-D", "FORWARD", "-s", lan, "-j", FILTER_CHAIN],
        ["iptables", "-D", "FORWARD", "-d", lan, "-j", FILTER_CHAIN],
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", lan, "-j", NAT_CHAIN],
        ["iptables", "-t", "nat", "-D", "PREROUTING", "-s", lan, "-j", PRE_CHAIN],
        ["iptables", "-D", "INPUT", "-s", lan, "-p", "tcp", "--dport", "80", "-j", INPUT_CHAIN],
    ]


def _ensure_chain_commands(table: str, chain: str) -> list[Command]:
    if table == "filter":
        return [["iptables", "-N", chain], ["iptables", "-F", chain]]
    return [
        ["iptables", "-t", table, "-N", chain],
        ["iptables", "-t", table, "-F", chain],
    ]


def _run_command_groups(
    commands: Iterable[Command],
    *,
    run: Runner,
    ignore_create_chain: bool,
) -> None:
    for command in commands:
        rc = run(command)
        if rc == 0:
            continue
        if ignore_create_chain and _is_create_chain(command):
            continue
        raise RuntimeError(f"iptables command failed ({rc}): {' '.join(command)}")


def _is_create_chain(command: Sequence[str]) -> bool:
    return "-N" in command


def _run_iptables(command: Sequence[str]) -> int:
    completed = subprocess.run(
        list(command),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return int(completed.returncode)


def _require_iface(name: str) -> str:
    iface = str(name or "").strip()
    if not _IFACE_RE.match(iface):
        raise ValueError(f"Invalid interface name: {name!r}")
    return iface


def _require_cidr(value: str) -> str:
    cidr = str(value or "").strip()
    if not _CIDR_RE.match(cidr):
        raise ValueError(f"Invalid IPv4 CIDR: {value!r}")
    return cidr


def _require_ipv4(value: str) -> str:
    ip = str(value or "").strip()
    if not _IPV4_RE.match(ip):
        raise ValueError(f"Invalid IPv4 address: {value!r}")
    return ip
