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
LAN_CIDR = "192.168.1.0/24"

_IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,14}$")
_CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

Command = list[str]
Runner = Callable[[Sequence[str]], int]


def evil_twin_nat_setup_commands(
    *,
    ap_iface: str,
    wan_iface: Optional[str] = None,
    lan_cidr: str = LAN_CIDR,
) -> list[Command]:
    """Return argv lists that install scoped NAT/FORWARD rules.

    With no WAN uplink there is nothing to NAT; an empty command list is returned
    so FORWARD/POSTROUTING on the host stay unchanged.
    """
    if not wan_iface:
        return []

    ap = _require_iface(ap_iface)
    wan = _require_iface(wan_iface)
    lan = _require_cidr(lan_cidr)
    commands: list[Command] = []
    commands.extend(_ensure_chain_commands("filter", FILTER_CHAIN))
    commands.extend(_ensure_chain_commands("nat", NAT_CHAIN))
    commands.extend(_jump_install_commands(lan))
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
            ["iptables", "-t", "nat", "-F", NAT_CHAIN],
            ["iptables", "-t", "nat", "-X", NAT_CHAIN],
        ]
    )
    return commands


def apply_evil_twin_nat(
    *,
    ap_iface: str,
    wan_iface: Optional[str] = None,
    lan_cidr: str = LAN_CIDR,
    run: Optional[Runner] = None,
) -> None:
    """Install scoped rules after clearing any previous WIFIANGEL_ET_* state."""
    runner = run or _run_iptables
    remove_evil_twin_nat(lan_cidr=lan_cidr, run=runner)
    setup = evil_twin_nat_setup_commands(
        ap_iface=ap_iface, wan_iface=wan_iface, lan_cidr=lan_cidr
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


def _jump_install_commands(lan: str) -> list[Command]:
    return [
        ["iptables", "-I", "FORWARD", "1", "-s", lan, "-j", FILTER_CHAIN],
        ["iptables", "-I", "FORWARD", "1", "-d", lan, "-j", FILTER_CHAIN],
        ["iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", lan, "-j", NAT_CHAIN],
    ]


def _jump_delete_commands(lan: str) -> list[Command]:
    return [
        ["iptables", "-D", "FORWARD", "-s", lan, "-j", FILTER_CHAIN],
        ["iptables", "-D", "FORWARD", "-d", lan, "-j", FILTER_CHAIN],
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", lan, "-j", NAT_CHAIN],
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
