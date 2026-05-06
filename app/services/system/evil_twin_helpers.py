"""Helpers for Evil Twin telemetry parsing and connection inspection."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess


def parse_dnsmasq_query_lines(lines: list[str]) -> list[tuple[str, str, str, str]]:
    """Return recent rows as (time_hint, client_ip, qname, qtype)."""
    pat = re.compile(
        r"query\[([A-Za-z0-9]+)\]\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
        re.IGNORECASE,
    )
    rows: list[tuple[str, str, str, str]] = []
    for line in lines:
        if "192.168.1." not in line:
            continue
        match = pat.search(line)
        if not match:
            continue
        qtype, qname, client_ip = match.group(1), match.group(2), match.group(3)
        if not client_ip.startswith("192.168.1."):
            continue
        time_hint = ""
        if "dnsmasq" in line:
            time_hint = line.split("dnsmasq", 1)[0].strip()
        rows.append((time_hint, client_ip, qname, qtype))
    return rows[-25:]


def fetch_conntrack_tcp_lan() -> list[tuple[str, str, str]]:
    """Read NAT-forwarded ESTABLISHED LAN TCP sessions from conntrack."""
    if not shutil.which("conntrack"):
        return []
    try:
        raw = subprocess.check_output(
            ["conntrack", "-L", "-p", "tcp"],
            text=True,
            timeout=10,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []
    lan = "192.168.1."
    out: list[tuple[str, str, str]] = []
    for line in raw.splitlines():
        if lan not in line or "ESTABLISHED" not in line.upper():
            continue
        kv: dict[str, str] = {}
        for tok in line.split():
            if "=" in tok:
                key, _, value = tok.partition("=")
                kv[key] = value
        src, sport = kv.get("src", ""), kv.get("sport", "")
        dst, dport = kv.get("dst", ""), kv.get("dport", "")
        if src.startswith(lan):
            out.append((f"{src}:{sport}", f"{dst}:{dport}", "ESTABLISHED"))
    return out[-20:]


def format_bytes(n: int) -> str:
    if n <= 0:
        return "0 B"
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def conntrack_cli_bytes_for_ip(ip: str) -> int:
    """Sum bytes= values from conntrack CLI for a host."""
    if not ip or not shutil.which("conntrack"):
        return 0
    total = 0
    needles = (f"src={ip}", f"dst={ip}")
    try:
        raw = subprocess.check_output(
            ["conntrack", "-L", "-o", "extended"],
            text=True,
            timeout=12,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return 0
    for line in raw.splitlines():
        if not any(n in line for n in needles):
            continue
        for tok in line.split():
            if tok.startswith("bytes="):
                try:
                    total += int(tok[6:])
                except ValueError:
                    pass
                break
    return total


def nf_conntrack_bytes_for_ip(ip: str) -> int:
    """Read bytes for a host from /proc/net/nf_conntrack with CLI fallback."""
    if not ip:
        return 0
    path = Path("/proc/net/nf_conntrack")
    needles = (f"src={ip}", f"dst={ip}")
    total = 0
    try:
        with path.open("r", errors="replace") as fh:
            for line in fh:
                if not any(n in line for n in needles):
                    continue
                for tok in line.split():
                    if tok.startswith("bytes="):
                        try:
                            total += int(tok[6:])
                        except ValueError:
                            pass
                        break
    except OSError:
        return conntrack_cli_bytes_for_ip(ip)
    if total > 0:
        return total
    return conntrack_cli_bytes_for_ip(ip)


def fetch_established_tcp_for_lan() -> list[tuple[str, str, str]]:
    """Return LAN TCP sessions via conntrack first, then ss/netstat fallback."""
    conntrack_rows = fetch_conntrack_tcp_lan()
    if conntrack_rows:
        return conntrack_rows

    lan = "192.168.1."
    out: list[tuple[str, str, str]] = []

    for cmd in (["ss", "-H", "-tn", "state", "established"], ["ss", "-tn", "state", "established"]):
        if not shutil.which(cmd[0]):
            continue
        try:
            raw = subprocess.check_output(cmd, text=True, timeout=5, stderr=subprocess.DEVNULL)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            continue
        for line in raw.splitlines():
            line = line.strip()
            if not line or lan not in line or "ESTAB" not in line.upper():
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            if parts[0] in ("ESTAB", "ESTABLISHED") and len(parts) >= 5:
                local, remote = parts[3], parts[4]
            else:
                local, remote = parts[-2], parts[-1]
            if local.startswith(lan):
                out.append((local, remote, "ESTABLISHED"))
        if out:
            return out[-15:]

    if not shutil.which("netstat"):
        return []
    try:
        raw = subprocess.check_output(["netstat", "-tn"], text=True, timeout=5)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return []
    for line in raw.splitlines():
        if not line.startswith("tcp") or "ESTABLISHED" not in line.upper() or lan not in line:
            continue
        parts = line.split()
        if len(parts) >= 6:
            out.append((parts[3], parts[4], parts[5]))
    return out[-15:]

