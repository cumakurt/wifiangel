"""Interactive Wi-Fi security analysis application (main controller)."""

from __future__ import annotations

import os
import sys
from itertools import islice
from typing import Optional

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel

from adapters.system_tools import (
    CommandRunner,
    WiFiAdapterManager,
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
from app.services.attacks.auto_hack_orchestrator import (
    generate_html_report as svc_generate_html_report,
    run_auto_hack as svc_run_auto_hack,
)
from app.services.attacks.deauth_service import (
    run_deauth_all_clients as svc_run_deauth_all_clients,
    run_deauth_single_client as svc_run_deauth_single_client,
)
from app.services.attacks.evil_twin_service import (
    cleanup_evil_twin as svc_cleanup_evil_twin,
    run_evil_twin_attack as svc_run_evil_twin_attack,
    run_evil_twin_attack_impl as svc_run_evil_twin_attack_impl,
    verify_network_services as svc_verify_network_services,
)
from app.services.attacks.mitm_service import (
    format_bytes as svc_mitm_format_bytes,
    get_mac as svc_mitm_get_mac,
    restore_settings as svc_mitm_restore_settings,
    run_mitm_attack as svc_run_mitm_attack,
    run_mitm_attack_impl as svc_run_mitm_attack_impl,
    start_bettercap as svc_mitm_start_bettercap,
)
from app.services.system.cleanup_flow import run_auto_hack_cleanup as svc_run_auto_hack_cleanup, run_kill_processes as svc_run_kill_processes
from app.services.system.bootstrap_service import initialize_adapter as svc_initialize_adapter
from app.services.system.lifecycle_service import cleanup_and_exit as svc_cleanup_and_exit
from app.services.system.network_helpers import (
    default_ipv4_uplink_interface as svc_default_ipv4_uplink_interface,
    ensure_wireless_iface_exists as svc_ensure_wireless_iface_exists,
    evil_twin_nonwifi_internet_uplink_ok as svc_evil_twin_nonwifi_internet_uplink_ok,
    interface_is_wireless as svc_interface_is_wireless,
    renew_dhcp_on_interface as svc_renew_dhcp_on_interface,
)
from app.services.system.evil_twin_helpers import (
    conntrack_cli_bytes_for_ip as svc_conntrack_cli_bytes_for_ip,
    fetch_conntrack_tcp_lan as svc_fetch_conntrack_tcp_lan,
    fetch_established_tcp_for_lan as svc_fetch_established_tcp_for_lan,
    format_bytes as svc_format_bytes,
    nf_conntrack_bytes_for_ip as svc_nf_conntrack_bytes_for_ip,
    parse_dnsmasq_query_lines as svc_parse_dnsmasq_query_lines,
)
from app.services.network.scan_service import (
    get_security as svc_get_security,
    handle_packet as svc_handle_packet,
    render_results_table as svc_render_results_table,
    run_airodump_scan_loop as svc_run_airodump_scan_loop,
    run_results_updater as svc_run_results_updater,
    run_scan_networks as svc_run_scan_networks,
)
from app.services.network.targeting_service import (
    run_network_hopper as svc_run_network_hopper,
    run_select_target_network as svc_run_select_target_network,
)
from app.services.tools.bluetooth_iot_service import run_bluetooth_iot_scanner as svc_run_bluetooth_iot_scanner
from app.services.tools.adapter_service import (
    run_change_adapter_mode as svc_run_change_adapter_mode,
    run_change_channel as svc_run_change_channel,
    run_mac_changer as svc_run_mac_changer,
    run_show_adapter_info as svc_run_show_adapter_info,
)
from app.services.tools.analysis_service import (
    run_channel_optimizer as svc_run_channel_optimizer,
    run_client_analysis as svc_run_client_analysis,
    run_security_audit as svc_run_security_audit,
    run_show_network_stats as svc_run_show_network_stats,
    run_signal_analyzer as svc_run_signal_analyzer,
)
from app.services.tools.hidden_ssid_service import run_hidden_ssid_discovery as svc_run_hidden_ssid_discovery
from app.services.tools.speed_test_service import run_speed_test as svc_run_speed_test
from app.services.tools.technical_service import (
    run_capture_health_checker as svc_run_capture_health_checker,
    run_channel_hopper_optimizer as svc_run_channel_hopper_optimizer,
    run_handshake_validator_pro as svc_run_handshake_validator_pro,
    run_rf_environment_profiler as svc_run_rf_environment_profiler,
    run_technical_intelligence_menu as svc_run_technical_intelligence_menu,
    run_wordlist_intelligence as svc_run_wordlist_intelligence,
    run_wps_risk_analyzer as svc_run_wps_risk_analyzer,
)
from app.context.runtime_state import RuntimeState
from app.controllers.attack_menu import run_attack_menu as ctrl_run_attack_menu, run_deauth_menu as ctrl_run_deauth_menu
from app.controllers.app_controller import run_application_loop as ctrl_run_application_loop
from app.controllers.main_menu import run_main_menu as ctrl_run_main_menu
from app.controllers.tools_menu import run_tools_menu as ctrl_run_tools_menu, run_wifi_adapter_settings as ctrl_run_wifi_adapter_settings
from app.ui import (
    BORDER_STYLE,
    TUI_THEME,
    render_welcome_banner,
)
from config import (
    WIFI_ANGEL_SESSION_BINARIES,
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
        self.runtime_state = RuntimeState(
            console=self.console,
            logger=self.logger,
            command_runner=self.command_runner,
            wifi_adapter=self.wifi_adapter,
        )
        
        render_welcome_banner(
            self.console,
            author_line="Cuma KURT  cumakurt@gmail.com",
            url_line="https://www.linkedin.com/in/cuma-kurt-34414917/",
        )
        svc_initialize_adapter(self, WIFI_ANGEL_SESSION_BINARIES)

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
        svc_run_airodump_scan_loop(self)

    def _results_updater(self):
        svc_run_results_updater(self)

    def scan_networks(self, *, live_table: bool = True):
        svc_run_scan_networks(self, live_table=live_table)

    def packet_handler(self, pkt):
        svc_handle_packet(self, pkt)

    def get_security(self, pkt):
        """Determines security type"""
        return svc_get_security(pkt)

    def print_results(self):
        """Shows results in table format"""
        svc_render_results_table(self)

    def show_main_menu(self):
        """Shows the main menu"""
        ctrl_run_main_menu(self)

    def show_attack_menu(self):
        """Shows attack techniques menu"""
        ctrl_run_attack_menu(self)

    def show_tools_menu(self):
        """Shows tools menu"""
        ctrl_run_tools_menu(self)

    def show_deauth_menu(self):
        """Shows deauthentication attack menu"""
        ctrl_run_deauth_menu(self)

    def wifi_adapter_settings(self):
        """WiFi adapter settings menu"""
        ctrl_run_wifi_adapter_settings(self)

    def change_adapter_mode(self):
        return svc_run_change_adapter_mode(self)

    def change_channel(self):
        return svc_run_change_channel(self)

    def show_adapter_info(self):
        return svc_run_show_adapter_info(self)

    def mac_changer(self):
        return svc_run_mac_changer(self)

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
        return svc_run_signal_analyzer(self)

    def channel_optimizer(self):
        return svc_run_channel_optimizer(self)

    def security_audit(self):
        return svc_run_security_audit(self)

    def network_hopper(self):
        return svc_run_network_hopper(self)

    def select_target_network(self):
        return svc_run_select_target_network(self)

    def auto_hack(self):
        return svc_run_auto_hack(self)
    
    def _generate_html_report(self, session_dir, attack_results, html_report_file):
        return svc_generate_html_report(self, session_dir, attack_results, html_report_file)

    def cleanup_and_exit(self):
        svc_cleanup_and_exit(self)

    def run(self):
        ctrl_run_application_loop(self)

    def show_network_stats(self):
        return svc_run_show_network_stats(self)

    def client_analysis(self):
        return svc_run_client_analysis(self)

    def wps_attack(self):
        """Performs WPS attack using Pixie Dust and brute force methods"""
        svc_run_wps_attack(self)

    def _ensure_wireless_iface_exists(self, preferred: str) -> str:
        return svc_ensure_wireless_iface_exists(self, preferred)

    def _default_ipv4_uplink_interface(self, *, exclude: Optional[set[str]] = None) -> Optional[str]:
        return svc_default_ipv4_uplink_interface(exclude=exclude)

    def _renew_dhcp_on_interface(self, iface: str) -> None:
        svc_renew_dhcp_on_interface(iface)

    def _interface_is_wireless(self, iface: str) -> bool:
        return svc_interface_is_wireless(iface)

    def _evil_twin_nonwifi_internet_uplink_ok(self, uplink: Optional[str]) -> tuple[bool, str]:
        return svc_evil_twin_nonwifi_internet_uplink_ok(self, uplink)

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
        svc_run_evil_twin_attack(self)

    def _evil_twin_attack_impl(self):
        return svc_run_evil_twin_attack_impl(self)

    def cleanup_evil_twin(self, original_settings, log_dir=None):
        return svc_cleanup_evil_twin(self, original_settings, log_dir)

    def verify_network_services(self):
        return svc_verify_network_services(self)

    def hidden_ssid_discovery(self):
        return svc_run_hidden_ssid_discovery(self)

    def bluetooth_iot_scanner(self):
        svc_run_bluetooth_iot_scanner(self)

    def _bluetooth_iot_scanner_impl(self):
        return svc_run_bluetooth_iot_scanner(self)

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
        """Safe cleanup for automated assessment mode."""
        svc_run_auto_hack_cleanup(self)

    def _kill_processes(self, process_names):
        """Kill specific processes by name"""
        svc_run_kill_processes(self, process_names)

    def deauth_all_clients(self):
        return svc_run_deauth_all_clients(self)
        
    def deauth_single_client(self):
        return svc_run_deauth_single_client(self)

    def speed_test(self):
        svc_run_speed_test(self)

    def technical_intelligence(self):
        svc_run_technical_intelligence_menu(self)

    def rf_environment_profiler(self):
        return svc_run_rf_environment_profiler(self)

    def handshake_validator_pro(self):
        return svc_run_handshake_validator_pro(self)

    def wordlist_intelligence(self):
        return svc_run_wordlist_intelligence(self)

    def capture_health_checker(self):
        return svc_run_capture_health_checker(self)

    def wps_risk_analyzer(self):
        return svc_run_wps_risk_analyzer(self)

    def channel_hopper_optimizer(self):
        return svc_run_channel_hopper_optimizer(self)

    def _speed_test_impl(self):
        return svc_run_speed_test(self)

    def _restore_settings(self, original_ip_forward, original_iptables, bettercap_process=None):
        return svc_mitm_restore_settings(self, original_ip_forward, original_iptables, bettercap_process)

    def _format_bytes(self, bytes_value):
        return svc_mitm_format_bytes(bytes_value)

    def get_mac(self, ip, interface):
        return svc_mitm_get_mac(self, ip, interface)

    def start_bettercap(self, interface, target_ip, gateway, script_path=None):
        return svc_mitm_start_bettercap(self, interface, target_ip, gateway, script_path=script_path)

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
        svc_run_mitm_attack(self)

    def _mitm_attack_impl(self):
        return svc_run_mitm_attack_impl(self)
