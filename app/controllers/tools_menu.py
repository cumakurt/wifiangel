"""Tools-related menu controllers."""

from __future__ import annotations

from rich.prompt import Prompt

from app.ui import render_menu_panel


def run_tools_menu(app) -> None:
    while True:
        render_menu_panel(
            app.console,
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
                ("11", "RF Environment Profiler"),
                ("12", "Handshake Validator Pro"),
                ("13", "Wordlist Intelligence"),
                ("14", "Capture Health Checker"),
                ("15", "WPS Risk Analyzer"),
                ("16", "Channel Hopper Optimizer"),
                ("0", "Back to main menu"),
            ],
        )

        choice = Prompt.ask("[heading]Option[/]")
        actions = {
            "1": app.wifi_adapter_settings,
            "2": app.show_network_stats,
            "3": app.client_analysis,
            "4": app.mac_changer,
            "5": app.signal_analyzer,
            "6": app.channel_optimizer,
            "7": app.security_audit,
            "8": app.hidden_ssid_discovery,
            "9": app.bluetooth_iot_scanner,
            "10": app.speed_test,
            "11": app.rf_environment_profiler,
            "12": app.handshake_validator_pro,
            "13": app.wordlist_intelligence,
            "14": app.capture_health_checker,
            "15": app.wps_risk_analyzer,
            "16": app.channel_hopper_optimizer,
        }
        if choice == "0":
            return
        action = actions.get(choice)
        if action:
            action()


def run_wifi_adapter_settings(app) -> None:
    while True:
        render_menu_panel(
            app.console,
            heading="Wi-Fi adapter",
            intro_lines=[f"[meta]Current interface[/]  [cyan]{app.interface_name}[/]"],
            items=[
                ("1", "Switch monitor / managed mode"),
                ("2", "Set channel"),
                ("3", "Adapter information"),
                ("0", "Back"),
            ],
        )

        choice = Prompt.ask("[heading]Option[/]")
        actions = {
            "1": app.change_adapter_mode,
            "2": app.change_channel,
            "3": app.show_adapter_info,
        }
        if choice == "0":
            break
        action = actions.get(choice)
        if action:
            action()
