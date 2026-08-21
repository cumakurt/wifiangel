"""Attack-related menu controllers."""

from __future__ import annotations

from rich.prompt import Prompt

from app.services.runtime_helpers import selected_network_record
from app.ui import render_menu_panel, target_banner
from app.services.tools.technical_service import run_hashcat_job_manager
from wifi.playbook import recommend_assessment


def run_attack_menu(app) -> None:
    while True:
        record = selected_network_record(app)
        playbook = None
        if record:
            bssid, network = record
            playbook = recommend_assessment(network)
            target_banner(app.console, str(network["ssid"]), bssid, playbook)
        elif app.selected_network:
            app.selected_network = None

        render_menu_panel(
            app.console,
            heading="Attack techniques",
            items=[
                ("1", "WPA / WPA2 / WPA3 handshake capture"),
                ("2", "Deauthentication attack"),
                ("3", "PMKID capture"),
                ("4", "Dictionary attack"),
                ("5", "Hybrid (handshake + PMKID)"),
                ("6", "WPS attack"),
                ("7", "Evil twin lab"),
                ("8", "Man-in-the-middle toolkit"),
                ("9", "Hashcat job manager"),
                ("10", "EAP lab AP (hostapd)"),
                ("0", "Back to main menu"),
            ],
        )

        choice = Prompt.ask("[heading]Option[/]")
        actions = {
            "1": app.capture_handshake,
            "2": app.show_deauth_menu,
            "3": app.pmkid_attack,
            "4": app.dictionary_attack,
            "5": app.hybrid_attack,
            "6": app.wps_attack,
            "7": app.evil_twin_attack,
            "8": app.mitm_attack,
            "9": lambda: run_hashcat_job_manager(app),
            "10": app.eap_lab_ap,
        }
        if choice == "0":
            app.current_menu = "main"
            return
        action = actions.get(choice)
        if action:
            action()


def run_deauth_menu(app) -> None:
    while True:
        render_menu_panel(
            app.console,
            heading="Deauthentication",
            items=[
                ("1", "Broadcast: all associated clients"),
                ("2", "Single client MAC"),
                ("0", "Back"),
            ],
        )

        choice = Prompt.ask("[heading]Option[/]")
        actions = {"1": app.deauth_all_clients, "2": app.deauth_single_client}
        if choice == "0":
            break
        action = actions.get(choice)
        if action:
            action()
