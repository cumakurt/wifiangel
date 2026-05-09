"""Attack-related menu controllers."""

from __future__ import annotations

from rich.prompt import Prompt

from app.ui import render_menu_panel, target_banner


def run_attack_menu(app) -> None:
    while True:
        if app.selected_network:
            network = app.networks[app.selected_network]
            target_banner(app.console, str(network["ssid"]), app.selected_network)

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
