"""Menu controllers extracted from WiFiAngel main class."""

from __future__ import annotations

import threading
import time

from rich.prompt import Prompt

from app.ui import render_menu_panel


def _adapter_mode_display(app) -> str:
    """Human-readable nl80211 type for the current adapter (iw dev <iface> info)."""
    raw = app.wifi_adapter.get_interface_type(app.interface_name)
    if raw:
        return raw.replace("_", " ").title()
    return "Unknown"


def run_main_menu(app) -> None:
    app.current_menu = "main"
    while True:
        try:
            intro = [
                f"[meta]Adapter[/]  [cyan]{app.interface_name}[/]",
                f"[meta]Interface mode[/]  [info]{_adapter_mode_display(app)}[/]",
            ]
            if app.scanning:
                intro.append(
                    "[success]LIVE[/] [meta]Network scan running (table updates below; option 2 stops scan)[/]"
                )

            render_menu_panel(
                app.console,
                heading="Main menu",
                intro_lines=intro,
                items=[
                    ("1", "Start monitor mode"),
                    ("2", "Start or stop network scan"),
                    ("3", "Select target network"),
                    ("4", "Attack techniques"),
                    ("5", "Tools"),
                    ("6", "Automated assessment workflow"),
                    ("7", "Switch to managed mode"),
                    ("0", "Exit"),
                ],
            )

            choice = Prompt.ask("[heading]Option[/]")
            app.logger.info(f"Main menu selection: {choice}")

            if choice == "1":
                if not app.start_monitor_mode():
                    continue
            elif choice == "2":
                if not app.interface_name.endswith("mon"):
                    app.console.print("[warning]Monitor mode is required for scanning.[/]")
                    app.console.print("[info]Enabling monitor mode automatically...[/]")
                    if not app.start_monitor_mode():
                        app.console.print("[error]Could not enable monitor mode.[/]")
                        continue

                app.scanning = not app.scanning
                if app.scanning:
                    scan_thread = threading.Thread(target=app.scan_networks)
                    scan_thread.daemon = True
                    scan_thread.start()
                    time.sleep(0.2)
                else:
                    app.console.print("[warning]Stopping scan...[/]")
            elif choice == "3":
                app.select_target_network()
            elif choice == "4":
                app.current_menu = "attack"
                app.show_attack_menu()
            elif choice == "5":
                app.current_menu = "tools"
                app.show_tools_menu()
            elif choice == "6":
                app.auto_hack()
            elif choice == "7":
                if app.wifi_adapter.get_interface_type(app.interface_name) == "managed":
                    app.console.print("[info]Interface is already in managed mode.[/]")
                    continue
                if app.scanning:
                    app.console.print("[warning]Stopping network scan before switching to managed mode...[/]")
                    app.scanning = False
                    time.sleep(1.2)
                try:
                    app.console.print("[info]Switching to managed mode (airmon-ng stop, iw type managed, NetworkManager)...[/]")
                    app.interface_name = app.wifi_adapter.set_managed_mode(app.interface_name)
                    app.console.print(f"[success]Managed mode[/]  [cyan]{app.interface_name}[/]")
                    app.logger.info("Main menu: interface set to managed mode on %s", app.interface_name)
                except Exception as exc:
                    app.console.print(f"[error]{exc!s}[/]")
                    app.logger.error("Main menu: set_managed_mode failed: %s", exc)
            elif choice == "0":
                if app.scanning:
                    app.console.print("[bold yellow]Stopping network scan...[/]")
                    app.scanning = False
                    time.sleep(1)
                app.logger.info("Program shutting down...")
                app.cleanup_and_exit()

        except KeyboardInterrupt:
            if app.scanning:
                app.scanning = False
                app.console.print("\n[bold yellow]Stopping network scan...[/]")
                time.sleep(1)
                continue
            if app.current_menu == "main":
                app.logger.info("Program shutting down...")
                app.cleanup_and_exit()
            else:
                app.logger.info("Returning to main menu")
                app.console.print("\n[bold yellow]Returning to main menu...[/]")
                app.current_menu = "main"
                continue
