"""Adapter and MAC management service functions."""

from __future__ import annotations

import re
import subprocess
import time

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt

from app.ui import BORDER_STYLE, render_menu_panel


def run_change_adapter_mode(app) -> None:
    render_menu_panel(
        app.console,
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
            app.interface_name = app.wifi_adapter.start_monitor_mode(app.interface_name)
            app.console.print(f"[success]Monitor mode[/]  [cyan]{app.interface_name}[/]")
            app.logger.info(f"Monitor mode activated on {app.interface_name}")
        elif choice == "2":
            app.console.print("[info]Switching to managed mode...[/]")
            app.interface_name = app.wifi_adapter.set_managed_mode(app.interface_name)
            time.sleep(2)
            try:
                iw_info = subprocess.check_output(["iwconfig", app.interface_name], stderr=subprocess.STDOUT).decode()
                if "Mode:Managed" in iw_info:
                    app.console.print(f"[success]Managed mode[/]  [cyan]{app.interface_name}[/]")
                    app.logger.info(f"Switched to managed mode: {app.interface_name}")
                else:
                    app.console.print("[warning]Interface might not be in managed mode.[/]")
            except Exception as exc:
                app.console.print(f"[error]Verification failed:[/] {exc!s}")
    except Exception as exc:
        app.console.print(f"[error]{exc!s}[/]")


def run_change_channel(app) -> None:
    channel = Prompt.ask("Enter new channel number (1-14 or 36-165)")
    try:
        channel = int(channel)
        result = app.command_runner.set_wireless_channel(app.interface_name, channel)
        if result.ok:
            app.console.print(f"[bold green]Channel changed to {channel}![/]")
        else:
            app.console.print(f"[bold red]Could not set channel {channel} on {app.interface_name}.[/]")
    except ValueError:
        app.console.print("[bold red]Invalid channel number![/]")


def run_show_adapter_info(app) -> None:
    try:
        info = subprocess.check_output(["iwconfig", app.interface_name]).decode()
        app.console.print(Panel(info, title="Adapter Information", border_style=BORDER_STYLE, box=box.MINIMAL))
    except Exception as exc:
        app.console.print(f"[bold red]Error: {str(exc)}[/]")


def run_select_capture_interface(app) -> None:
    """Pick the monitor/capture NIC without restarting the TUI."""
    names = app.wifi_adapter.list_wireless_interfaces()
    if not names:
        app.console.print("[error]No wireless interfaces found.[/]")
        return
    for idx, name in enumerate(names, 1):
        marker = " (current capture)" if name == app.interface_name else ""
        app.console.print(f"  {idx}. {name}{marker}")
    choice = Prompt.ask("Capture interface #", default="1")
    try:
        index = int(choice)
    except ValueError:
        app.console.print("[error]Invalid selection.[/]")
        return
    if not 1 <= index <= len(names):
        app.console.print("[error]Invalid selection.[/]")
        return
    selected = names[index - 1]
    if selected == app.ap_interface:
        app.console.print("[warning]Capture and AP cannot be the same dedicated radio. Clearing AP role.[/]")
        app.ap_interface = None
    app.interface_name = selected
    app.console.print(f"[success]Capture interface[/]  [cyan]{app.interface_name}[/]")
    app.logger.info("Capture interface set to %s", app.interface_name)


def run_select_ap_interface(app) -> None:
    """Pick a second wireless NIC for hostapd, or use the capture radio."""
    names = [name for name in app.wifi_adapter.list_wireless_interfaces() if name != app.interface_name]
    app.console.print("  0. Same as capture (single radio)")
    if not names:
        app.console.print("[info]Only one wireless NIC is present; Evil Twin will share the capture radio.[/]")
        app.ap_interface = None
        return
    for idx, name in enumerate(names, 1):
        marker = " (current AP)" if name == getattr(app, "ap_interface", None) else ""
        app.console.print(f"  {idx}. {name}{marker}")
    choice = Prompt.ask("AP interface #", default="0")
    try:
        index = int(choice)
    except ValueError:
        app.console.print("[error]Invalid selection.[/]")
        return
    if index == 0:
        app.ap_interface = None
        app.console.print("[success]AP role[/]  same as capture")
        return
    if not 1 <= index <= len(names):
        app.console.print("[error]Invalid selection.[/]")
        return
    app.ap_interface = names[index - 1]
    app.console.print(f"[success]AP interface[/]  [cyan]{app.ap_interface}[/]")
    app.logger.info("AP interface set to %s", app.ap_interface)


def run_mac_changer(app) -> None:
    if app.command_runner.which("macchanger") is None:
        app.console.print("[bold red]macchanger is not installed![/]")
        app.console.print("[yellow]Install it with: sudo apt install macchanger[/]")
        return

    def apply_macchanger(args):
        app.console.print(f"[bold blue]Updating MAC address for {app.interface_name}...[/]")
        app.wifi_adapter.set_link_down(app.interface_name)
        result = app.command_runner.run(
            ["macchanger", *args, app.interface_name],
            capture_output=True,
        )
        app.wifi_adapter.set_link_up(app.interface_name)
        output = result.stdout.strip() or result.stderr.strip()
        if result.ok:
            app.console.print(Panel(output, title="MAC Changer", border_style=BORDER_STYLE, box=box.MINIMAL))
            app.logger.info(f"MAC address updated on {app.interface_name}")
        else:
            app.console.print(Panel(output or "macchanger failed", title="MAC Changer Error", border_style=BORDER_STYLE, box=box.MINIMAL))
            app.logger.error(f"MAC address change failed on {app.interface_name}: {output}")

    while True:
        app.console.print("\n[bold yellow]MAC Address Changer[/]")
        app.console.print(f"Current Adapter: {app.interface_name}")
        app.console.print("1. Show Current MAC")
        app.console.print("2. Set Random MAC")
        app.console.print("3. Set Custom MAC")
        app.console.print("4. Restore Permanent MAC")
        app.console.print("0. Back")

        choice = Prompt.ask("Select an option", choices=["0", "1", "2", "3", "4"])
        if choice == "0":
            return
        if choice == "1":
            result = app.command_runner.run(["macchanger", "-s", app.interface_name], capture_output=True)
            app.console.print(Panel(result.stdout.strip() or result.stderr.strip(), title="Current MAC", border_style=BORDER_STYLE, box=box.MINIMAL))
        elif choice == "2":
            apply_macchanger(["-r"])
        elif choice == "3":
            custom_mac = Prompt.ask("Enter custom MAC address")
            if not re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", custom_mac):
                app.console.print("[bold red]Invalid MAC address format![/]")
                continue
            apply_macchanger(["-m", custom_mac])
        elif choice == "4":
            apply_macchanger(["-p"])
