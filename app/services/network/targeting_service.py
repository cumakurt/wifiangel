"""Network targeting and hopper service functions."""

from __future__ import annotations

import time

from rich import box
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from app.ui import BORDER_STYLE


def run_network_hopper(app) -> None:
    """Automatically hops between networks to gather intelligence."""
    if not app.networks:
        app.console.print("[bold red]No networks found. Please scan first![/]")
        return

    hopping = True
    current_index = 0
    networks_list = list(app.networks.items())

    def create_hopper_table():
        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
        table.add_column("Current Network", style="cyan", width=30)
        table.add_column("Channel", style="green", justify="center")
        table.add_column("Clients", style="yellow", justify="center")
        table.add_column("Data Packets", style="blue", justify="center")
        table.add_column("Signal", style="magenta", justify="center")

        _, network = networks_list[current_index]
        table.add_row(
            network["ssid"],
            str(network["channel"]),
            str(len(network["clients"])),
            str(network["data_packets"]),
            str(network["signal"]),
        )
        return Panel(table, title="[bold blue]Network Hopper[/]", border_style=BORDER_STYLE, box=box.MINIMAL)

    try:
        with Live(create_hopper_table(), refresh_per_second=2) as live:
            while hopping:
                _, network = networks_list[current_index]
                app.command_runner.set_wireless_channel(app.interface_name, network["channel"])
                live.update(create_hopper_table())
                time.sleep(2)
                current_index = (current_index + 1) % len(networks_list)
    except KeyboardInterrupt:
        app.console.print("\n[bold yellow]Network hopping stopped.[/]")


def run_select_target_network(app) -> None:
    """Allow user to select a target network."""
    if not app.networks:
        app.console.print("[error]No networks found. Scan first.[/]")
        return

    table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("No", style="cyan", justify="center")
    table.add_column("BSSID", style="green")
    table.add_column("SSID", style="yellow")
    table.add_column("Channel", style="blue", justify="center")
    table.add_column("Signal", style="magenta", justify="center")
    table.add_column("Security", style="red")
    table.add_column("Clients", style="cyan", justify="center")

    for idx, (bssid, network) in enumerate(app.networks.items(), 1):
        table.add_row(
            str(idx),
            bssid,
            network["ssid"],
            str(network["channel"]),
            str(network["signal"]),
            network["cipher"],
            str(len(network["clients"])),
        )

    app.console.print(table)
    app.console.print("\n[bold yellow]Select target network (0 to cancel):[/]")

    try:
        choice = int(Prompt.ask("Enter network number"))
        if choice == 0:
            return
        if 1 <= choice <= len(app.networks):
            app.selected_network = list(app.networks.keys())[choice - 1]
            network = app.networks[app.selected_network]
            app.console.print(f"\n[success]Selected network: {network['ssid']} ({app.selected_network})[/]")
            app.logger.info(f"Selected target network: {network['ssid']} ({app.selected_network})")
        else:
            app.console.print("[error]Invalid network number.[/]")
    except ValueError:
        app.console.print("[error]Invalid input.[/]")
