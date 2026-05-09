"""Network analysis tool service functions."""

from __future__ import annotations

import time
from datetime import datetime

from rich import box
from rich.live import Live
from rich.table import Table

from app.ui import BORDER_STYLE


def run_signal_analyzer(app) -> None:
    """Analyze WiFi signal strength and quality."""
    if not app.selected_network:
        app.console.print("[bold red]Please select a target network first![/]")
        return

    network = app.networks[app.selected_network]
    signal_data = []

    def create_signal_table():
        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
        table.add_column("Time", style="cyan")
        table.add_column("Signal Strength (dBm)", style="green")
        table.add_column("Quality", style="yellow")
        table.add_column("Interference", style="red")
        for data in signal_data[-10:]:
            quality = "Excellent" if data[1] > -50 else "Good" if data[1] > -60 else "Fair" if data[1] > -70 else "Poor"
            table.add_row(data[0], str(data[1]), quality, data[2])
        return table

    try:
        with Live(create_signal_table(), refresh_per_second=2) as live:
            while True:
                current_time = datetime.now().strftime("%H:%M:%S")
                signal_strength = network["signal"]
                interference = "Low"
                for other_bssid, other_net in app.networks.items():
                    if other_bssid != app.selected_network and abs(other_net["channel"] - network["channel"]) <= 1:
                        interference = "High"
                        break
                signal_data.append((current_time, signal_strength, interference))
                live.update(create_signal_table())
                time.sleep(0.5)
    except KeyboardInterrupt:
        app.console.print("\n[bold yellow]Signal analysis stopped.[/]")


def run_channel_optimizer(app) -> None:
    """Analyze and suggest best channel for WiFi operation."""
    channel_usage = {i: 0 for i in range(1, 15)}
    channel_usage.update({i: 0 for i in [36, 40, 44, 48, 52, 56, 60, 64]})
    for network in app.networks.values():
        channel = network["channel"]
        if channel in channel_usage:
            weight = abs(network["signal"]) / 100.0
            channel_usage[channel] += weight
            if channel <= 14:
                for i in range(max(1, channel - 2), min(14, channel + 2)):
                    if i != channel:
                        channel_usage[i] += weight * 0.5

    table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("Channel", style="cyan")
    table.add_column("Band", style="green")
    table.add_column("Usage", style="yellow")
    table.add_column("Recommendation", style="blue")
    for channel in sorted(channel_usage.keys()):
        band = "2.4GHz" if channel <= 14 else "5GHz"
        usage = "High" if channel_usage[channel] > 2 else "Medium" if channel_usage[channel] > 1 else "Low"
        recommendation = "Avoid" if usage == "High" else "Good" if usage == "Low" else "Fair"
        table.add_row(str(channel), band, usage, recommendation)
    app.console.print(table)


def run_security_audit(app) -> None:
    """Perform security audit of nearby networks."""
    if not app.networks:
        app.console.print("[bold red]No networks found. Please scan first![/]")
        return

    table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("Network", style="cyan")
    table.add_column("Security Issues", style="red")
    table.add_column("Risk Level", style="yellow")
    table.add_column("Recommendations", style="green")
    for _, network in app.networks.items():
        issues = []
        risk_level = "Low"
        recommendations = []
        if "OPEN" in network["cipher"]:
            issues.append("No encryption")
            risk_level = "High"
            recommendations.append("Enable WPA2/WPA3 encryption")
        elif "WEP" in network["cipher"]:
            issues.append("WEP encryption (broken)")
            risk_level = "High"
            recommendations.append("Upgrade to WPA2/WPA3")
        elif "WPA" in network["cipher"] and "WPA2" not in network["cipher"]:
            issues.append("WPA1 encryption (outdated)")
            risk_level = "Medium"
            recommendations.append("Upgrade to WPA2/WPA3")
        if network["wps"]:
            issues.append("WPS enabled")
            risk_level = "Medium"
            recommendations.append("Disable WPS")
        if network["signal"] > -30:
            issues.append("Signal too strong")
            recommendations.append("Reduce transmit power")
        elif network["signal"] < -70:
            issues.append("Signal too weak")
            recommendations.append("Increase transmit power or add repeaters")
        table.add_row(
            network["ssid"],
            "\n".join(issues) if issues else "None",
            risk_level,
            "\n".join(recommendations) if recommendations else "None",
        )
    app.console.print(table)


def run_show_network_stats(app) -> None:
    """Show detailed network statistics."""
    if not app.networks:
        app.console.print("[bold red]No networks found. Please scan first![/]")
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
    for _, network in app.networks.items():
        table.add_row(
            network["ssid"],
            str(network["channel"]),
            network["cipher"],
            str(network["signal"]),
            str(len(network["clients"])),
            str(network["data_packets"]),
            network["first_seen"].strftime("%H:%M:%S"),
            network["last_seen"].strftime("%H:%M:%S"),
        )
    app.console.print(table)


def run_client_analysis(app) -> None:
    """Analyze connected clients."""
    if not app.networks:
        app.console.print("[bold red]No networks found. Please scan first![/]")
        return
    table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Client Analysis[/]")
    table.add_column("Client MAC", style="cyan")
    table.add_column("Connected To", style="green")
    table.add_column("Network Security", style="yellow")
    table.add_column("Data Packets", style="blue")
    for _, network in app.networks.items():
        for client in network["clients"]:
            table.add_row(client, network["ssid"], network["cipher"], str(network["data_packets"]))
    app.console.print(table)
