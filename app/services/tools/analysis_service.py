"""Network analysis tool service functions."""

from __future__ import annotations

import time
from datetime import datetime

from rich import box
from rich.live import Live
from rich.table import Table

from app.ui import BORDER_STYLE
from app.services.runtime_helpers import require_selected_network, selected_network_record, snapshot_networks
from wifi.playbook import recommend_assessment
from wifi.probes import probe_stats_from_app
from config import CHANNELS_2GHZ, CHANNELS_5GHZ


def run_signal_analyzer(app) -> None:
    """Analyze WiFi signal strength and quality."""
    record = require_selected_network(app)
    if not record:
        return
    bssid, _network = record
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
                current = selected_network_record(app)
                if not current or current[0] != bssid:
                    app.console.print("\n[bold yellow]Selected network is no longer available.[/]")
                    return
                _, network = current
                current_time = datetime.now().strftime("%H:%M:%S")
                signal_strength = network["signal"]
                interference = "Low"
                for other_bssid, other_net in snapshot_networks(app):
                    if other_bssid != bssid and abs(other_net["channel"] - network["channel"]) <= 1:
                        interference = "High"
                        break
                signal_data.append((current_time, signal_strength, interference))
                live.update(create_signal_table())
                time.sleep(0.5)
    except KeyboardInterrupt:
        app.console.print("\n[bold yellow]Signal analysis stopped.[/]")


def run_channel_optimizer(app) -> None:
    """Analyze and suggest best channel for WiFi operation."""
    channel_usage = {i: 0.0 for i in CHANNELS_2GHZ}
    channel_usage.update({i: 0.0 for i in CHANNELS_5GHZ})
    for network in app.networks.values():
        channel = network["channel"]
        if channel in channel_usage:
            weight = abs(network["signal"]) / 100.0
            channel_usage[channel] += weight
            if channel <= 14:
                for i in range(max(1, channel - 2), min(14, channel + 2)):
                    if i != channel and i in channel_usage:
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
    table.add_column("AKM", style="cyan")
    table.add_column("Next module", style="blue")
    table.add_column("Security Issues", style="red")
    table.add_column("Risk Level", style="yellow")
    table.add_column("Recommendations", style="green")
    for _, network in app.networks.items():
        playbook = recommend_assessment(network)
        issues = []
        risk_level = "Low"
        recommendations = [playbook.reason]
        if network.get("cipher") and "OPEN" in str(network["cipher"]).upper() and "WPA" not in str(network["cipher"]).upper():
            issues.append("No encryption")
            risk_level = "High"
            recommendations.append("Enable WPA2/WPA3 encryption")
        elif "WEP" in str(network.get("cipher") or ""):
            issues.append("WEP encryption (broken)")
            risk_level = "High"
            recommendations.append("Upgrade to WPA2/WPA3")
        elif playbook.akm_label == "802.1X":
            issues.append("Enterprise 802.1X")
            risk_level = "Low"
        elif "WPA" in str(network.get("cipher") or "") and "WPA2" not in str(network.get("cipher") or "") and "WPA3" not in str(network.get("cipher") or ""):
            issues.append("WPA1 encryption (outdated)")
            risk_level = "Medium"
            recommendations.append("Upgrade to WPA2/WPA3")
        if network.get("wps"):
            issues.append("WPS enabled")
            if risk_level == "Low":
                risk_level = "Medium"
            recommendations.append("Disable WPS")
        if playbook.skip_deauth and not playbook.skip_psk_capture:
            issues.append("PMF/SAE (passive capture)")
        if network["signal"] > -30:
            issues.append("Signal too strong")
            recommendations.append("Reduce transmit power")
        elif network["signal"] < -70:
            issues.append("Signal too weak")
            recommendations.append("Increase transmit power or add repeaters")
        table.add_row(
            network["ssid"],
            playbook.akm_label,
            playbook.menu_label,
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


def run_probe_ssid_table(app) -> None:
    """Show SSIDs observed in airodump-ng Probed ESSIDs (including unassociated stations)."""
    stats = probe_stats_from_app(app)
    if not stats:
        app.console.print(
            "[warning]No probe SSIDs yet. Run a network scan first; unassociated stations "
            "also contribute Preferred Network List names.[/]"
        )
        return
    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.MINIMAL,
        border_style=BORDER_STYLE,
        title="[bold blue]Probe SSIDs (client PNL)[/]",
    )
    table.add_column("#", style="cyan", justify="right")
    table.add_column("SSID", style="yellow")
    table.add_column("Stations", style="green", justify="right")
    table.add_column("Seen with AP", style="white")
    table.add_column("Lab SSID", style="magenta")
    for idx, stat in enumerate(stats[:40], 1):
        aps = ", ".join(stat.associated_bssids[:3]) if stat.associated_bssids else "-"
        if len(stat.associated_bssids) > 3:
            aps += "…"
        table.add_row(
            str(idx),
            stat.ssid,
            str(stat.station_count),
            aps,
            "yes" if stat.usable else "no",
        )
    app.console.print(table)
    top = next((item for item in stats if item.usable), None)
    if top:
        app.console.print(
            f"[info]Most observed usable SSID:[/] [cyan]{top.ssid}[/] "
            f"([dim]{top.station_count} station(s)[/]) — used as Evil Twin default when no target SSID is selected."
        )


def run_generate_session_report(app) -> None:
    """Write the current session HTML report from collected logs."""
    networks = dict(snapshot_networks(app))
    attachments = list(getattr(app, "report_attachments", []) or [])
    path = app.logger.generate_report(networks=networks, lab_sessions=attachments or None)
    app.console.print(f"[success]HTML report written to {path}[/]")
    app.logger.info("Session HTML report generated: %s", path)
