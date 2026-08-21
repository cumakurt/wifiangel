#!/usr/bin/env python3
"""Render WiFiAngel TUI panels with Rich and export PNG screenshots for README."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.terminal_theme import DIMMED_MONOKAI

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.attacks.handshake_engine import (  # noqa: E402
    CaptureQualityReport,
    CaptureSession,
    CaptureTarget,
    DeauthStrategy,
    _render_capture_status,
    _render_capture_summary,
)
from app.ui import (  # noqa: E402
    BORDER_STYLE,
    TUI_THEME,
    create_scan_results_table,
    render_menu_panel,
    render_playbook_panel,
    render_welcome_banner,
    target_banner,
)
from wifi.playbook import recommend_assessment  # noqa: E402

OUT = ROOT / "images"
WIDTH = 92


def _console() -> Console:
    return Console(
        theme=TUI_THEME,
        record=True,
        width=WIDTH,
        force_terminal=True,
        color_system="truecolor",
        highlight=False,
        file=open(os.devnull, "w", encoding="utf-8"),
    )


def _lab_networks() -> list[tuple[str, dict]]:
    now = datetime(2026, 5, 9, 12, 4, 11)
    return [
        (
            "aa:bb:cc:11:22:01",
            {
                "ssid": "Lab-WPA2",
                "channel": 6,
                "cipher": "WPA2/CCMP/PSK",
                "signal": -42,
                "clients": {"11:22:33:44:55:01", "11:22:33:44:55:02"},
                "wps": False,
                "data_packets": 1840,
                "first_seen": now,
                "last_seen": now,
            },
        ),
        (
            "aa:bb:cc:11:22:02",
            {
                "ssid": "Lab-WPA3",
                "channel": 36,
                "cipher": "WPA3/CCMP/SAE",
                "signal": -51,
                "clients": {"11:22:33:44:55:03"},
                "wps": False,
                "data_packets": 220,
                "first_seen": now,
                "last_seen": now,
            },
        ),
        (
            "aa:bb:cc:11:22:03",
            {
                "ssid": "Lab-Guest",
                "channel": 1,
                "cipher": "OPEN",
                "signal": -38,
                "clients": set(),
                "wps": False,
                "data_packets": 12,
                "first_seen": now,
                "last_seen": now,
            },
        ),
        (
            "aa:bb:cc:11:22:04",
            {
                "ssid": "Lab-WPS",
                "channel": 11,
                "cipher": "WPA2/CCMP/PSK",
                "signal": -47,
                "clients": {"11:22:33:44:55:04"},
                "wps": True,
                "data_packets": 640,
                "first_seen": now,
                "last_seen": now,
            },
        ),
    ]


def _save_png(console: Console, stem: str) -> Path:
    png = OUT / f"{stem}.png"
    with tempfile.TemporaryDirectory() as tmp:
        svg_path = Path(tmp) / f"{stem}.svg"
        console.save_svg(str(svg_path), title="WiFiAngel", theme=DIMMED_MONOKAI)
        raw = Path(tmp) / "raw.png"
        chrome = shutil.which("chromium") or shutil.which("google-chrome")
        if not chrome:
            raise RuntimeError("chromium/google-chrome is required to rasterize TUI screenshots")
        subprocess.run(
            [
                chrome,
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--hide-scrollbars",
                "--force-device-scale-factor=2",
                "--window-size=1400,2400",
                f"--screenshot={raw}",
                svg_path.as_uri(),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        magick = shutil.which("magick") or shutil.which("convert")
        if not magick:
            shutil.copyfile(raw, png)
            return png
        subprocess.run(
            [
                magick,
                str(raw),
                "-trim",
                "+repage",
                "-bordercolor",
                "#1a1a1a",
                "-border",
                "12",
                str(png),
            ],
            check=True,
        )
    return png


def capture(stem: str, painter) -> Path:
    console = _console()
    painter(console)
    path = _save_png(console, stem)
    print(f"wrote {path.relative_to(ROOT)}")
    return path


def paint_welcome(console: Console) -> None:
    render_welcome_banner(
        console,
        author_line="Cuma KURT  cumakurt@gmail.com",
        url_line="https://www.linkedin.com/in/cuma-kurt-34414917/",
    )


def paint_main(console: Console) -> None:
    render_menu_panel(
        console,
        heading="Main menu",
        intro_lines=[
            "[meta]Adapter[/]  [cyan]wlan0[/]",
            "[meta]Interface mode[/]  [info]Managed[/]",
        ],
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


def paint_main_scan(console: Console) -> None:
    render_menu_panel(
        console,
        heading="Main menu",
        intro_lines=[
            "[meta]Adapter[/]  [cyan]wlan0mon[/]",
            "[meta]Interface mode[/]  [info]Monitor[/]",
            "[success]LIVE[/] [meta]Network scan running (table updates below; option 2 stops scan)[/]",
        ],
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
    table = create_scan_results_table()
    for idx, (bssid, data) in enumerate(_lab_networks(), 1):
        table.add_row(
            str(idx),
            bssid,
            data["ssid"],
            str(data["channel"]),
            data["cipher"],
            str(data["signal"]),
            str(len(data["clients"])),
        )
    console.print()
    console.print(table)


def paint_attack(console: Console) -> None:
    bssid, network = _lab_networks()[0]
    playbook = recommend_assessment(network)
    target_banner(console, str(network["ssid"]), bssid, playbook)
    console.print()
    render_menu_panel(
        console,
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


def paint_deauth(console: Console) -> None:
    render_menu_panel(
        console,
        heading="Deauthentication",
        items=[
            ("1", "Broadcast: all associated clients"),
            ("2", "Single client MAC"),
            ("0", "Back"),
        ],
    )


def paint_tools(console: Console) -> None:
    render_menu_panel(
        console,
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
            ("17", "Technical intelligence"),
            ("18", "Network hopper"),
            ("19", "Generate HTML session report"),
            ("20", "Probe SSIDs (client PNL)"),
            ("21", "Session browser"),
            ("0", "Back to main menu"),
        ],
    )


def paint_adapter(console: Console) -> None:
    render_menu_panel(
        console,
        heading="Wi-Fi adapter",
        intro_lines=[
            "[meta]Capture[/]  [cyan]wlan0mon[/]",
            "[meta]Evil Twin AP[/]  [cyan]wlan1[/]",
        ],
        items=[
            ("1", "Switch monitor / managed mode"),
            ("2", "Set channel"),
            ("3", "Adapter information"),
            ("4", "Select capture interface"),
            ("5", "Select AP interface"),
            ("0", "Back"),
        ],
    )


def paint_technical(console: Console) -> None:
    render_menu_panel(
        console,
        heading="Technical intelligence",
        items=[
            ("1", "Capture quality and replay verifier"),
            ("2", "802.11 frame intelligence"),
            ("3", "Handshake artifact index"),
            ("4", "Hashcat job manager"),
            ("5", "PMF / WPA3 compatibility detector"),
            ("6", "Target client profiler"),
            ("7", "Interface capability profiler"),
            ("8", "Live packet-rate telemetry"),
            ("9", "Adaptive channel plan"),
            ("10", "RF environment profiler"),
            ("11", "Handshake Validator Pro"),
            ("12", "Wordlist intelligence"),
            ("13", "Capture health checker"),
            ("14", "WPS risk analyzer"),
            ("15", "Channel Hopper Optimizer"),
            ("0", "Back"),
        ],
    )


def paint_hashcat_menu(console: Console) -> None:
    render_menu_panel(
        console,
        heading="Hashcat job manager",
        items=[
            ("1", "Create dictionary / rules job"),
            ("2", "Create mask job (-a 3)"),
            ("3", "List jobs"),
            ("4", "Show command and restore argv"),
            ("5", "Update job status"),
            ("0", "Back"),
        ],
    )


def paint_hashcat_jobs(console: Console) -> None:
    table = Table(title="[bold blue]Hashcat Jobs[/]", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("ID", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Mode", style="yellow", justify="right")
    table.add_column("-a", style="blue", justify="right")
    table.add_column("Session", style="magenta")
    table.add_column("Hash file", style="white")
    table.add_row(
        "a1b2c3d4e5f6",
        "queued",
        "22000",
        "0",
        "wifiangel_lab-wpa2_22000",
        "handshake/Lab-WPA2_aabbcc112201/lab.22000",
    )
    table.add_row("c0ffee12ab34", "complete", "22000", "3", "wifiangel_mask_22000", "auto_hack_sessions/20260509/hash.22000")
    console.print(table)


def paint_session_browser(console: Console) -> None:
    table = Table(
        title="[bold blue]Lab sessions[/]",
        box=box.MINIMAL,
        border_style=BORDER_STYLE,
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Kind", style="cyan")
    table.add_column("Label", style="yellow")
    table.add_column("Status", style="green")
    table.add_column("Hash", style="white")
    table.add_column("Detail", style="magenta")
    table.add_row("1", "handshake", "Lab-WPA2", "usable", "lab.22000", "score 86")
    table.add_row("2", "auto-hack", "20260509_120411", "captured", "hash.22000", "1 recovered")
    table.add_row("3", "mitm", "20260509_121002", "complete", "-", "eth0 ARP session")
    table.add_row("4", "hashcat", "a1b2c3d4e5f6", "queued", "lab.22000", "mode 22000")
    console.print(table)
    console.print()
    render_menu_panel(
        console,
        heading="Session browser",
        items=[
            ("1", "Refresh list"),
            ("2", "Show details"),
            ("3", "Re-validate artifact"),
            ("4", "Queue hashcat job"),
            ("5", "Attach to HTML report"),
            ("0", "Back"),
        ],
    )


def paint_select_target(console: Console) -> None:
    table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("No", style="cyan", justify="center")
    table.add_column("BSSID", style="green")
    table.add_column("SSID", style="yellow")
    table.add_column("Channel", style="blue", justify="center")
    table.add_column("Signal", style="magenta", justify="center")
    table.add_column("Security", style="red")
    table.add_column("Clients", style="cyan", justify="center")
    table.add_column("Next", style="white")
    for idx, (bssid, network) in enumerate(_lab_networks(), 1):
        playbook = recommend_assessment(network)
        table.add_row(
            str(idx),
            bssid,
            network["ssid"],
            str(network["channel"]),
            str(network["signal"]),
            network["cipher"],
            str(len(network["clients"])),
            playbook.akm_label,
        )
    console.print(table)
    console.print("\n[bold yellow]Select target network (0 to cancel):[/]")
    bssid, network = _lab_networks()[0]
    render_playbook_panel(console, recommend_assessment(network))


def paint_handshake(console: Console) -> None:
    target = CaptureTarget(
        bssid="aa:bb:cc:11:22:01",
        ssid="Lab-WPA2",
        channel=6,
        cipher="WPA2/CCMP/PSK",
        clients=("11:22:33:44:55:01", "11:22:33:44:55:02"),
    )
    session_dir = Path("handshake/Lab-WPA2_aabbcc112201_20260509_120411")
    session = CaptureSession(
        session_id="20260509_120411",
        started_at="2026-05-09T12:04:11",
        interface="wlan0mon",
        target=target,
        session_dir=session_dir,
        output_prefix=session_dir / "capture",
        manifest_path=session_dir / "capture_manifest.json",
        pmkid_pcapng=session_dir / "pmkid.pcapng",
        pmkid_hash=session_dir / "pmkid.22000",
        status="capturing",
        duration_seconds=94.0,
        deauth_strategy=DeauthStrategy(
            mode="targeted",
            clients=target.clients,
            packet_count=2,
            interval_seconds=8.0,
            reason="Associated stations present; PMF not required",
        ),
        deauth_bursts=4,
        best_score=86,
        best_verdict="crackable",
    )
    report = CaptureQualityReport(
        path=str(session_dir / "capture-01.cap"),
        score=86,
        verdict="crackable",
        format="pcap",
        frame_counts={"eapol": 8, "beacon": 120},
        eapol_messages={"M1": 2, "M2": 2, "M3": 2, "M4": 2},
        replay_pairs=2,
        pmkid_records=0,
        eapol_hash_records=1,
        bssid_matched=True,
        reasons=("Complete EAPOL replay pair",),
    )
    console.print(_render_capture_status(session, report))
    console.print()
    session.status = "complete"
    session.best_capture = str(session_dir / "capture-01.cap")
    session.hash_file = str(session_dir / "lab.22000")
    session.hashcat_job_id = "a1b2c3d4e5f6"
    console.print(_render_capture_summary(session))


def paint_auto_hack(console: Console) -> None:
    priority = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.MINIMAL,
        border_style="cyan",
        title="[bold blue]Target Networks (Prioritized)[/]",
    )
    priority.add_column("Priority", style="cyan", justify="center")
    priority.add_column("Network", style="green")
    priority.add_column("Score", style="yellow", justify="center")
    priority.add_column("Clients", style="blue", justify="center")
    priority.add_column("Security", style="magenta")
    priority.add_column("Next", style="white")
    scored = [
        (_lab_networks()[0], 85),
        (_lab_networks()[3], 70),
        (_lab_networks()[1], 55),
    ]
    for i, ((bssid, network), score) in enumerate(scored, 1):
        playbook = recommend_assessment(network)
        priority.add_row(
            str(i),
            f"{network['ssid']} ({bssid})",
            str(score),
            str(len(network["clients"])),
            network["cipher"],
            playbook.akm_label,
        )
    console.print(priority)
    console.print()
    rows = [
        Text.assemble(("  * ", "dim"), ("Lab-WPA2", "bold cyan"), ("  ", ""), ("Deauth done; capture phase (typically 3-5 min)", ""), ("  ", "dim"), ("94s", "yellow")),
    ]
    live = Panel(
        Group(
            Text.assemble(("Finished ", "bold"), ("0/2", "green bold"), ("  ", ""), ("|  ", "dim"), ("Each network capture typically runs ~3-5 minutes before this step advances.", "dim")),
            Group(*rows),
        ),
        title="[bold]Step 4 · Sequential assessments[/]",
        subtitle="[dim]Live status from capture loop[/]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    console.print(live)
    console.print()
    results = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.MINIMAL,
        border_style="cyan",
        title="[bold blue]Assessment Results[/]",
    )
    results.add_column("Network", style="cyan")
    results.add_column("Status", style="yellow", width=40)
    results.add_column("Handshake", style="green")
    results.add_column("PMKID", style="blue")
    results.add_column("Password", style="magenta")
    results.add_row("Lab-WPA2", "[success]Assessment successful - passphrase recovered.", "[green]Captured", "[yellow]Trying", "********")
    results.add_row("Lab-WPS", "[warning]Captured data but could not recover passphrase.", "[green]Captured", "[red]Failed", "")
    console.print(results)


def paint_network_stats(console: Console) -> None:
    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.MINIMAL,
        border_style=BORDER_STYLE,
        title="[bold blue]Network Statistics[/]",
    )
    table.add_column("Network", style="cyan")
    table.add_column("Channel", style="green")
    table.add_column("Security", style="yellow")
    table.add_column("Signal", style="blue")
    table.add_column("Clients", style="magenta")
    table.add_column("Data Packets", style="cyan")
    table.add_column("First Seen", style="green")
    table.add_column("Last Seen", style="yellow")
    for _, network in _lab_networks():
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
    console.print(table)
    console.print()
    clients = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.MINIMAL,
        border_style=BORDER_STYLE,
        title="[bold blue]Client Analysis[/]",
    )
    clients.add_column("Client MAC", style="cyan")
    clients.add_column("Connected To", style="green")
    clients.add_column("Network Security", style="yellow")
    clients.add_column("Data Packets", style="blue")
    for _, network in _lab_networks():
        for client in sorted(network["clients"]):
            clients.add_row(client, network["ssid"], network["cipher"], str(network["data_packets"]))
    console.print(clients)


def paint_probe_ssids(console: Console) -> None:
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
    table.add_row("1", "Lab-WPA2", "3", "aa:bb:cc:11:22:01", "yes")
    table.add_row("2", "Corp-Guest", "2", "-", "yes")
    table.add_row("3", "Lab-WPS", "1", "aa:bb:cc:11:22:04", "yes")
    console.print(table)


def paint_pmf(console: Console) -> None:
    table = Table(title="[bold blue]PMF / WPA3 Compatibility[/]", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("SSID", style="cyan")
    table.add_column("Cipher", style="yellow")
    table.add_column("WPA3", style="green", justify="center")
    table.add_column("PMF", style="magenta", justify="center")
    table.add_column("Hint", style="white")
    table.add_row("Lab-WPA2", "WPA2/CCMP/PSK", "no", "-", "PSK handshake capture")
    table.add_row("Lab-WPA3", "WPA3/CCMP/SAE", "yes", "required", "Passive capture; skip deauth")
    table.add_row("Lab-Guest", "OPEN", "no", "-", "Evil Twin / MITM lab path")
    table.add_row("Lab-WPS", "WPA2/CCMP/PSK", "no", "-", "WPS additional path")
    console.print(table)


def paint_evil_twin(console: Console) -> None:
    status = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.MINIMAL,
        border_style=BORDER_STYLE,
        title="[bold blue]Evil Twin Status[/]",
    )
    status.add_column("SSID", style="cyan")
    status.add_column("Channel", style="green")
    status.add_column("Security", style="yellow")
    status.add_column("AP Status", style="magenta")
    status.add_column("Running Time", style="cyan")
    status.add_row("Lab-WPA2", "6", "WPA2-PSK", "[bold green]Active", "00:04:18")
    console.print(status)
    console.print()
    clients = Table(
        show_header=True,
        header_style="bold yellow",
        box=box.MINIMAL,
        border_style=BORDER_STYLE,
        title="[bold blue]Connected Clients[/]",
    )
    clients.add_column("MAC", style="cyan")
    clients.add_column("IP", style="green")
    clients.add_column("Hostname", style="yellow")
    clients.add_row("11:22:33:44:55:01", "192.168.1.12", "lab-phone")
    console.print(clients)
    console.print()
    console.print("[success]Internet sharing on[/] — NAT [dim]192.168.1.0/24[/] → [cyan]eth0[/] (AP [cyan]wlan1[/], scoped WIFIANGEL_ET chains)")


def paint_mitm(console: Console) -> None:
    session = Table(show_header=False, box=box.MINIMAL, border_style=BORDER_STYLE, pad_edge=False, expand=True)
    session.add_column("k", style="meta")
    session.add_column("v", style="white")
    session.add_row("Interface", "eth0")
    session.add_row("Gateway", "192.168.9.1")
    session.add_row("Target", "192.168.9.24")
    session.add_row("NAT", "WIFIANGEL_MITM_NAT")
    traffic = Table(box=box.MINIMAL, border_style=BORDER_STYLE, show_header=True, header_style="bold dim", expand=True)
    traffic.add_column("Time", style="dim")
    traffic.add_column("Proto", style="cyan")
    traffic.add_column("Summary", style="white")
    traffic.add_row("12:10:04", "DNS", "lab-phone → lab.internal A")
    traffic.add_row("12:10:05", "HTTP", "192.168.9.24 → 192.168.9.1 GET /")
    clients = Table(show_header=True, box=box.MINIMAL, border_style=BORDER_STYLE, header_style="bold dim", expand=True)
    clients.add_column("IP", style="cyan")
    clients.add_column("MAC", style="green")
    clients.add_column("Hostname", style="yellow")
    clients.add_row("192.168.9.24", "11:22:33:44:55:01", "lab-phone")
    console.print(
        Panel(
            Group(session, Text(""), traffic, Text(""), clients),
            title="[bold]MITM session[/]",
            border_style=BORDER_STYLE,
            box=box.ROUNDED,
        )
    )
    console.print("\n[bold white on red]Ctrl+C stops the MITM session when you are done.[/]")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    shots = [
        ("welcome", paint_welcome),
        ("main_menu", paint_main),
        ("main_menu_scan", paint_main_scan),
        ("Attack_techniques", paint_attack),
        ("deauthentication", paint_deauth),
        ("tools", paint_tools),
        ("wifi_adapter", paint_adapter),
        ("technical_intelligence", paint_technical),
        ("hashcat_job_manager", paint_hashcat_menu),
        ("hashcat_jobs", paint_hashcat_jobs),
        ("session_browser", paint_session_browser),
        ("select_target", paint_select_target),
        ("handshake_capture", paint_handshake),
        ("automated_assessment", paint_auto_hack),
        ("network_statistics", paint_network_stats),
        ("probe_ssids", paint_probe_ssids),
        ("pmf_wpa3", paint_pmf),
        ("evil_twin", paint_evil_twin),
        ("mitm_dashboard", paint_mitm),
    ]
    for stem, painter in shots:
        capture(stem, painter)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
