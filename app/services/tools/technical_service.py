"""Technical intelligence tools for WiFiAngel."""

from __future__ import annotations

import shlex
import time
from pathlib import Path

from rich import box
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from adapters.system_tools.capabilities import collect_interface_capabilities
from app.ui import BORDER_STYLE, render_menu_panel
from attacks.hashcat_jobs import HashcatJobStore
from config import HANDSHAKE_DIR, TMP_DIR
from wifi.artifacts import best_artifacts_by_identity, index_capture_artifacts
from wifi.capture_quality import analyze_capture_quality
from wifi.channel_hopper import build_adaptive_channel_plan
from wifi.client_profiler import build_client_profiles
from wifi.frame_intelligence import analyze_pcap_frames, summarize_network_security
from wifi.telemetry import PacketRateCounter


def run_technical_intelligence_menu(app) -> None:
    """Run the technical intelligence submenu."""
    while True:
        render_menu_panel(
            app.console,
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
                ("0", "Back"),
            ],
        )
        choice = Prompt.ask("[heading]Option[/]")
        actions = {
            "1": run_capture_quality_tool,
            "2": run_frame_intelligence_tool,
            "3": run_artifact_index_tool,
            "4": run_hashcat_job_manager,
            "5": run_pmf_wpa3_detector,
            "6": run_target_client_profiler,
            "7": run_interface_capability_profiler,
            "8": run_live_packet_rate_telemetry,
            "9": run_adaptive_channel_plan,
        }
        if choice == "0":
            return
        action = actions.get(choice)
        if action:
            action(app)


def run_capture_quality_tool(app) -> None:
    path = _prompt_existing_file("Capture or hash file", default=str(HANDSHAKE_DIR))
    if not path:
        return
    bssid = Prompt.ask("Expected BSSID (optional)", default="").strip() or None
    essid = Prompt.ask("Expected ESSID (optional)", default="").strip() or None
    report = analyze_capture_quality(path, bssid=bssid, essid=essid)

    table = Table(title="[bold blue]Capture Quality[/]", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("File", report.path)
    table.add_row("Format", report.format)
    table.add_row("Score", str(report.score))
    table.add_row("Verdict", report.verdict)
    table.add_row("Replay pairs", str(report.replay_pairs))
    table.add_row("EAPOL messages", ", ".join(f"{k}:{v}" for k, v in report.eapol_messages.items()) or "-")
    table.add_row("Hash records", f"PMKID={report.pmkid_records}, EAPOL={report.eapol_hash_records}")
    table.add_row("Reasons", "\n".join(report.reasons))
    app.console.print(table)


def run_frame_intelligence_tool(app) -> None:
    source = Prompt.ask("Analyze [current] scan data or [file] pcap?", choices=["current", "file"], default="current")
    if source == "file":
        path = _prompt_existing_file("PCAP/CAP/PCAPNG file", default=str(HANDSHAKE_DIR))
        if not path:
            return
        report = analyze_pcap_frames(path)
        table = Table(title="[bold blue]802.11 Frame Intelligence[/]", box=box.MINIMAL, border_style=BORDER_STYLE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Total frames", str(report.total_frames))
        table.add_row("Frame counts", ", ".join(f"{k}:{v}" for k, v in report.frame_counts.items()) or "-")
        table.add_row("Top BSSIDs", ", ".join(f"{k}:{v}" for k, v in list(report.bssids.items())[:5]) or "-")
        table.add_row("Top SSIDs", ", ".join(f"{k}:{v}" for k, v in list(report.ssids.items())[:5]) or "-")
        table.add_row("RSN profiles", str(len(report.rsn_profiles)))
        table.add_row("PMF required", str(report.pmf_required_networks))
        table.add_row("WPA3 capable", str(report.wpa3_networks))
        app.console.print(table)
        return

    if not app.networks:
        app.console.print("[bold red]No networks found. Please scan first.[/]")
        return
    _print_security_profile_table(app)


def run_artifact_index_tool(app) -> None:
    root_input = Prompt.ask("Artifact root", default=str(HANDSHAKE_DIR))
    root = Path(root_input).expanduser()
    if not root.exists():
        app.console.print(f"[bold red]Path not found: {root}[/]")
        return
    index_path = TMP_DIR / "capture_artifact_index.json"
    artifacts = index_capture_artifacts(root, index_path=index_path)
    best = best_artifacts_by_identity(artifacts)

    table = Table(title="[bold blue]Capture Artifact Index[/]", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("Best", style="green", justify="center")
    table.add_column("Identity", style="cyan")
    table.add_column("Score", style="yellow", justify="right")
    table.add_column("Verdict", style="magenta")
    table.add_column("File", style="white")
    for artifact in sorted(artifacts, key=lambda item: (-item.quality_score, item.path))[:40]:
        identity = artifact.inferred_bssid or artifact.inferred_ssid or artifact.sha256[:12]
        table.add_row("yes" if best.get(identity) == artifact else "", identity, str(artifact.quality_score), artifact.verdict, artifact.path)
    app.console.print(table)
    app.console.print(f"[success]Index written to {index_path}[/]")


def run_hashcat_job_manager(app) -> None:
    store = HashcatJobStore(TMP_DIR / "hashcat_jobs.json")
    while True:
        render_menu_panel(
            app.console,
            heading="Hashcat job manager",
            items=[
                ("1", "Create queued job"),
                ("2", "List jobs"),
                ("3", "Show command"),
                ("4", "Update job status"),
                ("0", "Back"),
            ],
        )
        choice = Prompt.ask("[heading]Option[/]")
        if choice == "0":
            return
        if choice == "1":
            hash_file = _prompt_existing_file("Hash file", default=str(HANDSHAKE_DIR))
            if not hash_file:
                continue
            wordlist = _prompt_existing_file("Wordlist file", default="wordlists")
            if not wordlist:
                continue
            mode = IntPrompt.ask("Hashcat mode", default=22000)
            workload = IntPrompt.ask("Workload profile", default=3)
            potfile_disable = Confirm.ask("Disable potfile for this job?", default=False)
            job = store.create_job(
                hash_file=hash_file,
                wordlist=wordlist,
                mode=mode,
                workload=workload,
                potfile_disable=potfile_disable,
            )
            app.console.print(f"[success]Job ready:[/] {job.job_id}")
            app.console.print(_format_command(job.command()))
        elif choice == "2":
            _print_hashcat_jobs(app, store)
        elif choice == "3":
            jobs = store.list_jobs()
            job = _select_job(app, jobs)
            if job:
                app.console.print(Panel(_format_command(job.command()), title=f"Job {job.job_id}", border_style=BORDER_STYLE, box=box.MINIMAL))
                app.console.print(Panel(_format_command(job.restore_command()), title="Restore", border_style=BORDER_STYLE, box=box.MINIMAL))
        elif choice == "4":
            jobs = store.list_jobs()
            job = _select_job(app, jobs)
            if job:
                status = Prompt.ask("New status", choices=["queued", "running", "paused", "complete", "failed"], default=job.status)
                store.update_status(job.job_id, status)
                app.console.print("[success]Status updated.[/]")


def run_pmf_wpa3_detector(app) -> None:
    if not app.networks:
        app.console.print("[bold red]No networks found. Please scan first.[/]")
        return
    _print_security_profile_table(app)


def run_target_client_profiler(app) -> None:
    if not app.networks:
        app.console.print("[bold red]No networks found. Please scan first.[/]")
        return
    profiles = build_client_profiles(app.networks)
    table = Table(title="[bold blue]Target Client Profiles[/]", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("MAC", style="cyan")
    table.add_column("Vendor", style="green")
    table.add_column("Networks", style="yellow")
    table.add_column("Best dBm", style="magenta", justify="right")
    table.add_column("Score", style="white", justify="right")
    for profile in profiles[:40]:
        table.add_row(
            profile.mac,
            profile.vendor,
            ", ".join(profile.associated_networks),
            str(profile.best_signal),
            f"{profile.target_score:.2f}",
        )
    app.console.print(table)


def run_interface_capability_profiler(app) -> None:
    caps = collect_interface_capabilities(app.command_runner, app.interface_name)
    table = Table(title="[bold blue]Interface Capability Profile[/]", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("Capability", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Interface", caps.interface)
    table.add_row("Type", caps.interface_type)
    table.add_row("Modes", ", ".join(caps.supported_modes) or "-")
    table.add_row("Channels", ", ".join(str(ch) for ch in caps.channels[:40]) or "-")
    table.add_row("Monitor", "yes" if caps.supports_monitor else "no")
    table.add_row("AP mode", "yes" if caps.supports_ap else "no")
    table.add_row("5 GHz", "yes" if caps.supports_5ghz else "no")
    table.add_row("HT/VHT/HE", f"{caps.supports_ht}/{caps.supports_vht}/{caps.supports_he}")
    table.add_row("Recommended modules", "\n".join(caps.recommended_modules))
    app.console.print(table)


def run_live_packet_rate_telemetry(app) -> None:
    duration = IntPrompt.ask("Telemetry duration seconds", default=15)
    counter = PacketRateCounter()
    start = time.time()

    try:
        from scapy.all import sniff
    except Exception as exc:
        app.console.print(f"[bold red]Scapy is required for telemetry: {exc}[/]")
        return

    def _render_table():
        snapshot = counter.snapshot(time.time() - start)
        table = Table(title="[bold blue]Live Packet Rate Telemetry[/]", box=box.MINIMAL, border_style=BORDER_STYLE)
        table.add_column("Frame", style="cyan")
        table.add_column("Count", style="yellow", justify="right")
        table.add_column("Rate/s", style="green", justify="right")
        for frame_type, count in snapshot.counts.items():
            table.add_row(frame_type, str(count), str(snapshot.rates_per_second.get(frame_type, 0.0)))
        if not snapshot.counts:
            table.add_row("waiting", "0", "0.0")
        return table

    app.console.print(f"[info]Sniffing on {app.interface_name} for {duration} seconds...[/]")
    try:
        with Live(_render_table(), refresh_per_second=4, console=app.console) as live:
            def _observe(pkt):
                counter.observe_packet(pkt)
                live.update(_render_table())

            sniff(iface=app.interface_name, prn=_observe, timeout=duration, store=False)
    except PermissionError:
        app.console.print("[bold red]Packet telemetry requires root privileges and monitor-mode access.[/]")
    except Exception as exc:
        app.console.print(f"[bold red]Telemetry failed: {exc}[/]")


def run_adaptive_channel_plan(app) -> None:
    if not app.networks:
        app.console.print("[bold red]No networks found. Please scan first.[/]")
        return
    plan = build_adaptive_channel_plan(app.networks)
    table = Table(title="[bold blue]Adaptive Channel Plan[/]", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("Rank", style="cyan", justify="right")
    table.add_column("Channel", style="green", justify="right")
    table.add_column("Band", style="yellow")
    table.add_column("Dwell ms", style="magenta", justify="right")
    table.add_column("Score", style="white", justify="right")
    table.add_column("Reason", style="cyan")
    for idx, entry in enumerate(plan[:20], 1):
        table.add_row(str(idx), str(entry.channel), entry.band, str(entry.dwell_ms), f"{entry.score:.2f}", entry.reason)
    app.console.print(table)


def _print_security_profile_table(app) -> None:
    table = Table(title="[bold blue]PMF / WPA3 Compatibility[/]", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("SSID", style="cyan")
    table.add_column("Cipher", style="yellow")
    table.add_column("WPA3", style="green", justify="center")
    table.add_column("PMF", style="magenta", justify="center")
    table.add_column("Hint", style="white")
    for network in app.networks.values():
        profile = summarize_network_security(network)
        pmf = "required" if profile["pmf_required"] else "capable" if profile["pmf_capable"] else "-"
        table.add_row(
            profile["ssid"],
            profile["cipher"],
            "yes" if profile["wpa3"] else "no",
            pmf,
            profile["hint"],
        )
    app.console.print(table)


def _prompt_existing_file(label: str, *, default: str) -> Path | None:
    value = Prompt.ask(label, default=default).strip()
    path = Path(value).expanduser()
    if path.is_dir():
        files = [item for item in sorted(path.iterdir()) if item.is_file()]
        if not files:
            return None
        return files[0]
    if not path.exists():
        return None
    return path


def _print_hashcat_jobs(app, store: HashcatJobStore) -> None:
    jobs = store.list_jobs()
    table = Table(title="[bold blue]Hashcat Jobs[/]", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("ID", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Mode", style="yellow", justify="right")
    table.add_column("Session", style="magenta")
    table.add_column("Hash file", style="white")
    for job in jobs:
        table.add_row(job.job_id, job.status, str(job.mode), job.session, job.hash_file)
    if not jobs:
        table.add_row("-", "none", "-", "-", "-")
    app.console.print(table)


def _select_job(app, jobs):
    if not jobs:
        app.console.print("[warning]No jobs found.[/]")
        return None
    for idx, job in enumerate(jobs, 1):
        app.console.print(f"{idx}. {job.job_id} [{job.status}] {job.hash_file}")
    choice = IntPrompt.ask("Job number", default=1)
    if not 1 <= choice <= len(jobs):
        app.console.print("[warning]Invalid job selection.[/]")
        return None
    return jobs[choice - 1]


def _format_command(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)
