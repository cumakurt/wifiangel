"""Browse handshake, auto-hack, MITM, and hashcat lab sessions."""

from __future__ import annotations

from pathlib import Path

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from app.ui import BORDER_STYLE, render_menu_panel
from attacks.hashcat_jobs import HashcatJobStore
from config import AUTO_HACK_SESSIONS_DIR, DEFAULT_WORDLIST, HANDSHAKE_DIR, LOGS_ROOT, TMP_DIR
from wifi.sessions import (
    HASH_SUFFIXES,
    KIND_MITM,
    LabSession,
    attach_session,
    discover_lab_sessions,
    pick_hash_file,
    revalidate_session,
)


def run_session_browser(app) -> None:
    """List lab sessions and re-validate, queue hashcat, or attach to the HTML report."""
    while True:
        sessions = _load_sessions()
        _print_session_table(app, sessions)
        render_menu_panel(
            app.console,
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
        choice = Prompt.ask("[heading]Option[/]")
        if choice == "0":
            return
        if choice == "1":
            continue
        session = _select_session(app, sessions)
        if not session:
            continue
        if choice == "2":
            _print_session_detail(app, session)
        elif choice == "3":
            _revalidate(app, session)
        elif choice == "4":
            _queue_hashcat(app, session)
        elif choice == "5":
            _attach(app, session)


def _load_sessions() -> list[LabSession]:
    store = HashcatJobStore(TMP_DIR / "hashcat_jobs.json")
    return discover_lab_sessions(
        handshake_dir=HANDSHAKE_DIR,
        auto_hack_dir=AUTO_HACK_SESSIONS_DIR,
        mitm_dir=LOGS_ROOT / "mitm",
        hashcat_jobs=store.list_jobs(),
    )


def _print_session_table(app, sessions: list[LabSession]) -> None:
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
    if not sessions:
        table.add_row("-", "-", "No sessions found", "-", "-", "-")
    for index, session in enumerate(sessions, start=1):
        hash_name = Path(session.hash_file).name if session.hash_file else "-"
        table.add_row(str(index), session.kind, session.label, session.status, hash_name, session.detail or "-")
    app.console.print(table)


def _select_session(app, sessions: list[LabSession]) -> LabSession | None:
    if not sessions:
        app.console.print("[warning]No lab sessions to select.[/]")
        return None
    raw = Prompt.ask("Session number", default="1").strip()
    try:
        index = int(raw)
    except ValueError:
        app.console.print("[warning]Enter a session number from the table.[/]")
        return None
    if index < 1 or index > len(sessions):
        app.console.print("[warning]Session number is out of range.[/]")
        return None
    return sessions[index - 1]


def _print_session_detail(app, session: LabSession) -> None:
    table = Table(show_header=False, box=box.MINIMAL, border_style=BORDER_STYLE, title="[bold blue]Session[/]")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Kind", session.kind)
    table.add_row("Label", session.label)
    table.add_row("Path", session.path)
    table.add_row("Status", session.status)
    table.add_row("Hash file", session.hash_file or "-")
    table.add_row("Detail", session.detail or "-")
    app.console.print(table)


def _revalidate(app, session: LabSession) -> None:
    result = revalidate_session(session)
    app.console.print(
        Panel(
            f"{result['status']} (score {result['score']})\n{result['path']}\n{result['detail']}",
            title="Re-validate",
            border_style=BORDER_STYLE,
            box=box.MINIMAL,
        )
    )


def _queue_hashcat(app, session: LabSession) -> None:
    if session.kind == KIND_MITM:
        app.console.print("[warning]MITM logs are not hashcat inputs.[/]")
        return
    hash_file = pick_hash_file(Path(session.path), session.hash_file)
    if not hash_file or Path(hash_file).suffix.lower() not in HASH_SUFFIXES:
        app.console.print("[warning]No .22000/.16800 hash file on this session. Capture or convert first.[/]")
        return
    if not DEFAULT_WORDLIST.exists():
        app.console.print(f"[warning]Default wordlist missing: {DEFAULT_WORDLIST}[/]")
        return
    store = HashcatJobStore(TMP_DIR / "hashcat_jobs.json")
    job = store.create_job(hash_file=Path(hash_file), wordlist=DEFAULT_WORDLIST, mode=22000, workload=3)
    app.console.print(f"[success]Hashcat job {job.job_id} queued for {Path(hash_file).name}[/]")


def _attach(app, session: LabSession) -> None:
    current = list(getattr(app, "report_attachments", []) or [])
    updated = attach_session(current, session)
    app.report_attachments = updated
    app.console.print(
        f"[success]Attached {session.kind} [cyan]{session.label}[/] "
        f"({len(updated)} item(s) for Tools 19 HTML report).[/]"
    )
