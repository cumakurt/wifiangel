"""Safety helpers for authorized wireless assessment workflows."""

from __future__ import annotations

import re

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from app.ui import BORDER_STYLE


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")
_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|authorization|cookie|set-cookie|api[_-]?key)\b"
    r"\s*([:=])\s*([^,\s;&]+)"
)


def sanitize_filename(value: object, *, fallback: str = "artifact", max_length: int = 96) -> str:
    """Return a filesystem-safe ASCII filename segment."""
    text = str(value or "").strip()
    text = _CONTROL_CHARS.sub("_", text)
    text = _UNSAFE_FILENAME_CHARS.sub("_", text)
    text = re.sub(r"_+", "_", text).strip("._-")
    if not text:
        text = fallback
    text = text[:max_length].rstrip("._-")
    return text or fallback


def redact_sensitive_text(value: object) -> str:
    """Redact common secret-bearing assignments from tool output."""
    text = str(value or "")

    def _replacement(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}<redacted>"

    return _SENSITIVE_ASSIGNMENT.sub(_replacement, text)


def confirm_legal_use(console) -> bool:
    """Ask for the single startup legal-use confirmation."""
    lines = [
        Text("Legal use confirmation", style="bold yellow", justify="center"),
        Text(""),
        Text("Use WiFiAngel only for lawful, authorized security testing."),
        Text("You are responsible for complying with all applicable laws, rules, and permissions."),
        Text("Only test networks and equipment you own or have explicit authorization to assess."),
        Text(""),
        Text("Continue? (Y/N)", style="bold cyan", justify="center"),
    ]

    console.print(
        Panel(
            Group(*lines),
            title="[warning]Startup Confirmation[/]",
            border_style=BORDER_STYLE,
            box=box.MINIMAL,
        )
    )
    try:
        answer = Prompt.ask("Confirmation", default="N")
    except (EOFError, KeyboardInterrupt):
        console.print("\n[warning]Startup cancelled.[/]")
        return False

    if answer.strip().lower() != "y":
        console.print("[warning]Authorization not confirmed. Startup cancelled.[/]")
        return False
    return True
