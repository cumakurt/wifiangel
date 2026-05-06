"""Rich theme and style tokens for the terminal UI."""

from __future__ import annotations

from types import SimpleNamespace

from rich.theme import Theme

# Rich Table/Panel border_style uses Style.parse(), which does not resolve Theme
# aliases like markup [border] does. Keep this equal to the "border" theme entry.
BORDER_STYLE = "dim bright_black"

TUI_THEME = Theme(
    {
        "brand": "bold bright_cyan",
        "brand_sub": "dim cyan",
        "title": "bold bright_white",
        "heading": "bold cyan",
        "menu.key": "bold bright_cyan",
        "menu.text": "default",
        "menu.dim": "dim white",
        "accent": "bright_magenta",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "info": "bright_blue",
        "border": "dim bright_black",
        "meta": "dim",
        "highlight": "bold white",
    }
)

M = SimpleNamespace(
    ok="[success]OK[/]",
    warn="[warning]WARN[/]",
    err="[error]FAIL[/]",
    info="[info]NOTE[/]",
)
