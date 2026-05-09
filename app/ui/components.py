"""Reusable panels, menus, and tables for the WiFiAngel TUI."""

from __future__ import annotations

from datetime import datetime

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .theme import BORDER_STYLE


def render_welcome_banner(console: Console, *, author_line: str, url_line: str) -> None:
    """Startup brand block: minimal, high contrast, no icons."""
    year = datetime.now().year
    title = Text()
    title.append("WiFiAngel", style="brand")
    title.append("   ", style="default")
    title.append("Wireless security workspace", style="brand_sub")

    footer = Text()
    footer.append(f"(c) {year}  ", style="meta")
    footer.append(author_line.strip(), style="menu.dim")
    footer.append("\n", style="default")
    footer.append(url_line.strip(), style="meta")

    body = Group(title, Text(""), footer)
    console.print(
        Panel.fit(
            body,
            border_style=BORDER_STYLE,
            box=box.MINIMAL,
            padding=(1, 2),
        )
    )
    console.print()


def render_menu_panel(
    console: Console,
    *,
    heading: str,
    items: list[tuple[str, str]],
    intro_lines: list[str] | None = None,
    foot_hint: str = "Enter the option number",
) -> None:
    """Menu panel with aligned numeric keys."""
    blocks: list[str] = [f"[heading]{heading}[/]", ""]
    if intro_lines:
        for line in intro_lines:
            blocks.append(line)
        blocks.append("")
    for key, label in items:
        blocks.append(f"  [menu.key]{key:>2}[/]  {label}")
    blocks.append("")
    blocks.append(f"[meta]{foot_hint}  |  Ctrl+C where supported[/]")
    content = "\n".join(blocks)
    console.print(
        Panel(
            content,
            border_style=BORDER_STYLE,
            box=box.ROUNDED,
            padding=(1, 2),
            title="[title]WiFiAngel[/]",
            title_align="left",
        )
    )


def create_scan_results_table() -> Table:
    """Live scan table styling."""
    table = Table(
        title="[heading]Networks in range[/]",
        box=box.MINIMAL,
        border_style=BORDER_STYLE,
        header_style="bold bright_white on #1e293b",
        show_lines=False,
        padding=(0, 1),
        expand=False,
    )
    table.add_column("#", style="meta", justify="right", width=3)
    table.add_column("BSSID", style="cyan", overflow="ellipsis", max_width=19)
    table.add_column("SSID", style="highlight", overflow="ellipsis", max_width=28)
    table.add_column("Ch", justify="center", style="bright_white", width=4)
    table.add_column("Security", style="accent", overflow="ellipsis", max_width=18)
    table.add_column("dBm", justify="right", style="yellow", width=5)
    table.add_column("Clients", justify="right", style="green", width=7)
    return table


def target_banner(console: Console, ssid: str, bssid: str) -> None:
    console.print(
        Panel(
            f"[meta]Target[/]  [highlight]{ssid}[/]  [meta]({bssid})[/]",
            border_style=BORDER_STYLE,
            box=box.MINIMAL,
            padding=(0, 1),
        )
    )
