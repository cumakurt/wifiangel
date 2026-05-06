"""Smoke tests for TUI components (no terminal required)."""

from __future__ import annotations

from rich.console import Console

from app.ui import TUI_THEME, create_scan_results_table, render_menu_panel, render_welcome_banner


def test_render_welcome_banner_no_exception():
 c = Console(theme=TUI_THEME, record=True, width=80, height=40)
 render_welcome_banner(c, author_line="Test", url_line="https://example.test")
 assert len(c.export_text()) > 10


def test_render_menu_panel_no_exception():
 c = Console(theme=TUI_THEME, record=True, width=80)
 render_menu_panel(
 c,
 heading="Test menu",
 intro_lines=["[meta]Hint[/]"],
 items=[("1", "One"), ("0", "Back")],
 )
 assert "Test menu" in c.export_text()


def test_create_scan_table_columns():
 t = create_scan_results_table()
 t.add_row("1", "aa:bb", "ssid", "6", "WPA2", "-45", "2")
 c = Console(theme=TUI_THEME, record=True, width=120)
 c.print(t)
 assert "aa:bb" in c.export_text()
