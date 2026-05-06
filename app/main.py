"""CLI entry: environment checks then interactive app."""

from __future__ import annotations

from rich.console import Console

from config import (
    check_os,
    check_required_packages,
    check_root,
    ensure_runtime_dirs,
    warn_optional_missing_tools,
)

from .wifi_angel import WiFiAngel


def main() -> None:
    console = Console()
    check_root(console)
    check_os(console)
    check_required_packages(console)
    ensure_runtime_dirs()
    warn_optional_missing_tools(console)

    wifi_angel = WiFiAngel()
    wifi_angel.run()
