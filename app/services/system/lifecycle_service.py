"""Application lifecycle services."""

from __future__ import annotations

import sys


def cleanup_and_exit(app) -> None:
    """Perform cleanup before exiting the application."""
    app.scanning = False
    app.console.print("[bold yellow]Performing cleanup...[/]")
    app.logger.info("Cleanup process started")

    try:
        iface = getattr(app, "interface_name", None)
        if iface:
            app.interface_name = app.wifi_adapter.set_managed_mode(iface)
            app.logger.info(f"{app.interface_name} switched to managed mode")
        app.console.print("[bold green]Cleanup completed.[/]")
        app.logger.info("Cleanup completed")
    except Exception as exc:
        app.logger.error(f"Error during cleanup: {str(exc)}")
        app.console.print(f"[bold red]Error during cleanup: {str(exc)}[/]")

    sys.exit(0)
