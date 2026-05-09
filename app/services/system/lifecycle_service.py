"""Application lifecycle services."""

from __future__ import annotations

import subprocess
import sys
import time


def cleanup_and_exit(app) -> None:
    """Perform cleanup before exiting the application."""
    app.scanning = False
    app.console.print("[bold yellow]Performing cleanup...[/]")
    app.logger.info("Cleanup process started")

    try:
        subprocess.run(["airmon-ng", "stop", app.interface_name], stdout=subprocess.PIPE)
        app.logger.info(f"{app.interface_name} switched to managed mode")
        time.sleep(1)
        subprocess.run(["systemctl", "start", "NetworkManager"], stdout=subprocess.PIPE)
        app.logger.info("NetworkManager started")
        app.console.print("[bold green]Cleanup completed.[/]")
        app.logger.info("Cleanup completed")
    except Exception as exc:
        app.logger.error(f"Error during cleanup: {str(exc)}")
        app.console.print(f"[bold red]Error during cleanup: {str(exc)}[/]")

    sys.exit(0)
