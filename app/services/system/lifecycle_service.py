"""Application lifecycle services."""

from __future__ import annotations

import sys
import time

from cleanup import remove_evil_twin_nat, remove_mitm_nat

_SCAN_TEARDOWN_SECONDS = 1.5


def cleanup_and_exit(app, exit_code: int = 0) -> None:
    """Stop scan children, drop lab NAT, restore managed mode, then exit."""
    was_scanning = bool(getattr(app, "scanning", False))
    app.scanning = False
    app.console.print("[bold yellow]Performing cleanup...[/]")
    app.logger.info("Cleanup process started")

    if was_scanning:
        time.sleep(_SCAN_TEARDOWN_SECONDS)

    try:
        remove_evil_twin_nat()
    except Exception as exc:
        app.logger.error(f"Error removing Evil Twin NAT during exit: {exc}")

    try:
        remove_mitm_nat(out_iface=getattr(app, "_mitm_out_iface", None))
    except Exception as exc:
        app.logger.error(f"Error removing MITM NAT during exit: {exc}")

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

    sys.exit(int(exit_code))
