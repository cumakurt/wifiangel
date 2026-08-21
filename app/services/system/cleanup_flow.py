"""Cleanup helpers for auto-hack/process termination."""

from __future__ import annotations


_AUTO_HACK_PROCESSES = (
    "airodump-ng",
    "aireplay-ng",
    "hcxdumptool",
    "hashcat",
    "aircrack-ng",
)


def run_auto_hack_cleanup(app) -> None:
    """Stop capture/crack children started by the automated workflow."""
    try:
        runner = getattr(app, "command_runner", None)
        if runner is not None:
            runner.kill_processes(_AUTO_HACK_PROCESSES)
        app.logger.info("Auto hack cleanup completed")
    except Exception as exc:
        app.logger.error(f"Error during cleanup: {str(exc)}")


def run_kill_processes(app, process_names) -> None:
    """Kill specific process names with graceful then forced termination."""
    runner = getattr(app, "command_runner", None)
    if runner is None:
        return
    runner.kill_processes(process_names)
