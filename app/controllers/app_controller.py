"""Top-level application controller loop."""

from __future__ import annotations


def run_application_loop(app) -> None:
    """Run main menu loop and handle top-level interrupts."""
    try:
        while True:
            try:
                app.show_main_menu()
            except KeyboardInterrupt:
                if app.current_menu == "main":
                    app.logger.info("Program shutting down...")
                    app.cleanup_and_exit()
                else:
                    app.logger.info("Returning to main menu")
                    app.console.print("\n[bold yellow]Returning to main menu...[/]")
                    app.current_menu = "main"
                    continue
    except Exception as exc:
        app.logger.error(f"Unexpected error: {str(exc)}")
        app.cleanup_and_exit()
