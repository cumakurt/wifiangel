"""Bootstrap services for WiFiAngel startup."""

from __future__ import annotations

import sys

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt

from app.ui import BORDER_STYLE


def initialize_adapter(app, required_binaries) -> None:
    """Validate tools, select wireless interface and set adapter state."""
    try:
        required_tools = list(required_binaries)
        missing_tools = app.wifi_adapter.missing_tools(required_tools)

        if missing_tools:
            app.console.print(f"[bold red]Missing required tools: {', '.join(missing_tools)}[/]")
            app.console.print("[yellow]Please install the missing tools using:[/]")
            app.console.print("[white]sudo apt install aircrack-ng hashcat hcxdumptool[/]")
            sys.exit(1)

        wifi_interfaces = app.wifi_adapter.list_wireless_interfaces()
        if not wifi_interfaces:
            app.console.print(
                "[bold red]No Wi-Fi interfaces were detected.[/]\n"
                "[yellow]Checks:[/]\n"
                " • Is this a VM? Pass the USB Wi-Fi dongle or PCI device through to the guest.\n"
                " • Run [white]ip link[/] and [white]iw dev[/] — you should see a [white]wlan*[/] device.\n"
                " • Optional: [white]sudo apt install wireless-tools[/] if [white]iwconfig[/] is missing.\n"
                " • Some containers/WSL environments do not expose wireless hardware."
            )
            raise RuntimeError("No wireless network adapter found (see messages above).")

        if len(wifi_interfaces) > 1:
            app.console.print()
            rows = "\n".join(
                f"  [menu.key]{i:>2}[/]  [cyan]{iface}[/]"
                for i, iface in enumerate(wifi_interfaces, 1)
            )
            app.console.print(
                Panel(
                    rows,
                    title="[title]Select wireless interface[/]",
                    border_style=BORDER_STYLE,
                    box=box.MINIMAL,
                    padding=(1, 2),
                )
            )
            choice = Prompt.ask(
                "[heading]Interface #[/]",
                choices=[str(i) for i in range(1, len(wifi_interfaces) + 1)],
            )
            app.interface_name = wifi_interfaces[int(choice) - 1]
        else:
            app.interface_name = wifi_interfaces[0]

        app.console.print(f"[success]OK[/] [meta]Adapter ready[/]  [cyan]{app.interface_name}[/]")
        app.logger.info(f"WiFi adapter initialized: {app.interface_name}")
    except Exception as exc:
        app.logger.error(f"Could not initialize WiFi adapter: {str(exc)}")
        app.console.print(f"[bold red]Could not initialize WiFi adapter: {str(exc)}[/]")
        sys.exit(1)
