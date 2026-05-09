"""Bluetooth and IoT scanning service."""

from __future__ import annotations

import asyncio
import ipaddress
import subprocess
import time
from datetime import datetime

from rich import box
from rich.console import Group
from rich.live import Live
from rich.prompt import Prompt
from rich.table import Table

from app.ui import BORDER_STYLE

try:
    from bleak import BleakScanner
except ImportError:  # Optional dependency for BLE scanning only.
    BleakScanner = None

try:
    from zeroconf import ServiceBrowser, Zeroconf
except ImportError:  # Optional dependency for mDNS IoT discovery only.
    ServiceBrowser = None
    Zeroconf = None


def run_bluetooth_iot_scanner(app) -> None:
    """Scan for Bluetooth and IoT devices."""
    app.console.clear()
    app.create_header()

    menu = """
        [bold cyan]Bluetooth & IoT Scanner[/]

        1. BLE device scanner
        2. IoT service discovery (mDNS)
        0. Back to tools menu
        """
    app.console.print(menu)

    choice = input("\nEnter your choice (0-2): ")

    if choice == "1":
        if BleakScanner is None:
            app.console.print("[bold red]BLE scanning requires the `bleak` package.[/]")
            app.console.print("[yellow]Install with:[/] [white]pip install bleak[/]")
            return

        async def scan_ble_devices():
            devices = {}
            start_time = time.time()
            scan_duration = 60

            def get_device_type(manufacturer_data, name):
                if not manufacturer_data and not name:
                    return "Unknown"
                if 76 in manufacturer_data:
                    if "AirPods" in name:
                        return "AirPods"
                    if "Watch" in name:
                        return "Apple Watch"
                    if "iPhone" in name:
                        return "iPhone"
                    return "Apple Device"

                manufacturer_types = {
                    6: "Microsoft Device",
                    117: "Samsung Device",
                    34819: "Govee Device",
                    89: "Intel Device",
                    10: "Nordic Semiconductor",
                    211: "Fitbit Device",
                }
                for mfg_id in manufacturer_data.keys():
                    if mfg_id in manufacturer_types:
                        return manufacturer_types[mfg_id]

                name_lower = name.lower()
                if "speaker" in name_lower:
                    return "Bluetooth Speaker"
                if "headphone" in name_lower or "buds" in name_lower:
                    return "Headphones"
                if "watch" in name_lower:
                    return "Smartwatch"
                if "car" in name_lower:
                    return "Car System"
                if "tv" in name_lower:
                    return "Smart TV"
                if "mouse" in name_lower:
                    return "Mouse"
                if "keyboard" in name_lower:
                    return "Keyboard"
                return "Unknown BLE Device"

            def detection_callback(device, advertising_data):
                device_type = get_device_type(advertising_data.manufacturer_data, device.name or "")
                devices[device.address] = {
                    "name": device.name or "Unknown",
                    "rssi": advertising_data.rssi if advertising_data.rssi else "N/A",
                    "manufacturer_data": advertising_data.manufacturer_data,
                    "type": device_type,
                    "first_seen": datetime.now().strftime("%H:%M:%S"),
                }

            def create_status_table():
                table = Table(
                    show_header=True,
                    header_style="bold magenta",
                    box=box.MINIMAL,
                    border_style=BORDER_STYLE,
                    title="[bold cyan]Discovered BLE Devices[/]",
                )
                table.add_column("MAC Address", style="cyan")
                table.add_column("Name", style="green")
                table.add_column("Device Type", style="blue")
                table.add_column("RSSI (dBm)", style="yellow")
                table.add_column("First Seen", style="magenta")
                for addr, dev in sorted(devices.items(), key=lambda x: x[1]["first_seen"]):
                    table.add_row(addr, dev["name"], dev["type"], str(dev["rssi"]), dev["first_seen"])
                elapsed = int(time.time() - start_time)
                remaining = max(scan_duration - elapsed, 0)
                time_info = f"\n[bold yellow]Scan Time: {elapsed}s / {scan_duration}s (Remaining: {remaining}s)[/]"
                return Group(table, time_info)

            try:
                app.console.print("\n[info]Starting BLE scan (60 seconds)...[/]")
                app.console.print("[yellow]Press Ctrl+C to stop scanning[/]")
                async with BleakScanner(detection_callback=detection_callback):
                    with Live(create_status_table(), refresh_per_second=2) as live:
                        while (time.time() - start_time) < scan_duration:
                            live.update(create_status_table())
                            await asyncio.sleep(0.5)
                app.console.print("\n[success]Scan completed.[/]")
                if devices:
                    app.console.print(create_status_table())
                else:
                    app.console.print("\n[yellow]No BLE devices found[/]")
            except KeyboardInterrupt:
                app.console.print("\n[bold yellow]Scan stopped by user![/]")
                if devices:
                    app.console.print(create_status_table())
                else:
                    app.console.print("\n[yellow]No BLE devices found[/]")
            except Exception as exc:
                app.console.print(f"\n[bold red]Error during BLE scan: {str(exc)}[/]")

        try:
            asyncio.run(scan_ble_devices())
        except KeyboardInterrupt:
            pass

    elif choice == "2":
        if Zeroconf is None or ServiceBrowser is None:
            app.console.print("[bold red]IoT discovery requires the `zeroconf` package.[/]")
            app.console.print("[yellow]Install with:[/] [white]pip install zeroconf[/]")
            return
        try:
            iw_info = subprocess.check_output(["iwconfig", app.interface_name]).decode()
            if "Mode:Monitor" in iw_info:
                app.console.print("[warning]Interface is in monitor mode. Switching to managed mode...[/]")
                subprocess.run(["airmon-ng", "stop", app.interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                app.interface_name = app.interface_name.replace("mon", "")
                subprocess.run(["ip", "link", "set", app.interface_name, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iw", app.interface_name, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["ip", "link", "set", app.interface_name, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["systemctl", "restart", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2)
                app.console.print("[success]Interface switched to managed mode[/]")
        except Exception as exc:
            app.console.print(f"[bold red]Error checking interface mode: {str(exc)}[/]")
            return

        try:
            ip_info = subprocess.check_output(["ip", "route", "show"]).decode()
            default_network = None
            for line in ip_info.split("\n"):
                if "default via" in line:
                    parts = line.split()
                    interface = parts[4]
                    ip_addr = subprocess.check_output(["ip", "addr", "show", interface]).decode()
                    for addr_line in ip_addr.split("\n"):
                        if "inet " in addr_line:
                            network = addr_line.split()[1].split("/")[0]
                            default_network = ".".join(network.split(".")[:-1]) + ".0/24"
                            break
                    break
        except Exception:
            default_network = "192.168.1.0/24"

        app.console.print(f"\n[bold cyan]Current Network: {default_network}[/]")
        ip_block = Prompt.ask("Enter IP block to scan (e.g., 192.168.1.0/24)", default=default_network)
        try:
            ipaddress.ip_network(ip_block, strict=False)
        except ValueError:
            app.console.print("[bold red]Invalid IP block format! Using default network.[/]")
            ip_block = default_network

        class IoTListener:
            def __init__(self, console, target_network):
                self.console = console
                self.discovered_services = {}
                self.target_network = ipaddress.ip_network(target_network, strict=False)
                self.start_time = time.time()
                self.scan_duration = 15

            def add_service(self, zc, type_, name):
                info = zc.get_service_info(type_, name)
                if not info:
                    return
                addresses = info.parsed_addresses()
                valid_addresses = []
                for addr in addresses:
                    try:
                        if ipaddress.ip_address(addr) in self.target_network:
                            valid_addresses.append(addr)
                    except Exception:
                        continue
                if valid_addresses:
                    self.discovered_services[name] = {
                        "type": type_,
                        "addresses": valid_addresses,
                        "port": info.port,
                        "server": info.server if hasattr(info, "server") else "Unknown",
                        "properties": {
                            k.decode(): v.decode() if isinstance(v, bytes) else v for k, v in info.properties.items()
                        }
                        if info.properties
                        else {},
                        "first_seen": datetime.now().strftime("%H:%M:%S"),
                    }

                table = Table(
                    show_header=True,
                    header_style="bold magenta",
                    box=box.MINIMAL,
                    border_style=BORDER_STYLE,
                    title=f"[bold cyan]Discovered IoT Services in {self.target_network}[/]",
                )
                table.add_column("Name", style="cyan")
                table.add_column("Type", style="green")
                table.add_column("IP Addresses", style="yellow")
                table.add_column("Port", style="blue")
                table.add_column("First Seen", style="magenta")
                for service_name, service in sorted(self.discovered_services.items(), key=lambda x: x[1]["first_seen"]):
                    table.add_row(
                        service_name,
                        service["type"],
                        "\n".join(service["addresses"]),
                        str(service["port"]),
                        service["first_seen"],
                    )
                elapsed = int(time.time() - self.start_time)
                remaining = max(self.scan_duration - elapsed, 0)
                time_info = f"\n[bold yellow]Scan Time: {elapsed}s / {self.scan_duration}s (Remaining: {remaining}s)[/]"
                self.console.clear()
                self.console.print(f"\n[info]Scanning for IoT services in {self.target_network}...[/]")
                self.console.print(Group(table, time_info))

            def update_service(self, zc, type_, name):
                self.add_service(zc, type_, name)

            def remove_service(self, zc, type_, name):
                if name in self.discovered_services:
                    del self.discovered_services[name]

        zeroconf = Zeroconf()
        listener = IoTListener(app.console, ip_block)
        service_types = [
            "_http._tcp.local.",
            "_https._tcp.local.",
            "_ipp._tcp.local.",
            "_printer._tcp.local.",
            "_airplay._tcp.local.",
            "_spotify-connect._tcp.local.",
            "_googlecast._tcp.local.",
            "_hue._tcp.local.",
            "_homekit._tcp.local.",
            "_smb._tcp.local.",
            "_mqtt._tcp.local.",
            "_nest-camera._tcp.local.",
            "_sonos._tcp.local.",
            "_raop._tcp.local.",
        ]
        try:
            app.console.print(f"\n[info]Starting IoT service discovery in {ip_block}...[/]")
            app.console.print("[yellow]Press Ctrl+C to stop scanning[/]")
            _ = [ServiceBrowser(zeroconf, service_type, listener) for service_type in service_types]
            start_time = time.time()
            try:
                while (time.time() - start_time) < 15:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                app.console.print("\n[bold yellow]Scan stopped by user![/]")
            if listener.discovered_services:
                app.console.print("\n[success]Scan completed.[/]")
            else:
                app.console.print("\n[yellow]No IoT services found in the specified network.[/]")
        except Exception as exc:
            app.console.print(f"\n[bold red]Error during IoT scan: {str(exc)}[/]")
        finally:
            zeroconf.close()

    elif choice == "0":
        return
