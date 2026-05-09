"""Hidden SSID discovery service (airodump-ng CSV, same pipeline as main scan)."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.table import Table

from attacks.commands import airodump_network_discovery
from app.ui import BORDER_STYLE
from config import TMP_DIR
from wifi.airodump_csv import (
    ap_row_to_network_fields,
    parse_airodump_csv,
    probed_essids_by_bssid,
    station_client_counts,
)


def run_hidden_ssid_discovery(app) -> None:
    """Discover hidden SSIDs using the same passive discovery path as the main network scan."""
    was_in_monitor_mode = app.interface_name.endswith("mon")

    if not was_in_monitor_mode:
        app.console.print("[bold blue]Interface is not in monitor mode, switching to monitor mode...[/]")
        if not app.start_monitor_mode():
            app.console.print("[bold red]Failed to enable monitor mode! Aborting.[/]")
            return
        app.console.print(f"[bold green]Successfully switched to monitor mode: {app.interface_name}[/]")

    # bssid -> state (APs that were or still are hidden in airodump CSV)
    hidden_networks: dict[str, dict] = {}
    stop_event = threading.Event()
    start_time = time.time()

    tmp = Path(TMP_DIR)
    tmp.mkdir(parents=True, exist_ok=True)
    prefix = tmp / f"wa_hidden_{os.getpid()}_{threading.get_ident()}_{int(time.time() * 1000)}"
    csv_path = Path(f"{prefix}-01.csv")
    argv = airodump_network_discovery(app.interface_name, prefix, write_interval=1)
    proc: Optional[subprocess.Popen] = None

    app.console.print("[bold blue]Starting Hidden SSID Discovery...[/]")
    app.console.print("[info]Using airodump-ng passive scan (same as main menu scan: --band abg, --wps, CSV).[/]")
    app.console.print("[warning]Press Ctrl+C at any time to stop the scanning process.[/]")
    app.console.print("[bold yellow]Watching for hidden ESSID rows, client probes, and ESSID updates in CSV...[/]")

    def _merge_probes(state: dict, new_names: set[str]) -> None:
        probes: list[str] = state["probes"]
        for name in sorted(new_names):
            if name and name not in probes:
                probes.append(name)

    def create_status_table():
        table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.MINIMAL,
            border_style=BORDER_STYLE,
            title="[bold blue]Hidden SSID Discovery[/]",
        )
        table.add_column("BSSID", style="cyan")
        table.add_column("Channel", style="green")
        table.add_column("Signal", style="blue")
        table.add_column("Clients", style="magenta")
        table.add_column("Encryption", style="red")
        table.add_column("Probes / leaked SSID", style="yellow")

        for bssid, data in hidden_networks.items():
            leak = data.get("broadcast_ssid")
            parts = list(data["probes"])
            if leak:
                parts = [leak] + [p for p in parts if p != leak]
            probes_text = "\n".join(parts[-5:]) if parts else "No probes yet"
            enc = data["encryption"]
            if data.get("wps"):
                enc = f"{enc} [WPS]"
            table.add_row(
                bssid,
                str(data["channel"]),
                f"{data['signal']} dBm",
                str(len(data["clients"])),
                enc,
                probes_text,
            )
        return table

    def _poll_csv() -> None:
        if not csv_path.is_file():
            return
        try:
            aps, stas = parse_airodump_csv(csv_path)
            by_clients = station_client_counts(stas)
            probed_map = probed_essids_by_bssid(stas)
            now = datetime.now()
            for ap in aps:
                fields = ap_row_to_network_fields(ap)
                if not fields:
                    continue
                bssid = fields["bssid"]
                ssid_val = fields["ssid"]
                ch = int(fields["channel"] or 0)
                sig = int(fields["signal"])
                cipher_str = str(fields["cipher"])
                wps = bool(fields["wps"])

                if ssid_val == "<Hidden Network>":
                    if bssid not in hidden_networks:
                        hidden_networks[bssid] = {
                            "channel": ch if ch > 0 else 0,
                            "signal": sig,
                            "encryption": cipher_str,
                            "wps": wps,
                            "clients": set(by_clients.get(bssid, ())),
                            "probes": [],
                            "broadcast_ssid": None,
                            "first_seen": now,
                            "last_seen": now,
                        }
                    else:
                        st = hidden_networks[bssid]
                        st["last_seen"] = now
                        st["signal"] = sig
                        st["encryption"] = cipher_str
                        st["wps"] = wps or st.get("wps", False)
                        if ch > 0:
                            st["channel"] = ch
                        st["clients"].update(by_clients.get(bssid, ()))
                elif bssid in hidden_networks:
                    st = hidden_networks[bssid]
                    st["last_seen"] = now
                    st["signal"] = sig
                    st["encryption"] = cipher_str
                    st["wps"] = wps or st.get("wps", False)
                    if ch > 0:
                        st["channel"] = ch
                    st["clients"].update(by_clients.get(bssid, ()))
                    if ssid_val and ssid_val != "<Hidden Network>":
                        st["broadcast_ssid"] = ssid_val

            for bssid in list(hidden_networks.keys()):
                st = hidden_networks[bssid]
                st["clients"].update(by_clients.get(bssid, ()))
                _merge_probes(st, probed_map.get(bssid, set()))
        except Exception as exc:
            app.logger.error(f"Hidden SSID CSV merge error: {exc}")

    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        while not stop_event.is_set():
            try:
                elapsed = int(time.time() - start_time)
                minutes = elapsed // 60
                seconds = elapsed % 60
                duration = f"{minutes:02d}:{seconds:02d}"
                os.system("clear" if os.name != "nt" else "cls")
                app.console.print(f"[bold blue]Hidden SSID Discovery - Duration: {duration}[/]")
                app.console.print(f"[bold yellow]Tracking {len(hidden_networks)} hidden / previously hidden AP(s)[/]")
                app.console.print("[bold red]Press Ctrl+C to stop scanning and return to the main menu[/]")
                if proc.poll() is not None:
                    app.logger.error(f"airodump-ng exited unexpectedly (code {proc.returncode})")
                    app.console.print("[bold red]airodump-ng stopped unexpectedly.[/]")
                    break

                _poll_csv()

                if hidden_networks:
                    app.console.print(create_status_table())
                else:
                    app.console.print("[bold yellow]No hidden ESSID rows yet — airodump-ng is scanning (--band abg)...[/]")

                time.sleep(1.05)
            except KeyboardInterrupt:
                app.console.print("\n[bold yellow]Stopping Hidden SSID discovery (Ctrl+C pressed)...[/]")
                stop_event.set()
                break
    except KeyboardInterrupt:
        app.console.print("\n[bold yellow]Stopping Hidden SSID discovery (Ctrl+C pressed)...[/]")
        stop_event.set()
    finally:
        stop_event.set()
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            for p in prefix.parent.glob(prefix.name + "*"):
                p.unlink(missing_ok=True)
        except OSError:
            pass

        if hidden_networks:
            app.console.print("\n[bold green]Hidden Networks Found:[/]")
            final_table = Table(
                show_header=True,
                header_style="bold magenta",
                box=box.MINIMAL,
                border_style=BORDER_STYLE,
                title="[bold blue]Hidden Network Discovery Results[/]",
            )
            final_table.add_column("BSSID", style="cyan")
            final_table.add_column("Channel", style="green")
            final_table.add_column("Signal", style="blue")
            final_table.add_column("Encryption", style="red")
            final_table.add_column("Discovered SSIDs", style="yellow")
            final_table.add_column("Connected Clients", style="magenta")

            for bssid, data in hidden_networks.items():
                leak = data.get("broadcast_ssid")
                probe_lines = list(data["probes"])
                if leak:
                    summary = leak
                    if probe_lines:
                        rest = "\n".join(p for p in probe_lines if p != leak)
                        if rest:
                            summary = f"{summary}\n(probes)\n{rest}"
                else:
                    summary = "\n".join(probe_lines) if probe_lines else "No SSIDs discovered"
                clients_text = "\n".join(list(data["clients"])[:5]) if data["clients"] else "None detected"
                if len(data["clients"]) > 5:
                    clients_text += f"\n... and {len(data['clients']) - 5} more"
                enc = data["encryption"]
                if data.get("wps"):
                    enc = f"{enc} [WPS]"
                final_table.add_row(
                    bssid,
                    str(data["channel"]),
                    f"{data['signal']} dBm",
                    enc,
                    summary,
                    clients_text,
                )
            app.console.print(final_table)

            total_duration = int(time.time() - start_time)
            minutes = total_duration // 60
            seconds = total_duration % 60
            app.console.print(f"\n[bold green]Scan completed in {minutes:02d}:{seconds:02d}[/]")
            app.console.print(f"[bold green]Tracked {len(hidden_networks)} hidden / de-hidden AP(s)[/]")
            hint_total = 0
            for d in hidden_networks.values():
                names = set(d["probes"])
                if d.get("broadcast_ssid"):
                    names.add(d["broadcast_ssid"])
                hint_total += len(names)
            app.console.print(f"[bold green]Collected {hint_total} unique SSID hint(s) from CSV (ESSID column + probed ESSIDs)[/]")
        else:
            app.console.print("\n[bold yellow]No hidden networks discovered.[/]")

        if not was_in_monitor_mode:
            app.console.print("\n[bold blue]Switching back to managed mode...[/]")
            try:
                subprocess.run(
                    ["airmon-ng", "stop", app.interface_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if app.interface_name.endswith("mon"):
                    app.interface_name = app.interface_name[:-3]
                subprocess.run(["ip", "link", "set", app.interface_name, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iw", app.interface_name, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["ip", "link", "set", app.interface_name, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["systemctl", "restart", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                app.console.print(f"[bold green]Successfully switched back to managed mode: {app.interface_name}[/]")
                app.logger.info(f"Switched back to managed mode: {app.interface_name}")
            except Exception as exc:
                app.console.print(f"[bold red]Error switching back to managed mode: {str(exc)}[/]")
                app.logger.error(f"Error switching back to managed mode: {str(exc)}")

        app.current_menu = "tools"
