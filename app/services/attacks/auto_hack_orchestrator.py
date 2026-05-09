"""Auto-hack orchestration service."""

from __future__ import annotations

import concurrent.futures
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html import escape

from rich import box
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from adapters.system_tools import managed_name_from_monitor
from config import AUTO_HACK_SESSIONS_DIR, DEFAULT_WORDLIST, ROCKYOU_WORDLIST


def run_auto_hack(app) -> None:
    """Automated wireless assessment orchestration for discovered networks."""
    try:
        app.console.print("[info]Starting automated assessment...[/]")
        app.logger.info("Automated assessment mode initiated")
        session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = AUTO_HACK_SESSIONS_DIR / session_timestamp
        session_dir.mkdir(parents=True, exist_ok=True)
        app.logger.info(f"Session directory created at {session_dir}")

        report_file = session_dir / "auto_hack_report.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("WiFiAngel Automated Assessment Report\n")
            f.write(f"Session: {session_timestamp}\n")
            f.write(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        app.console.print("[bold blue]1. Enabling Monitor Mode...[/]")
        try:
            mon = app.wifi_adapter.find_monitor_interface()
            cur_iface_type = app.wifi_adapter.get_interface_type(app.interface_name)
            if cur_iface_type == "monitor":
                app.console.print(f"[success]Already in monitor mode: {app.interface_name}[/]")
                app.logger.info(f"Already in monitor mode: {app.interface_name}")
            elif mon:
                app.interface_name = mon
                app.console.print(f"[success]Using monitor interface: {app.interface_name}[/]")
                app.logger.info(f"Using monitor interface: {app.interface_name}")
            else:
                base = managed_name_from_monitor(app.interface_name)
                app.interface_name = app.wifi_adapter.start_monitor_mode(base)
                app.console.print(f"[success]Monitor mode enabled on {app.interface_name}[/]")
                app.logger.info(f"Monitor mode enabled on {app.interface_name}")
                time.sleep(2)
            with open(report_file, "a", encoding="utf-8") as f:
                f.write(f"Interface: {app.interface_name} (Monitor Mode)\n")
        except Exception as exc:
            app.logger.error(f"Automated assessment monitor mode failed: {exc}")
            app.console.print(f"[bold red]Could not enable monitor mode: {exc}[/]")
            return

        app.console.print("[bold blue]2. Network discovery via airodump-ng (60 seconds, same as menu scan)...[/]")
        if not hasattr(app, "_networks_lock"):
            app._networks_lock = threading.Lock()
        with app._networks_lock:
            app.networks.clear()
        app.scanning = True
        scan_thread = threading.Thread(target=app.scan_networks, daemon=True)
        scan_thread.start()

        scan_time = 60
        scan_start_time = time.time()
        app.console.print("[info]Live network table is active during discovery.[/]")
        for _ in range(scan_time):
            if not app.scanning:
                break
            time.sleep(1)

        scan_duration = time.time() - scan_start_time
        app.scanning = False
        scan_thread.join(timeout=3)

        network_count = len(app.networks)
        clients_count = sum(len(network["clients"]) for network in app.networks.values())
        app.console.print(f"[success]Scan completed. Found {network_count} networks and {clients_count} clients.[/]")
        if network_count > 0:
            networks_table = Table(show_header=True, header_style="bold blue", box=box.MINIMAL, border_style="cyan", title="[bold green]Discovered Networks[/]")
            networks_table.add_column("SSID", style="cyan")
            networks_table.add_column("BSSID", style="green")
            networks_table.add_column("Channel", style="blue", justify="center")
            networks_table.add_column("Security", style="yellow")
            networks_table.add_column("Signal", style="magenta", justify="center")
            networks_table.add_column("Clients", style="red", justify="center")
            sorted_networks = sorted(app.networks.items(), key=lambda x: x[1]["signal"], reverse=True)
            for bssid, network in sorted_networks:
                networks_table.add_row(
                    network["ssid"], bssid, str(network["channel"]), network["cipher"], str(network["signal"]), str(len(network["clients"]))
                )
            app.console.print(networks_table)

        app.logger.info(f"Network scan completed in {scan_duration:.2f} seconds")
        app.logger.info(f"Found {len(app.networks)} networks")
        with open(report_file, "a", encoding="utf-8") as f:
            f.write(f"Scan Duration: {scan_duration:.2f} seconds\n")
            f.write(f"Total Networks Found: {len(app.networks)}\n\n")
            f.write("Network Details:\n")
            for bssid, network in app.networks.items():
                f.write(f"- {network['ssid']} ({bssid}):\n")
                f.write(f"  Channel: {network['channel']}\n")
                f.write(f"  Security: {network['cipher']}\n")
                f.write(f"  Signal: {network['signal']}\n")
                f.write(f"  Clients: {len(network['clients'])}\n")
                if network["clients"]:
                    f.write(f"  Client MACs: {', '.join(network['clients'])}\n")
                f.write("\n")

        if not app.networks:
            app.console.print("[error]No networks found. Check your WiFi adapter.[/]")
            app.logger.error("No networks found during scan")
            with open(report_file, "a", encoding="utf-8") as f:
                f.write("ERROR: No networks found during scan\n")
            return

        app.console.print("[bold blue]3. Prioritizing Target Networks...[/]")
        scored_networks = []
        for bssid, network in app.networks.items():
            score = len(network["clients"]) * 20
            signal_strength = abs(network["signal"])
            score += 15 if signal_strength < 60 else 10 if signal_strength < 70 else 5
            if "WEP" in network["cipher"]:
                score += 30
            elif "WPA" in network["cipher"] and "WPA2" not in network["cipher"]:
                score += 20
            elif "WPA2" in network["cipher"]:
                score += 15
            elif "WPA3" in network["cipher"]:
                score += 25
            if network.get("wps", False):
                score += 20
            scored_networks.append((bssid, network, score))
        scored_networks.sort(key=lambda x: x[2], reverse=True)

        priority_table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style="cyan", title="[bold blue]Target Networks (Prioritized)[/]")
        priority_table.add_column("Priority", style="cyan", justify="center")
        priority_table.add_column("Network", style="green")
        priority_table.add_column("Score", style="yellow", justify="center")
        priority_table.add_column("Clients", style="blue", justify="center")
        priority_table.add_column("Security", style="magenta")
        display_networks = min(20, len(scored_networks))
        for i, (bssid, network, score) in enumerate(scored_networks[:display_networks], 1):
            priority_table.add_row(str(i), f"{network['ssid']} ({bssid})", str(score), str(len(network["clients"])), network["cipher"])
        app.console.print(priority_table)

        app.console.print("\n[bold blue]Network Selection[/]")
        selected_networks_input = Prompt.ask("[bold green]Select networks to assess", default="")

        selected_indices = []
        if not selected_networks_input.strip():
            app.console.print("[warning]No networks selected. Automated assessment cancelled.[/]")
            app._auto_hack_cleanup()
            return
        if selected_networks_input.lower() != "all":
            try:
                input_indices = [int(idx.strip()) for idx in selected_networks_input.split(",") if idx.strip()]
                selected_indices = [idx for idx in input_indices if 1 <= idx <= display_networks]
                if not selected_indices:
                    app.console.print("[warning]No valid networks selected. Automated assessment cancelled.[/]")
                    app._auto_hack_cleanup()
                    return
                else:
                    app.console.print(f"[bold green]Selected {len(selected_indices)} networks for assessment.[/]")
            except ValueError:
                app.console.print("[warning]Invalid selection. Automated assessment cancelled.[/]")
                app._auto_hack_cleanup()
                return
        else:
            app.console.print("[bold green]Selected all displayed networks for assessment.[/]")
            selected_indices = list(range(1, display_networks + 1))

        app.logger.info(f"Target networks prioritized: {len(scored_networks)} networks ranked")
        app.logger.info(f"User selected {len(selected_indices)} networks for assessment")
        with open(report_file, "a", encoding="utf-8") as f:
            f.write("Prioritized Targets:\n")
            for i, (bssid, network, score) in enumerate(scored_networks, 1):
                selected_mark = " [SELECTED]" if i in selected_indices else ""
                f.write(f"{i}. {network['ssid']} ({bssid}) - Score: {score}{selected_mark}\n")
            f.write("\n")

        networks_with_clients = []
        for i, (bssid, network, _score) in enumerate(scored_networks, 1):
            if i not in selected_indices and selected_indices:
                continue
            try:
                if not isinstance(network, dict):
                    app.logger.warning(f"Invalid network data for {bssid}: not a dictionary")
                    continue
                validated_network = {
                    "ssid": str(network.get("ssid", "Unknown")),
                    "channel": int(network.get("channel", 1)) if str(network.get("channel", 1)).isdigit() else 1,
                    "cipher": str(network.get("cipher", "Unknown")),
                    "signal": int(network.get("signal", 0)) if str(network.get("signal", 0)).lstrip("-").isdigit() else 0,
                }
                clients = network.get("clients", set())
                if not isinstance(clients, set):
                    clients = set(clients) if clients else set()
                validated_network["clients"] = clients
                if validated_network["clients"]:
                    networks_with_clients.append((bssid, validated_network))
                    app.logger.debug(f"Validated network data for {validated_network['ssid']} ({bssid})")
                else:
                    app.logger.debug(f"Skipping network {validated_network['ssid']} ({bssid}): no clients")
            except Exception as exc:
                app.logger.error(f"Error validating network {bssid}: {str(exc)}")
                continue

        if not networks_with_clients:
            app.console.print("[error]No networks with connected clients. Active assessment requires observed clients.[/]")
            app.logger.error("No networks with connected clients")
            with open(report_file, "a", encoding="utf-8") as f:
                f.write("ERROR: No networks with connected clients found\n")
            app._auto_hack_cleanup()
            return

        app.console.print(f"[bold green]Found {len(networks_with_clients)} networks with active clients.[/]")
        app.logger.info(f"Found {len(networks_with_clients)} networks with active clients")
        with open(report_file, "a", encoding="utf-8") as f:
            f.write("\nValidated Networks:\n")
            for bssid, network in networks_with_clients:
                f.write(f"- {network['ssid']} ({bssid}):\n")
                f.write(f"  Channel: {network['channel']}\n")
                f.write(f"  Security: {network['cipher']}\n")
                f.write(f"  Clients: {len(network['clients'])}\n")
                f.write(f"  Signal: {network['signal']}\n\n")

        results_table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style="cyan", title="[bold blue]Assessment Results[/]")
        results_table.add_column("Network", style="cyan")
        results_table.add_column("Status", style="yellow", width=40)
        results_table.add_column("Handshake", style="green")
        results_table.add_column("PMKID", style="blue")
        results_table.add_column("Password", style="magenta")

        wordlist = str(DEFAULT_WORDLIST)
        if not os.path.exists(wordlist):
            wordlist_alt = str(ROCKYOU_WORDLIST)
            if os.path.exists(wordlist_alt):
                wordlist = wordlist_alt
                app.console.print(f"[warning]Default wordlist not found, using {wordlist_alt} instead.[/]")
                app.logger.warning(f"Default wordlist not found, using {wordlist_alt} instead")
            else:
                app.console.print("[error]No default wordlists found.[/]")
                wordlist = Prompt.ask("[bold yellow]Please enter the path to a wordlist file (or press Enter to skip)")
                if not wordlist or not os.path.exists(wordlist):
                    app.console.print("[error]No valid wordlist. Exiting automated assessment.[/]")
                    app.logger.error("No valid wordlist provided, exiting automated assessment")
                    app._auto_hack_cleanup()
                    return

        max_parallel_attacks = min(4, len(networks_with_clients))
        app.console.print(f"[bold blue]4. Starting parallel assessments on {len(networks_with_clients)} networks (max {max_parallel_attacks} at once)...[/]")
        attack_results = []
        attack_progress = {"lock": threading.Lock(), "active": {}}
        total_nets = len(networks_with_clients)

        def _render_step4_live() -> Panel:
            finished = len(attack_results)
            rows = []
            with attack_progress["lock"]:
                for _bid, st in sorted(attack_progress["active"].items(), key=lambda x: x[1]["ssid"].lower()):
                    rows.append(
                        Text.assemble(("  * ", "dim"), (st["ssid"], "bold cyan"), ("  ", ""), (st["detail"], ""), ("  ", "dim"), (f"{st['elapsed']}s", "yellow"))
                    )
            parts = [Text.assemble(("Finished ", "bold"), (f"{finished}/{total_nets}", "green bold"), ("  ", ""), ("|  ", "dim"), ("Each network capture typically runs ~3-5 minutes before this step advances.", "dim"))]
            parts.append(Group(*rows) if rows else Text("  Starting workers...", style="dim"))
            return Panel(Group(*parts), title="[bold]Step 4 · Parallel assessments[/]", subtitle="[dim]Live status from capture loop[/]", border_style="cyan", box=box.ROUNDED, padding=(0, 1))

        executor = ThreadPoolExecutor(max_workers=max_parallel_attacks)
        future_to_network = {}
        try:
            for bssid, validated_net in networks_with_clients:
                future = executor.submit(app._auto_hack_single_network, bssid, validated_net, session_dir, wordlist, attack_progress)
                future_to_network[future] = (bssid, validated_net)

            pending = set(future_to_network.keys())
            with Live(_render_step4_live(), console=app.console, refresh_per_second=4, transient=True) as live:
                while pending:
                    done, pending = concurrent.futures.wait(pending, timeout=0.25, return_when=concurrent.futures.FIRST_COMPLETED)
                    for future in done:
                        bssid, network = future_to_network[future]
                        try:
                            result = future.result()
                            attack_results.append((bssid, network, result))
                            results_table.add_row(
                                network["ssid"],
                                result["status_message"],
                                result["handshake_status"],
                                result["pmkid_status"],
                                result["password"] if result["password"] else "",
                            )
                        except Exception as exc:
                            app.logger.error(f"Error during automated assessment of {network['ssid']}: {str(exc)}")
                            result = {
                                "status_message": f"[error]Error: {str(exc)}[/]",
                                "handshake_status": "[red]Failed",
                                "pmkid_status": "[red]Failed",
                                "password": None,
                                "handshake_file": None,
                                "pmkid_file": None,
                            }
                            attack_results.append((bssid, network, result))
                            results_table.add_row(network["ssid"], result["status_message"], result["handshake_status"], result["pmkid_status"], "")
                    live.update(_render_step4_live())
        except KeyboardInterrupt:
            app.console.print("\n[warning]Automated assessment stopped by user.[/]")
            app.logger.warning("Automated assessment stopped by user")
            for future in future_to_network:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            app.scanning = False
            app._auto_hack_cleanup()
            app.current_menu = "main"
            return
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        app.console.print("\n")
        app.console.print(results_table)
        handshakes_captured = sum(1 for _, _, result in attack_results if "[green]Captured" in result["handshake_status"])
        pmkids_captured = sum(1 for _, _, result in attack_results if "[green]Captured" in result["pmkid_status"])
        passwords_found = sum(1 for _, _, result in attack_results if result["password"])

        app.console.print("\n[bold blue]5. Assessment Result Analysis[/]")
        analysis_table = Table(show_header=True, header_style="bold blue", box=box.MINIMAL, border_style="cyan", title="[bold green]Analysis Summary[/]")
        analysis_table.add_column("Metric", style="cyan")
        analysis_table.add_column("Value", style="yellow")
        analysis_table.add_column("Success Rate", style="green")
        total_networks = len(networks_with_clients)
        analysis_table.add_row("Networks Assessed", str(total_networks), "100%")
        analysis_table.add_row("Handshakes Captured", str(handshakes_captured), f"{handshakes_captured/total_networks*100:.1f}%" if total_networks > 0 else "0%")
        analysis_table.add_row("PMKIDs Captured", str(pmkids_captured), f"{pmkids_captured/total_networks*100:.1f}%" if total_networks > 0 else "0%")
        analysis_table.add_row("Passphrases Recovered", str(passwords_found), f"{passwords_found/total_networks*100:.1f}%" if total_networks > 0 else "0%")
        app.console.print(analysis_table)

        security_panel = Panel(
            "[yellow]Network Security Analysis[/]\n\n"
            + (f"[success]Recovered {passwords_found} passphrases out of {total_networks} networks.[/]\n\n" if passwords_found > 0 else "[error]No passphrases were recovered.[/]\n\n")
            + "[yellow]Security Recommendations:[/]\n"
            + "- [cyan]Use WPA3 encryption when available for better security.[/]\n"
            + "- [cyan]Use complex, randomly generated passwords (20+ characters).[/]\n"
            + "- [cyan]Use unique passwords for each network.[/]\n"
            + "- [cyan]Disable WPS as it can be vulnerable to attacks.[/]\n"
            + "- [cyan]Consider implementing MAC address filtering as an extra layer.[/]\n"
            + "- [cyan]Enable network logging to detect attack attempts.[/]\n\n"
            + "[yellow]Security Statistics:[/]\n"
            + f"- [cyan]Networks with vulnerable security (WEP/WPA): {sum(1 for _, network, _ in attack_results if 'WEP' in network['cipher'] or ('WPA' in network['cipher'] and 'WPA2' not in network['cipher'] and 'WPA3' not in network['cipher']))}/{total_networks}[/]\n"
            + f"- [cyan]Networks with recommended security (WPA3): {sum(1 for _, network, _ in attack_results if 'WPA3' in network['cipher'])}/{total_networks}[/]\n",
            title="[bold magenta]Security Analysis & Recommendations[/]",
            border_style="cyan",
            box=box.MINIMAL,
        )
        app.console.print(security_panel)

        end_time = datetime.now()
        app.logger.info(f"Automated assessment completed at {end_time}")
        with open(report_file, "a", encoding="utf-8") as f:
            f.write(f"End Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Duration: {(end_time - datetime.strptime(session_timestamp, '%Y%m%d_%H%M%S')).total_seconds():.2f} seconds\n\n")
            f.write("==================\nSUMMARY RESULTS\n==================\n")
            f.write(f"Networks Assessed: {total_networks}\n")
            f.write(f"Handshakes Captured: {handshakes_captured}\n")
            f.write(f"PMKIDs Captured: {pmkids_captured}\n")
            f.write(f"Passphrases Recovered: {passwords_found}\n\n")
            f.write("==================\nSECURITY ANALYSIS\n==================\n")
            f.write(f"Networks with vulnerable security (WEP/WPA): {sum(1 for _, network, _ in attack_results if 'WEP' in network['cipher'] or ('WPA' in network['cipher'] and 'WPA2' not in network['cipher'] and 'WPA3' not in network['cipher']))}/{total_networks}\n")
            f.write(f"Networks with recommended security (WPA3): {sum(1 for _, network, _ in attack_results if 'WPA3' in network['cipher'])}/{total_networks}\n\n")
            f.write("==================\nRECOMMENDATIONS\n==================\n")
            f.write("Security Recommendations:\n")
            f.write("- Use WPA3 encryption when available for better security.\n")
            f.write("- Use complex, randomly generated passwords (20+ characters).\n")
            f.write("- Use unique passwords for each network.\n")
            f.write("- Disable WPS as it can be vulnerable to attacks.\n")
            f.write("- Consider implementing MAC address filtering as an extra layer.\n")
            f.write("- Enable network logging to detect attack attempts.\n\n")
            f.write("==================\nFOLLOW-UP STEPS\n==================\n")
            if passwords_found > 0:
                f.write("- Recovered passphrases should be disclosed to network owners for security improvement.\n")
                f.write("- Networks with recovered passphrases should update their security configurations immediately.\n")
            if handshakes_captured > 0 and passwords_found < handshakes_captured:
                f.write("- Additional cracking attempts with larger dictionaries can be performed offline.\n")
                f.write("- Consider using more powerful hardware for offline cracking.\n")
            f.write("- Regular security audits should be performed to ensure continued network safety.\n")

        html_report_file = session_dir / "auto_hack_report.html"
        generate_html_report(app, session_dir, attack_results, html_report_file)
        app.console.print("\n[success]Automated assessment completed. Detailed reports saved to:[/]")
        app.console.print(f"[bold cyan]  - Text Report: {report_file}[/]")
        app.console.print(f"[bold cyan]  - HTML Report: {html_report_file}[/]")
    except KeyboardInterrupt:
        app.console.print("\n[warning]Automated assessment stopped by user.[/]")
        app.logger.warning("Automated assessment stopped by user")
        app.scanning = False
        app._auto_hack_cleanup()
        app.current_menu = "main"
        return
    except Exception as exc:
        app.console.print(f"[error]Error during automated assessment: {str(exc)}[/]")
        app.logger.error(f"Error during automated assessment: {str(exc)}")
        app.scanning = False
    finally:
        app.console.print("[bold blue]Performing cleanup...[/]")
        app._auto_hack_cleanup()
        app.current_menu = "main"


def generate_html_report(app, session_dir, attack_results, html_report_file) -> None:
    """Generate an HTML report with attack results."""
    try:
        total_networks = len(attack_results)
        handshakes_captured = sum(1 for _, _, result in attack_results if "[green]Captured" in result["handshake_status"])
        pmkids_captured = sum(1 for _, _, result in attack_results if "[green]Captured" in result["pmkid_status"])
        passwords_found = sum(1 for _, _, result in attack_results if result["password"])
        vulnerable_networks = sum(1 for _, network, _ in attack_results if "WEP" in network["cipher"] or ("WPA" in network["cipher"] and "WPA2" not in network["cipher"] and "WPA3" not in network["cipher"]))
        wpa3_networks = sum(1 for _, network, _ in attack_results if "WPA3" in network["cipher"])

        attack_results_rows = ""
        for bssid, network, result in attack_results:
            handshake_status = "Captured" if "[green]Captured" in result["handshake_status"] else "Failed"
            handshake_class = "success" if "[green]Captured" in result["handshake_status"] else "error"
            pmkid_status = "Captured" if "[green]Captured" in result["pmkid_status"] else "Failed"
            pmkid_class = "success" if "[green]Captured" in result["pmkid_status"] else "error"
            ssid = escape(str(network.get("ssid", "Unknown")))
            bssid_html = escape(str(bssid))
            cipher = escape(str(network.get("cipher", "Unknown")))
            password = escape(str(result["password"]) if result["password"] else "Not found")
            password_class = "success" if result["password"] else "warning"
            attack_results_rows += f"""<tr>
            <td>{ssid}</td>
            <td>{bssid_html}</td>
            <td>{cipher}</td>
            <td class="{handshake_class}">{handshake_status}</td>
            <td class="{pmkid_class}">{pmkid_status}</td>
            <td class="{password_class}">{password}</td>
        </tr>"""

        followup_steps = ""
        if passwords_found > 0:
            followup_steps += "<li>Recovered passphrases should be disclosed to network owners for security improvement.</li>"
            followup_steps += "<li>Networks with recovered passphrases should update their security configurations immediately.</li>"
        if handshakes_captured > 0 and passwords_found < handshakes_captured:
            followup_steps += "<li>Additional cracking attempts with larger dictionaries can be performed offline.</li>"
            followup_steps += "<li>Consider using more powerful hardware for offline cracking.</li>"
        followup_steps += "<li>Regular security audits should be performed to ensure continued network safety.</li>"

        now = datetime.now()
        session_start_time = datetime.strptime(session_dir.name, "%Y%m%d_%H%M%S")
        duration = (now - session_start_time).total_seconds()

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFiAngel Automated Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        h1 {{ border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ padding: 12px 15px; border: 1px solid #ddd; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .success {{ color: #27ae60; font-weight: bold; }}
        .warning {{ color: #f39c12; font-weight: bold; }}
        .error {{ color: #e74c3c; font-weight: bold; }}
        .summary-box {{ background-color: #ecf0f1; border-left: 5px solid #3498db; padding: 15px; margin: 20px 0; }}
        .recommendations {{ background-color: #e8f4fd; border-left: 5px solid #2980b9; padding: 15px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>WiFiAngel Automated Assessment Report</h1>
    <div class="summary-box">
        <h2>Session Summary</h2>
        <p><strong>Date:</strong> {now.strftime("%Y-%m-%d")}</p>
        <p><strong>Start Time:</strong> {session_start_time.strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>End Time:</strong> {now.strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Duration:</strong> {duration:.2f} seconds</p>
        <p><strong>Networks Scanned:</strong> {len(app.networks)}</p>
        <p><strong>Networks Assessed:</strong> {total_networks}</p>
    </div>
    <h2>Assessment Results</h2>
    <table>
        <tr><th>Network</th><th>BSSID</th><th>Security</th><th>Handshake</th><th>PMKID</th><th>Password</th></tr>
        {attack_results_rows}
    </table>
    <h2>Statistics</h2>
    <div class="summary-box">
        <p><strong>Handshakes Captured:</strong> {handshakes_captured} / {total_networks} ({(handshakes_captured/total_networks*100) if total_networks > 0 else 0:.1f}%)</p>
        <p><strong>PMKIDs Captured:</strong> {pmkids_captured} / {total_networks} ({(pmkids_captured/total_networks*100) if total_networks > 0 else 0:.1f}%)</p>
        <p><strong>Passphrases Recovered:</strong> {passwords_found} / {total_networks} ({(passwords_found/total_networks*100) if total_networks > 0 else 0:.1f}%)</p>
    </div>
    <h2>Security Analysis</h2>
    <div class="summary-box">
        <p><strong>Networks with vulnerable security (WEP/WPA):</strong> {vulnerable_networks} / {total_networks}</p>
        <p><strong>Networks with recommended security (WPA3):</strong> {wpa3_networks} / {total_networks}</p>
    </div>
    <h2>Recommendations</h2>
    <div class="recommendations">
        <ul>
            <li>Use WPA3 encryption when available for better security.</li>
            <li>Use complex, randomly generated passwords (20+ characters).</li>
            <li>Use unique passwords for each network.</li>
            <li>Disable WPS as it can be vulnerable to attacks.</li>
            <li>Consider implementing MAC address filtering as an extra layer.</li>
            <li>Enable network logging to detect attack attempts.</li>
        </ul>
    </div>
    <h2>Follow-up Steps</h2>
    <div class="recommendations"><ul>{followup_steps}</ul></div>
    <footer><p>Generated by WiFiAngel on {now.strftime("%Y-%m-%d")}</p></footer>
</body>
</html>"""

        with open(html_report_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        app.logger.info(f"HTML report generated at {html_report_file}")
    except Exception as exc:
        app.logger.error(f"Error generating HTML report: {str(exc)}")
