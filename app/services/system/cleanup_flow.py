"""Cleanup helpers for auto-hack/process termination."""

from __future__ import annotations

import subprocess
import time


def run_auto_hack_cleanup(app) -> None:
    """Safe cleanup for auto-hack mode."""
    try:
        processes_to_kill = ["airodump-ng", "aireplay-ng", "hcxdumptool", "hashcat", "aircrack-ng"]
        for proc in processes_to_kill:
            try:
                subprocess.run(["pkill", "-f", proc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(1)
                subprocess.run(["pkill", "-9", "-f", proc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

        try:
            subprocess.run(["pkill", "-9", "-f", "defunct"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

        try:
            subprocess.run(["pkill", "-9", "-f", "hcxdumptool"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-9", "-f", "airodump-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-9", "-f", "aireplay-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

        try:
            airmon_check = subprocess.run(["airmon-ng", "check"], capture_output=True, text=True)
            if "PID" in airmon_check.stdout and "Name" in airmon_check.stdout:
                app.logger.info("Killing leftover network-related processes")
                subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

        app.logger.info("Auto hack cleanup completed")
    except Exception as exc:
        app.logger.error(f"Error during cleanup: {str(exc)}")
        try:
            subprocess.run(["pkill", "-9", "-f", "air"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-9", "-f", "hcx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-9", "-f", "hashcat"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


def run_kill_processes(app, process_names) -> None:
    """Kill specific process names with graceful then forced termination."""
    for proc_name in process_names:
        try:
            subprocess.run(["pkill", "-f", proc_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            subprocess.run(["pkill", "-9", "-f", proc_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:
            app.logger.error(f"Error killing {proc_name}: {str(exc)}")

    try:
        subprocess.run(["pkill", "-9", "-f", "defunct"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

