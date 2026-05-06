"""Capture/verification helpers extracted from WiFiAngel controller."""

from __future__ import annotations

from pathlib import Path
import subprocess

from attacks.commands import aircrack_check, hcxpcapngtool_info
from attacks.parsers import has_aircrack_handshake


def stream_output_to_file(process, file) -> None:
    """Stream subprocess stdout to file without crashing caller threads."""
    try:
        if process and process.stdout and not process.stdout.closed:
            for line in iter(process.stdout.readline, ""):
                if line and file and not file.closed:
                    try:
                        file.write(line)
                        file.flush()
                    except (ValueError, IOError):
                        break
    except Exception:
        pass
    finally:
        if process and process.stdout and not process.stdout.closed:
            try:
                process.stdout.close()
            except Exception:
                pass


def verify_handshake(cap_file, bssid, logger, ssid=None) -> bool:
    """Verify a WPA handshake using multiple tools when available."""
    try:
        logger.info(f"Verifying handshake in {cap_file}")
        aircrack_result = subprocess.run(aircrack_check(cap_file), capture_output=True, text=True)

        pyrit_verification = False
        try:
            pyrit_cmd = ["pyrit", "-r", str(cap_file), "analyze"]
            pyrit_result = subprocess.run(pyrit_cmd, capture_output=True, text=True)
            if "handshake(s)" in pyrit_result.stdout:
                pyrit_verification = True
                logger.info("Pyrit verified handshake")
        except Exception:
            logger.debug("Pyrit verification failed or not available")

        cowpatty_verification = False
        if ssid:
            try:
                cowpatty_cmd = ["cowpatty", "-c", "-r", str(cap_file), "-s", ssid]
                cowpatty_result = subprocess.run(cowpatty_cmd, capture_output=True, text=True)
                if "Collected all necessary data to mount crack against WPA" in cowpatty_result.stdout:
                    cowpatty_verification = True
                    logger.info("Cowpatty verified handshake")
            except Exception:
                logger.debug("Cowpatty verification failed or not available")

        has_handshake = False
        if has_aircrack_handshake(aircrack_result.stdout, bssid):
            has_handshake = True
            logger.info("Aircrack-ng verified handshake")

        verified = has_handshake or pyrit_verification or cowpatty_verification
        if verified:
            logger.info("Handshake verification successful")
            return True

        logger.warning("Handshake verification failed")
        return False
    except Exception as exc:
        logger.error(f"Error verifying handshake: {str(exc)}")
        return False


def verify_pmkid(pmkid_file, bssid, logger) -> bool:
    """Verify if PMKID output seems valid for target BSSID."""
    try:
        logger.info(f"Verifying PMKID in {pmkid_file}")

        pmkid_path = Path(pmkid_file)
        if not pmkid_path.exists() or pmkid_path.stat().st_size == 0:
            logger.warning("PMKID file is empty or does not exist")
            return False

        with open(pmkid_path, "r", errors="ignore") as f:
            content = f.read()
            bssid_parts = bssid.split(":")
            if len(bssid_parts) == 6:
                bssid_no_colons = "".join(bssid_parts)
                bssid_formats = [
                    bssid.lower(),
                    bssid.upper(),
                    bssid_no_colons.lower(),
                    bssid_no_colons.upper(),
                ]
                for bssid_format in bssid_formats:
                    if bssid_format in content:
                        logger.info(f"PMKID verification successful - found BSSID {bssid_format}")
                        return True

        try:
            hashcat_cmd = ["hashcat", "--show", "-m", "22000", str(pmkid_file)]
            hashcat_result = subprocess.run(hashcat_cmd, capture_output=True, text=True)
            if bssid.replace(":", "").lower() in hashcat_result.stdout.lower():
                logger.info("Hashcat verified PMKID")
                return True
        except Exception:
            pass

        try:
            hcx_cmd = hcxpcapngtool_info(str(pmkid_file).replace(".22000", ".pcapng"))
            hcx_result = subprocess.run(hcx_cmd, capture_output=True, text=True)
            if bssid.lower() in hcx_result.stdout.lower():
                logger.info("hcxpcapngtool verified PMKID")
                return True
        except Exception:
            pass

        logger.warning("PMKID verification failed - BSSID not found in file")
        return False
    except Exception as exc:
        logger.error(f"Error verifying PMKID: {str(exc)}")
        return False

