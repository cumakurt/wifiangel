from __future__ import annotations

from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from app.services.attacks import auto_hack_flow
from attacks.parsers import (
    extract_hashcat_password_for_bssid,
    extract_wifi_password,
    has_aircrack_handshake,
)


class _Logger:
    def __init__(self):
        self.messages: list[str] = []

    def info(self, msg, *args, **kwargs):
        self.messages.append(str(msg))

    def warning(self, msg, *args, **kwargs):
        self.messages.append(str(msg))

    def error(self, msg, *args, **kwargs):
        self.messages.append(str(msg))


class _FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 5, 9, 12, 0, 0)


class AutoHackFlowTests(unittest.TestCase):
    def test_parser_helpers_are_imported(self):
        self.assertIs(auto_hack_flow.has_aircrack_handshake, has_aircrack_handshake)
        self.assertIs(auto_hack_flow.extract_wifi_password, extract_wifi_password)
        self.assertIs(auto_hack_flow.extract_hashcat_password_for_bssid, extract_hashcat_password_for_bssid)

    def test_handshake_branch_cracks_without_nameerror(self):
        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp)
            wordlist = session_dir / "words.txt"
            wordlist.write_text("password123\n", encoding="utf-8")
            cap_path = session_dir / "LabNet_aabbccddeeff" / "handshake_20260509_120000-01.cap"

            proc = MagicMock()
            proc.poll.return_value = None
            proc.returncode = None

            app = SimpleNamespace(
                interface_name="wlan0mon",
                logger=_Logger(),
                _verify_handshake=MagicMock(return_value=True),
                _verify_pmkid=MagicMock(return_value=False),
            )
            network = {
                "ssid": "LabNet",
                "channel": 6,
                "cipher": "WPA2",
                "clients": {"11:22:33:44:55:66"},
                "wps": False,
            }

            def fake_popen(_cmd, **_kwargs):
                cap_path.parent.mkdir(parents=True, exist_ok=True)
                cap_path.write_bytes(b"pcap")
                return proc

            def fake_run(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                argv0 = cmd[0] if cmd else ""
                if argv0 == "aircrack-ng" and "-w" not in cmd:
                    result.stdout = "WPA (1 handshake) aa:bb:cc:dd:ee:ff"
                    result.stderr = ""
                elif argv0 == "aircrack-ng":
                    result.stdout = "KEY FOUND! [ labpass1 ]"
                    result.stderr = ""
                else:
                    result.stdout = ""
                    result.stderr = ""
                return result

            clock = {"t": 0.0}

            def fake_time():
                clock["t"] += 200.0
                return clock["t"]

            with (
                patch("app.services.attacks.auto_hack_flow.datetime", _FrozenDateTime),
                patch("app.services.attacks.auto_hack_flow.subprocess.Popen", side_effect=fake_popen),
                patch("app.services.attacks.auto_hack_flow.subprocess.run", side_effect=fake_run),
                patch("app.services.attacks.auto_hack_flow.time.sleep", return_value=None),
                patch("app.services.attacks.auto_hack_flow.time.time", side_effect=fake_time),
            ):
                result = auto_hack_flow.run_auto_hack_single_network(
                    app,
                    "aa:bb:cc:dd:ee:ff",
                    network,
                    session_dir,
                    str(wordlist),
                )

            self.assertEqual(result["password"], "labpass1")
            self.assertIn("[green]Captured", result["handshake_status"])
            self.assertTrue(any("Passphrase recovered" in msg for msg in app.logger.messages))
            self.assertFalse(any("labpass1" in msg for msg in app.logger.messages))
