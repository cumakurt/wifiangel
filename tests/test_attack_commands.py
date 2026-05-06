import unittest
from pathlib import Path

from attacks.commands import (
    aireplay_deauth,
    aircrack_check,
    aircrack_crack,
    airodump_capture,
    hashcat_crack,
    hcxdumptool_capture,
    hcxpcapngtool_convert,
    hcxpcapngtool_info,
)


class AttackCommandTests(unittest.TestCase):
    def test_airodump_capture_command(self):
        self.assertEqual(
            airodump_capture("wlan0mon", channel=6, bssid="aa:bb:cc:dd:ee:ff", output_prefix=Path("out/cap")),
            [
                "airodump-ng",
                "-c",
                "6",
                "--bssid",
                "aa:bb:cc:dd:ee:ff",
                "-w",
                "out/cap",
                "wlan0mon",
            ],
        )

    def test_airodump_capture_command_wpa3(self):
        self.assertEqual(
            airodump_capture("wlan0mon", channel=11, bssid="aa", output_prefix="out", wpa3=True),
            ["airodump-ng", "-c", "11", "--bssid", "aa", "-w", "out", "--wpa3", "wlan0mon"],
        )

    def test_aireplay_deauth_command(self):
        self.assertEqual(
            aireplay_deauth("wlan0mon", bssid="aa", count=5, client="bb"),
            ["aireplay-ng", "-0", "5", "-a", "aa", "-c", "bb", "wlan0mon"],
        )

    def test_aircrack_commands(self):
        self.assertEqual(aircrack_check("capture.cap"), ["aircrack-ng", "capture.cap"])
        self.assertEqual(
            aircrack_crack("capture.cap", "words.txt", "TestNet"),
            ["aircrack-ng", "-a", "2", "-w", "words.txt", "-e", "TestNet", "capture.cap"],
        )

    def test_hashcat_modes_and_flags(self):
        self.assertEqual(
            hashcat_crack("hash.22000", "words.txt", mode=16800, workload=3, force=True),
            ["hashcat", "-m", "16800", "-a", "0", "-w", "3", "--force", "hash.22000", "words.txt"],
        )
        self.assertEqual(
            hashcat_crack("hash.22000", "words.txt", workload=0, status=True, potfile_disable=True),
            ["hashcat", "-m", "22000", "-a", "0", "hash.22000", "words.txt", "--status", "--potfile-disable"],
        )

    def test_hcx_commands(self):
        self.assertEqual(
            hcxdumptool_capture("wlan0mon", "pmkid.pcapng", 6),
            ["hcxdumptool", "-i", "wlan0mon", "-w", "pmkid.pcapng", "-c", "6"],
        )
        self.assertEqual(
            hcxpcapngtool_convert("pmkid.22000", "pmkid.pcapng"),
            ["hcxpcapngtool", "-o", "pmkid.22000", "pmkid.pcapng"],
        )
        self.assertEqual(
            hcxpcapngtool_info("pmkid.pcapng"),
            ["hcxpcapngtool", "-i", "pmkid.pcapng", "--info=1"],
        )


if __name__ == "__main__":
    unittest.main()
