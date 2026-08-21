"""Tests for airodump-ng CSV parsing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from wifi.airodump_csv import (
    ap_row_to_network_fields,
    parse_airodump_csv,
    probed_essids_by_bssid,
    station_client_counts,
)

_SAMPLE_CSV = """
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2024-01-01 10:00:00, 2024-01-01 10:01:00,  6, 360, WPA2 CCMP, CCMP, PSK, -45,       10,        0,   0.  0.  0.  0,   8, TestSSID,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2024-01-01 10:00:00, 2024-01-01 10:01:00, -50,       20, AA:BB:CC:DD:EE:FF,
AA:BB:CC:EE:FF:00, 2024-01-01 10:00:01, 2024-01-01 10:01:01, -40,        5, (not associated), probe
"""


class AirodumpCsvTests(unittest.TestCase):
    def test_parse_and_fields(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix="-01.csv", delete=False, encoding="utf-8") as f:
            f.write(_SAMPLE_CSV)
            path = Path(f.name)
        try:
            aps, stas = parse_airodump_csv(path)
            self.assertEqual(len(aps), 1)
            self.assertEqual(len(stas), 2)
            nf = ap_row_to_network_fields(aps[0])
            assert nf is not None
            self.assertEqual(nf["bssid"], "aa:bb:cc:dd:ee:ff")
            self.assertEqual(nf["ssid"], "TestSSID")
            self.assertEqual(nf["channel"], 6)
            self.assertEqual(nf["signal"], -45)
            self.assertFalse(nf["wps"])
            self.assertEqual(nf["data_packets"], 0)
            self.assertIn("WPA2", nf["cipher"])
            counts = station_client_counts(stas)
            self.assertEqual(counts.get("aa:bb:cc:dd:ee:ff"), {"11:22:33:44:55:66"})
        finally:
            path.unlink(missing_ok=True)

    def test_probed_essids_by_bssid(self):
        csv_text = """
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2024-01-01 10:00:00, 2024-01-01 10:01:00,  6, 360, WPA2 CCMP, CCMP, PSK, -45,       10,        0,   0.  0.  0.  0,   0, ,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2024-01-01 10:00:00, 2024-01-01 10:01:00, -50,       20, AA:BB:CC:DD:EE:FF, GuestWiFi
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix="-01.csv", delete=False, encoding="utf-8") as f:
            f.write(csv_text)
            path = Path(f.name)
        try:
            _aps, stas = parse_airodump_csv(path)
            probed = probed_essids_by_bssid(stas)
            self.assertEqual(probed.get("aa:bb:cc:dd:ee:ff"), {"GuestWiFi"})
        finally:
            path.unlink(missing_ok=True)

    def test_wps_not_inferred_from_essid_text(self):
        row = {
            "BSSID": "AA:BB:CC:DD:EE:FF",
            "ESSID": "CafeWPSFree",
            "channel": "6",
            "Power": "-40",
            "Privacy": "WPA2",
            "Cipher": "CCMP",
            "Authentication": "PSK",
        }
        fields = ap_row_to_network_fields(row)
        assert fields is not None
        self.assertFalse(fields["wps"])
        self.assertEqual(fields["ssid"], "CafeWPSFree")

    def test_wps_from_privacy_token(self):
        row = {
            "BSSID": "AA:BB:CC:DD:EE:FF",
            "ESSID": "Lab",
            "channel": "1",
            "Power": "-50",
            "Privacy": "WPA2 WPS",
            "Cipher": "CCMP",
            "Authentication": "PSK",
        }
        fields = ap_row_to_network_fields(row)
        assert fields is not None
        self.assertTrue(fields["wps"])

    def test_missing_file(self):
        aps, stas = parse_airodump_csv(Path("/nonexistent/no.csv"))
        self.assertEqual(aps, [])
        self.assertEqual(stas, [])


if __name__ == "__main__":
    unittest.main()
