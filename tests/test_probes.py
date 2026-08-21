import unittest

from wifi.airodump_csv import parse_airodump_csv, parse_probed_essid_field, probed_essids_by_bssid, station_probe_rows
from wifi.probes import preferred_evil_twin_ssid, summarize_probe_ssids, usable_lab_ssid


class ProbeSsidTests(unittest.TestCase):
    def test_parse_probed_field_splits_and_dedupes(self):
        self.assertEqual(parse_probed_essid_field('Home, Cafe, Home; Guest'), ("Home", "Cafe", "Guest"))
        self.assertEqual(parse_probed_essid_field("<Hidden Network>"), ())

    def test_unassociated_stations_count_toward_global_ranking(self):
        stations = [
            {
                "Station MAC": "11:22:33:44:55:66",
                "BSSID": "(not associated)",
                "Probed ESSIDs": "HomeWifi, Cafe",
            },
            {
                "Station MAC": "AA:BB:CC:DD:EE:00",
                "BSSID": "(not associated)",
                "Probed ESSIDs": "HomeWifi",
            },
            {
                "Station MAC": "AA:BB:CC:DD:EE:01",
                "BSSID": "(not associated)",
                "Probed ESSIDs": "HomeWifi",
            },
            {
                "Station MAC": "AA:BB:CC:DD:EE:02",
                "BSSID": "AA:BB:CC:DD:EE:FF",
                "Probed ESSIDs": "Cafe",
            },
        ]
        rows = station_probe_rows(stations)
        self.assertEqual(len(rows), 4)
        self.assertIsNone(rows[0][1])
        stats = summarize_probe_ssids(stations)
        self.assertEqual(stats[0].ssid, "HomeWifi")
        self.assertEqual(stats[0].station_count, 3)
        cafe = next(item for item in stats if item.ssid == "Cafe")
        self.assertEqual(cafe.station_count, 2)
        self.assertEqual(cafe.associated_bssids, ("aa:bb:cc:dd:ee:ff",))
        associated_only = probed_essids_by_bssid(stations)
        self.assertEqual(associated_only.get("aa:bb:cc:dd:ee:ff"), {"Cafe"})
        self.assertNotIn("HomeWifi", associated_only.get("aa:bb:cc:dd:ee:ff", set()))

    def test_preferred_ssid_uses_selected_then_most_probed(self):
        stations = [
            {"Station MAC": "11:22:33:44:55:66", "BSSID": "(not associated)", "Probed ESSIDs": "OfficeGuest"},
            {"Station MAC": "11:22:33:44:55:67", "BSSID": "(not associated)", "Probed ESSIDs": "OfficeGuest"},
        ]
        stats = summarize_probe_ssids(stations)
        ssid, source = preferred_evil_twin_ssid(selected_ssid="LabAP", probe_stats=stats)
        self.assertEqual((ssid, source), ("LabAP", "selected"))
        ssid, source = preferred_evil_twin_ssid(selected_ssid="<Hidden Network>", probe_stats=stats)
        self.assertEqual((ssid, source), ("OfficeGuest", "probe"))
        ssid, source = preferred_evil_twin_ssid(selected_ssid="", probe_stats=())
        self.assertEqual((ssid, source), ("", ""))

    def test_usable_lab_ssid_rejects_hidden_and_overlong(self):
        self.assertTrue(usable_lab_ssid("Cafe"))
        self.assertFalse(usable_lab_ssid("<Hidden Network>"))
        self.assertFalse(usable_lab_ssid("x" * 33))
        self.assertFalse(usable_lab_ssid("bad\nssid"))


if __name__ == "__main__":
    unittest.main()
