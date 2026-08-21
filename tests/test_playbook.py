import unittest

from wifi.frame_intelligence import summarize_network_security
from wifi.playbook import (
    MODULE_ENTERPRISE,
    MODULE_EVIL_TWIN,
    MODULE_HANDSHAKE,
    MODULE_PMKID,
    MODULE_WPS,
    recommend_assessment,
)


class PlaybookTests(unittest.TestCase):
    def test_open_network_recommends_evil_twin(self):
        playbook = recommend_assessment({"ssid": "Guest", "cipher": "OPEN", "clients": set(), "wps": False})
        self.assertEqual(playbook.module_id, MODULE_EVIL_TWIN)
        self.assertTrue(playbook.skip_psk_capture)
        self.assertTrue(playbook.skip_deauth)
        self.assertEqual(playbook.akm_label, "Open")

    def test_enterprise_skips_psk_paths(self):
        playbook = recommend_assessment(
            {"ssid": "Corp", "cipher": "WPA2/CCMP/MGT", "clients": {"aa:bb:cc:dd:ee:ff"}, "wps": False}
        )
        self.assertEqual(playbook.module_id, MODULE_ENTERPRISE)
        self.assertTrue(playbook.skip_psk_capture)
        self.assertTrue(playbook.skip_deauth)
        self.assertEqual(playbook.akm_label, "802.1X")
        self.assertTrue(any("Attack 10" in item for item in playbook.findings))

    def test_sae_only_is_passive(self):
        playbook = recommend_assessment(
            {"ssid": "Lab", "cipher": "WPA3/CCMP/SAE", "clients": {"11:22:33:44:55:66"}, "wps": False}
        )
        self.assertEqual(playbook.module_id, MODULE_HANDSHAKE)
        self.assertEqual(playbook.capture_mode, "passive")
        self.assertTrue(playbook.skip_deauth)
        self.assertFalse(playbook.skip_psk_capture)
        self.assertEqual(playbook.akm_label, "SAE")

    def test_transition_mode_keeps_targeted_handshake(self):
        playbook = recommend_assessment(
            {
                "ssid": "Mixed",
                "cipher": "WPA2/WPA3/CCMP/PSK/SAE",
                "clients": {"11:22:33:44:55:66"},
                "wps": False,
            }
        )
        self.assertEqual(playbook.module_id, MODULE_HANDSHAKE)
        self.assertEqual(playbook.capture_mode, "active")
        self.assertFalse(playbook.skip_deauth)
        self.assertEqual(playbook.akm_label, "SAE+PSK (transition)")

    def test_psk_without_clients_prefers_pmkid(self):
        playbook = recommend_assessment({"ssid": "Home", "cipher": "WPA2/CCMP/PSK", "clients": set(), "wps": False})
        self.assertEqual(playbook.module_id, MODULE_PMKID)
        self.assertFalse(playbook.skip_psk_capture)

    def test_wps_without_clients_prefers_wps(self):
        playbook = recommend_assessment({"ssid": "Router", "cipher": "WPA2/CCMP/PSK", "clients": set(), "wps": True})
        self.assertEqual(playbook.module_id, MODULE_WPS)

    def test_security_summary_marks_sae_passive(self):
        summary = summarize_network_security({"ssid": "Lab", "cipher": "WPA3/SAE"})
        self.assertTrue(summary["passive_capture"])
        self.assertFalse(summary["transition_mode"])
        self.assertEqual(summary["akm_label"], "SAE")


if __name__ == "__main__":
    unittest.main()
