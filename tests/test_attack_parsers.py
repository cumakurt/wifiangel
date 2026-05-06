import unittest

from attacks.parsers import (
    extract_hashcat_password_for_bssid,
    extract_wifi_password,
    has_aircrack_handshake,
    is_valid_wifi_password,
    parse_aircrack_network_info,
)


class AttackParserTests(unittest.TestCase):
    def test_parse_aircrack_network_info(self):
        output = """
Index number of target network ?

   BSSID              ESSID

   AA:BB:CC:DD:EE:FF  Test Network
"""

        info = parse_aircrack_network_info(output)

        self.assertEqual(info.bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(info.essid, "Test Network")
        self.assertFalse(info.is_wpa3)

    def test_parse_aircrack_network_info_marks_wpa3(self):
        output = "BSSID              ESSID\nAA:BB:CC:DD:EE:FF  LabNet WPA3\nWPA3 SAE"

        info = parse_aircrack_network_info(output)

        self.assertTrue(info.is_wpa3)

    def test_has_aircrack_handshake(self):
        output = "WPA (1 handshake) AA:BB:CC:DD:EE:FF"

        self.assertTrue(has_aircrack_handshake(output))
        self.assertTrue(has_aircrack_handshake(output, "aa:bb:cc:dd:ee:ff"))
        self.assertFalse(has_aircrack_handshake(output, "00:11:22:33:44:55"))

    def test_extract_aircrack_password(self):
        output = "KEY FOUND! [ correct horse 1 ]"

        self.assertEqual(extract_wifi_password(output), "correct horse 1")

    def test_extract_context_password(self):
        output = "Status: Cracked\nHash line: SuperSecret123"

        self.assertEqual(extract_wifi_password(output), "SuperSecret123")

    def test_extract_hashcat_password_for_bssid(self):
        output = "aabbccddeeff:112233445566:TestNet:WifiPassword99"

        self.assertEqual(
            extract_hashcat_password_for_bssid(output, "AA:BB:CC:DD:EE:FF"),
            "WifiPassword99",
        )

    def test_invalid_password_filters_status_text(self):
        self.assertFalse(is_valid_wifi_password("00:00:05"))
        self.assertFalse(is_valid_wifi_password("10 seconds"))
        self.assertFalse(is_valid_wifi_password("progress 50%"))
        self.assertIsNone(extract_wifi_password("KEY FOUND! [ 00:00:05 ]"))


if __name__ == "__main__":
    unittest.main()
