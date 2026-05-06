import unittest

from adapters.system_tools.network import (
    arp_lookup_command,
    normalize_mac_address,
    parse_mac_from_arp_output,
    ping_probe_command,
)


class NetworkHelperTests(unittest.TestCase):
    def test_parse_mac_from_arp_output(self):
        output = "? (192.168.1.42) at AA:BB:CC:DD:EE:FF [ether] on wlan0"

        self.assertEqual(parse_mac_from_arp_output(output), "aa:bb:cc:dd:ee:ff")

    def test_parse_mac_supports_plain_and_hyphenated_formats(self):
        self.assertEqual(parse_mac_from_arp_output("aabbccddeeff"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parse_mac_from_arp_output("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")

    def test_parse_mac_returns_none_when_not_found(self):
        self.assertIsNone(parse_mac_from_arp_output("no entry"))

    def test_normalize_mac_keeps_unexpected_text_lowercase(self):
        self.assertEqual(normalize_mac_address("bad-value"), "bad-value")

    def test_command_builders(self):
        self.assertEqual(arp_lookup_command("192.168.1.5"), ["arp", "-a", "192.168.1.5"])
        self.assertEqual(
            ping_probe_command("192.168.1.5"),
            ["ping", "-c", "1", "-W", "1", "192.168.1.5"],
        )


if __name__ == "__main__":
    unittest.main()
