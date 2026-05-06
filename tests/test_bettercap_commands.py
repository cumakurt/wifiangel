import unittest

from adapters.system_tools.bettercap import bettercap_command, bettercap_stdin_eval_command


class BettercapCommandTests(unittest.TestCase):
    def test_bettercap_command_without_caplet(self):
        self.assertEqual(bettercap_command("wlan0"), ["bettercap", "-iface", "wlan0"])

    def test_bettercap_command_with_caplet(self):
        self.assertEqual(
            bettercap_command("wlan0", "/tmp/test.cap"),
            ["bettercap", "-iface", "wlan0", "-caplet", "/tmp/test.cap"],
        )

    def test_bettercap_stdin_eval_command(self):
        self.assertEqual(
            bettercap_stdin_eval_command("wlan0"),
            ["bettercap", "-iface", "wlan0", "-no-history", "-eval-"],
        )


if __name__ == "__main__":
    unittest.main()
