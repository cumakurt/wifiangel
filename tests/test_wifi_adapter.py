import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adapters.system_tools import (
    WiFiAdapterManager,
    managed_name_from_monitor,
    parse_iwconfig_monitor_interface,
    parse_iwconfig_wireless_interfaces,
)
from adapters.system_tools.wifi import parse_iw_dev_info_interface_type, parse_iw_dev_monitor_interface


class FakeRunner:
    def __init__(self, outputs=None, missing=None):
        self.outputs = list(outputs or [])
        self.missing = set(missing or [])
        self.calls = []

    def check_output(self, command, **kwargs):
        self.calls.append(("check_output", tuple(command)))
        if self.outputs:
            return self.outputs.pop(0)
        return ""

    def run(self, command, **kwargs):
        self.calls.append(("run", tuple(command)))

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

            @property
            def ok(self):
                return True

        return Result()

    def which(self, command):
        return None if command in self.missing else f"/usr/bin/{command}"


class WiFiAdapterParsingTests(unittest.TestCase):
    def test_parse_wireless_interfaces(self):
        output = (
            "wlan0     IEEE 802.11  ESSID:off/any\n"
            "lo        no wireless extensions.\n"
            "wlan1mon  IEEE 802.11  Mode:Monitor\n"
        )

        self.assertEqual(parse_iwconfig_wireless_interfaces(output), ["wlan0", "wlan1mon"])

    def test_parse_monitor_interface(self):
        output = "wlan0     IEEE 802.11  Mode:Managed\nwlan0mon  IEEE 802.11  Mode:Monitor\n"

        self.assertEqual(parse_iwconfig_monitor_interface(output), "wlan0mon")

    def test_managed_name_only_strips_monitor_suffix(self):
        self.assertEqual(managed_name_from_monitor("wlan0mon"), "wlan0")
        self.assertEqual(managed_name_from_monitor("monarch0"), "monarch0")

    def test_parse_iw_dev_monitor_interface_finds_monitor_blocks(self):
        output = "phy\n\tInterface foo\n\t\ttype monitor\n"
        self.assertEqual(parse_iw_dev_monitor_interface(output), "foo")

    def test_parse_iw_dev_monitor_interface_prefers_first_monitor(self):
        output = "phy#0\n\tInterface wlan0\n\t\ttype managed\n\tInterface wlan0mon\n\t\ttype monitor\n"
        self.assertEqual(parse_iw_dev_monitor_interface(output), "wlan0mon")

    def test_parse_iw_dev_info_interface_type_managed_and_ap(self):
        self.assertEqual(
            parse_iw_dev_info_interface_type("\taddr 00:11:22\n\ttype managed\n"),
            "managed",
        )
        self.assertEqual(parse_iw_dev_info_interface_type("\ttype AP\n"), "ap")

    def test_get_interface_type_from_iw_dev_info(self):
        runner = FakeRunner()
        manager = WiFiAdapterManager(runner)

        class Result:
            returncode = 0
            stdout = "\tInterface wlan0\n\ttype monitor\n"
            stderr = ""

        runner.run = lambda *a, **k: Result()

        self.assertEqual(manager.get_interface_type("wlan0"), "monitor")

class WiFiAdapterManagerTests(unittest.TestCase):
    def test_start_monitor_mode_prefers_mon_suffix_directory(self):
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as tmp:
            nb = Path(tmp)
            (nb / "wlan0mon").mkdir()
            (nb / "wlan0mon" / "wireless").mkdir(parents=True)
            manager = WiFiAdapterManager(runner, sleep=lambda _: None, sys_class_net=nb)
            interface = manager.start_monitor_mode("wlan0")
            self.assertEqual(interface, "wlan0mon")
            self.assertIn(("run", ("airmon-ng", "start", "wlan0")), runner.calls)

    def test_start_monitor_mode_returns_other_monitor_ifname_from_iw(self):
        iw_dev = "phy#0\n\tInterface wlxtestmon\n\t\ttype monitor\n"
        runner = FakeRunner(outputs=[iw_dev] * 20)
        with tempfile.TemporaryDirectory() as tmp:
            nb = Path(tmp)
            (nb / "wlxtestmon").mkdir()
            (nb / "wlxtestmon" / "wireless").mkdir(parents=True)
            manager = WiFiAdapterManager(runner, sleep=lambda _: None, sys_class_net=nb)
            interface = manager.start_monitor_mode("wlan0")
            self.assertEqual(interface, "wlxtestmon")

    def test_set_managed_mode_runs_expected_core_commands(self):
        runner = FakeRunner()
        manager = WiFiAdapterManager(runner)

        interface = manager.set_managed_mode("wlan0mon")

        self.assertEqual(interface, "wlan0")
        self.assertIn(("run", ("airmon-ng", "stop", "wlan0mon")), runner.calls)
        self.assertIn(("run", ("iw", "wlan0", "set", "type", "managed")), runner.calls)

    def test_missing_tools(self):
        runner = FakeRunner(missing={"hashcat"})
        manager = WiFiAdapterManager(runner)

        self.assertEqual(manager.missing_tools(["airmon-ng", "hashcat"]), ["hashcat"])

    @patch("adapters.system_tools.wifi.list_wireless_interfaces_sysfs", return_value=["wlan99"])
    def test_list_wireless_interfaces_prefers_sysfs(self, _mock_sysfs):
        runner = FakeRunner()
        manager = WiFiAdapterManager(runner)
        self.assertEqual(manager.list_wireless_interfaces(), ["wlan99"])
        self.assertEqual(runner.calls, [])

    @patch("adapters.system_tools.wifi.list_wireless_interfaces_sysfs", return_value=[])
    def test_list_wireless_interfaces_falls_back_to_iw_dev(self, _mock_sysfs):
        runner = FakeRunner(
            outputs=[
                "lo        no wireless extensions.\n",
                "phy#0\n\tInterface wlan0\n",
            ]
        )
        manager = WiFiAdapterManager(runner)
        self.assertEqual(manager.list_wireless_interfaces(), ["wlan0"])
        check_calls = [c for c in runner.calls if c[0] == "check_output"]
        self.assertEqual(
            check_calls,
            [
                ("check_output", ("iwconfig",)),
                ("check_output", ("iw", "dev")),
            ],
        )


if __name__ == "__main__":
    unittest.main()
