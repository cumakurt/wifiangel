from types import SimpleNamespace
import threading
import unittest
from unittest.mock import patch

from app.services.attacks.mitm_service import probe_subnet_hosts, restore_settings
from cleanup.iptables import MITM_NAT_CHAIN


class _Console:
    def print(self, *_args, **_kwargs):
        return None


class MitmServiceTests(unittest.TestCase):
    def test_probe_subnet_hosts_skips_self_and_collects_hits(self):
        seen: list[str] = []

        def fake_reachable(ip, *, timeout=1.5):
            seen.append(ip)
            return ip == "192.168.9.2"

        with patch("app.services.attacks.mitm_service.host_is_reachable", side_effect=fake_reachable):
            found = probe_subnet_hosts(
                "192.168.9.",
                skip_ip="192.168.9.1",
                cancel=threading.Event(),
                workers=8,
            )

        self.assertNotIn("192.168.9.1", seen)
        self.assertEqual(len(seen), 253)
        self.assertEqual(found, ["192.168.9.2"])

    def test_restore_settings_never_flushes_host_tables(self):
        calls: list[list[str]] = []

        class Runner:
            def run(self, command, **_kwargs):
                calls.append(list(command))
                return SimpleNamespace(ok=True, returncode=0)

        iptables_calls: list[list[str]] = []

        def fake_remove(*, out_iface=None, run=None):
            iptables_calls.append(["remove", out_iface or ""])

        app = SimpleNamespace(
            console=_Console(),
            logger=SimpleNamespace(error=lambda *_a, **_k: None),
            command_runner=Runner(),
            _mitm_out_iface="eth0",
        )
        with patch("app.services.attacks.mitm_service.remove_mitm_nat", side_effect=fake_remove):
            restore_settings(app, "0", None, bettercap_process=None)

        self.assertFalse(any(cmd == ["iptables", "-F"] for cmd in calls))
        self.assertFalse(any(cmd[:4] == ["iptables", "-t", "nat", "-F"] and len(cmd) == 4 for cmd in calls))
        self.assertFalse(any("iptables-restore" in cmd for cmd in calls))
        self.assertEqual(iptables_calls, [["remove", "eth0"]])
        self.assertIsNone(app._mitm_out_iface)
        self.assertEqual(MITM_NAT_CHAIN, "WIFIANGEL_MITM_NAT")


if __name__ == "__main__":
    unittest.main()
