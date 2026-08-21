import tempfile
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from app.services.attacks.evil_twin_lab import (
    DhcpLease,
    build_dnsmasq_conf,
    build_hostapd_conf,
    evaluate_isolation_check,
    isolation_ping_command,
    parse_dnsmasq_leases,
    probe_lease_reachability,
)
from app.services.attacks.lab_portal import LabCaptivePortal, _PAGE


class EvilTwinLabConfigTests(unittest.TestCase):
    def test_hostapd_isolation_flag(self):
        conf = build_hostapd_conf(
            ap_iface="wlan1",
            ssid="LabAP",
            channel=6,
            isolate_clients=True,
        )
        self.assertIn("ap_isolate=1", conf)
        self.assertIn("ssid=LabAP", conf)
        self.assertNotIn("wpa=2", conf)

    def test_dnsmasq_portal_sinks_all_names(self):
        conf = build_dnsmasq_conf(ap_iface="wlan1", log_dir=Path("/tmp/et"), portal=True)
        self.assertIn("address=/#/192.168.1.1", conf)
        self.assertNotIn("server=8.8.8.8", conf)

    def test_dnsmasq_without_portal_forwards_dns(self):
        conf = build_dnsmasq_conf(ap_iface="wlan1", log_dir=Path("/tmp/et"), portal=False)
        self.assertIn("server=8.8.8.8", conf)
        self.assertNotIn("address=/#/", conf)


class IsolationCheckTests(unittest.TestCase):
    def test_parse_leases_skips_gateway(self):
        text = (
            "1000 aa:aa:aa:aa:aa:aa 192.168.1.1 router *\n"
            "1001 bb:bb:bb:bb:bb:bb 192.168.1.2 phone *\n"
            "1002 cc:cc:cc:cc:cc:cc 192.168.1.3 laptop *\n"
        )
        leases = parse_dnsmasq_leases(text)
        self.assertEqual([item.ip for item in leases], ["192.168.1.2", "192.168.1.3"])

    def test_ping_command_binds_ap_iface(self):
        self.assertEqual(
            isolation_ping_command("192.168.1.4", "wlan1"),
            ["ping", "-c", "1", "-W", "1", "-I", "wlan1", "192.168.1.4"],
        )

    def test_two_leases_reachable_passes(self):
        leases = [
            DhcpLease("aa:aa:aa:aa:aa:aa", "192.168.1.2", "a"),
            DhcpLease("bb:bb:bb:bb:bb:bb", "192.168.1.3", "b"),
        ]
        check = evaluate_isolation_check(
            leases,
            {"192.168.1.2": True, "192.168.1.3": True},
            isolated=True,
        )
        self.assertEqual(check.status, "pass")
        self.assertIn("ap_isolate", check.detail)

    def test_pending_without_two_leases(self):
        leases = [DhcpLease("aa:aa:aa:aa:aa:aa", "192.168.1.2", "a")]
        check = evaluate_isolation_check(leases, {"192.168.1.2": True}, isolated=True)
        self.assertEqual(check.status, "pending")

    def test_skipped_when_isolation_off(self):
        check = evaluate_isolation_check([], {}, isolated=False)
        self.assertEqual(check.status, "skipped")

    def test_probe_uses_injected_runner(self):
        seen = []

        class Result:
            returncode = 0

        def runner(argv):
            seen.append(argv)
            return Result()

        out = probe_lease_reachability(["192.168.1.2", "192.168.1.3"], "wlan1", run=runner)
        self.assertEqual(out, {"192.168.1.2": True, "192.168.1.3": True})
        self.assertEqual(seen[0][-1], "192.168.1.2")


class LabPortalTests(unittest.TestCase):
    def test_page_is_lab_notice_without_password_field(self):
        lowered = _PAGE.lower()
        self.assertIn("authorized lab", lowered)
        self.assertNotIn("password", lowered)
        self.assertNotIn('type="password"', lowered)

    def test_http_hit_is_logged(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "portal.jsonl"
            portal = LabCaptivePortal("127.0.0.1", log_path, port=0)
            portal.start()
            try:
                port = portal.bound_port
                with urlopen(f"http://127.0.0.1:{port}/generate_204", timeout=2) as resp:
                    body = resp.read().decode("utf-8")
                self.assertIn("WiFiAngel authorized lab portal", body)
                req = Request(f"http://127.0.0.1:{port}/continue", data=b"ack=1", method="POST")
                with urlopen(req, timeout=2):
                    pass
                self.assertGreaterEqual(portal.hit_count, 2)
                logged = log_path.read_text(encoding="utf-8")
                self.assertIn("generate_204", logged)
            finally:
                portal.stop()


if __name__ == "__main__":
    unittest.main()
