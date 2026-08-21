from types import SimpleNamespace
import unittest

from app.services.system.adapter_roles import dedicated_ap_radio, resolve_ap_interface, role_exclude_ifaces


class AdapterRoleTests(unittest.TestCase):
    def test_ap_falls_back_to_capture(self):
        app = SimpleNamespace(interface_name="wlan0", ap_interface=None)
        self.assertEqual(resolve_ap_interface(app), "wlan0")
        self.assertFalse(dedicated_ap_radio(app))

    def test_dedicated_ap_radio(self):
        app = SimpleNamespace(interface_name="wlan0mon", ap_interface="wlan1")
        self.assertEqual(resolve_ap_interface(app), "wlan1")
        self.assertTrue(dedicated_ap_radio(app))
        self.assertEqual(role_exclude_ifaces(app), {"wlan0mon", "wlan1"})

    def test_same_name_is_not_dedicated(self):
        app = SimpleNamespace(interface_name="wlan0", ap_interface="wlan0")
        self.assertFalse(dedicated_ap_radio(app))
        self.assertEqual(resolve_ap_interface(app), "wlan0")


if __name__ == "__main__":
    unittest.main()
