import tempfile
import unittest
from pathlib import Path

from app.services.attacks.eap_lab import (
    DEFAULT_EAP_SSID,
    build_eap_hostapd_conf,
    build_eap_user_file,
    openssl_self_signed_command,
    valid_eap_identity,
    valid_eap_password,
    write_eap_lab_material,
)


class EapLabBuilderTests(unittest.TestCase):
    def test_user_file_is_local_eap_server_not_radius(self):
        text = build_eap_user_file("labuser", "labpass")
        self.assertIn("* PEAP,TTLS", text)
        self.assertIn('"labuser" MSCHAPV2 "labpass" [2]', text)
        self.assertIn("not a radius proxy", text.lower())

    def test_hostapd_uses_wpa_eap_without_psk(self):
        conf = build_eap_hostapd_conf(
            ap_iface="wlan1",
            ssid=DEFAULT_EAP_SSID,
            channel=6,
            eap_user_file=Path("/tmp/eap/hostapd.eap_user"),
            ca_cert=Path("/tmp/eap/server.pem"),
            server_cert=Path("/tmp/eap/server.pem"),
            private_key=Path("/tmp/eap/server.key"),
            isolate_clients=True,
        )
        self.assertIn("wpa_key_mgmt=WPA-EAP", conf)
        self.assertIn("eap_server=1", conf)
        self.assertIn("ieee8021x=1", conf)
        self.assertIn("ap_isolate=1", conf)
        self.assertNotIn("WPA-PSK", conf)
        self.assertNotIn("wpa_passphrase", conf)

    def test_openssl_command_is_self_signed_and_unencrypted(self):
        argv = openssl_self_signed_command(Path("/tmp/eap"))
        self.assertEqual(argv[0], "openssl")
        self.assertIn("-x509", argv)
        self.assertIn("-nodes", argv)
        self.assertNotIn("-passin", argv)
        self.assertNotIn("-passout", argv)

    def test_rejects_quote_in_identity(self):
        self.assertFalse(valid_eap_identity('bad"id'))
        self.assertFalse(valid_eap_password('bad"pw'))
        with self.assertRaises(ValueError):
            build_eap_user_file('bad"id', "ok")

    def test_write_material_uses_injected_openssl(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert_dir = Path(tmp)

            class Result:
                returncode = 0

            def runner(argv):
                self.assertEqual(argv[0], "openssl")
                (cert_dir / "server.key").write_text("key", encoding="utf-8")
                (cert_dir / "server.pem").write_text("pem", encoding="utf-8")
                return Result()

            material = write_eap_lab_material(
                cert_dir,
                identity="labuser",
                password="labpass",
                run=runner,
            )
            self.assertTrue(material.user_file.exists())
            self.assertIn("PEAP,TTLS", material.user_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
