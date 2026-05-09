from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from app.services.attacks.handshake_engine import (
    CapturePolicy,
    DeauthStrategy,
    analyze_best_capture,
    build_capture_target,
    choose_deauth_strategy,
    create_capture_session,
    promote_best_capture,
    should_stop_capture,
    update_session_quality,
    write_manifest,
)
from wifi.capture_quality import CaptureQualityReport


class HandshakeEngineTests(unittest.TestCase):
    def test_build_capture_target_normalizes_network_fields(self):
        target = build_capture_target(
            "aa:bb:cc:dd:ee:ff",
            {"ssid": "Lab", "channel": "6", "cipher": "WPA2", "clients": {"c2", "c1"}},
        )

        self.assertEqual(target.bssid, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(target.channel, 6)
        self.assertEqual(target.clients, ("c1", "c2"))

    def test_choose_deauth_strategy_disables_deauth_for_pmf_required(self):
        target = build_capture_target(
            "aa:bb:cc:dd:ee:ff",
            {"ssid": "Lab", "channel": 6, "cipher": "WPA3", "clients": {"11:22:33:44:55:66"}},
        )

        strategy = choose_deauth_strategy(
            target,
            {"pmf_required": True, "transition_mode": False},
            {"aa:bb:cc:dd:ee:ff": {"ssid": "Lab", "signal": -40, "clients": set(target.clients)}},
            CapturePolicy(),
        )

        self.assertEqual(strategy.mode, "passive")
        self.assertEqual(strategy.clients, ())

    def test_choose_deauth_strategy_prioritizes_observed_clients(self):
        target = build_capture_target(
            "aa:bb:cc:dd:ee:ff",
            {
                "ssid": "Lab",
                "channel": 6,
                "cipher": "WPA2",
                "clients": {"3c:07:54:11:22:33", "00:11:22:33:44:55"},
            },
        )

        strategy = choose_deauth_strategy(
            target,
            {"pmf_required": False, "transition_mode": False},
            {"aa:bb:cc:dd:ee:ff": {"ssid": "Lab", "signal": -40, "clients": set(target.clients)}},
            CapturePolicy(max_clients_per_burst=1),
        )

        self.assertEqual(strategy.mode, "targeted")
        self.assertEqual(len(strategy.clients), 1)

    def test_should_stop_on_crackable_quality_after_startup_delay(self):
        report = _quality_report(score=91, verdict="crackable")

        self.assertFalse(should_stop_capture(report, CapturePolicy(), 4.9))
        self.assertTrue(should_stop_capture(report, CapturePolicy(), 5.0))

    def test_manifest_writes_quality_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("app.services.attacks.handshake_engine.HANDSHAKE_DIR", Path(tmp)):
                target = build_capture_target(
                    "aa:bb:cc:dd:ee:ff",
                    {"ssid": "Lab", "channel": 6, "cipher": "WPA2", "clients": set()},
                )
                session = create_capture_session("wlan0mon", target)
                session.deauth_strategy = DeauthStrategy("broadcast", (), 1, 15, "test")
                update_session_quality(session, _quality_report(score=82, verdict="crackable"))
                write_manifest(session)

                data = json.loads(session.manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(data["best_score"], 82)
        self.assertEqual(data["best_verdict"], "crackable")
        self.assertEqual(data["deauth_strategy"]["mode"], "broadcast")
        self.assertTrue(data["pmkid_hash"].endswith(".22000"))

    def test_analyze_best_capture_includes_pmkid_hash_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("app.services.attacks.handshake_engine.HANDSHAKE_DIR", Path(tmp)):
                target = build_capture_target(
                    "aa:bb:cc:dd:ee:ff",
                    {"ssid": "Lab", "channel": 6, "cipher": "WPA2", "clients": set()},
                )
                session = create_capture_session("wlan0mon", target)
                session.pmkid_hash.write_text(
                    "WPA*01*00112233445566778899aabbccddeeff*"
                    "aabbccddeeff*112233445566*4c6162\n",
                    encoding="utf-8",
                )

                report = analyze_best_capture(session, target)

        self.assertIsNotNone(report)
        self.assertEqual(report.verdict, "crackable")
        self.assertEqual(report.format, "hashcat-22000")

    def test_promote_best_capture_copies_best_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "capture.cap"
            source.write_bytes(b"capture")
            with patch("app.services.attacks.handshake_engine.HANDSHAKE_DIR", root):
                target = build_capture_target(
                    "aa:bb:cc:dd:ee:ff",
                    {"ssid": "Lab", "channel": 6, "cipher": "WPA2", "clients": set()},
                )
                session = create_capture_session("wlan0mon", target)
                report = _quality_report(path=str(source), score=65, verdict="partial")

                promoted = promote_best_capture(session, target, report)

                self.assertIsNotNone(promoted)
                self.assertTrue(promoted.exists())
                self.assertEqual(promoted.read_bytes(), b"capture")


def _quality_report(path="capture.cap", score=50, verdict="partial"):
    return CaptureQualityReport(
        path=path,
        score=score,
        verdict=verdict,
        format="pcap",
        frame_counts={"eapol": 2},
        eapol_messages={"M1": 1, "M2": 1},
        replay_pairs=1,
        pmkid_records=0,
        eapol_hash_records=0,
        bssid_matched=True,
        reasons=("test",),
    )


if __name__ == "__main__":
    unittest.main()
