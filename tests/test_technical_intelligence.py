from pathlib import Path
import tempfile
import unittest

from adapters.system_tools.capabilities import parse_iw_list_capabilities
from attacks.hashcat_jobs import HashcatJobStore
from wifi.artifacts import best_artifacts_by_identity, index_capture_artifacts
from wifi.capture_quality import analyze_capture_quality, parse_eapol_key_frame
from wifi.channel_hopper import build_adaptive_channel_plan
from wifi.client_profiler import build_client_profiles, vendor_from_mac
from wifi.frame_intelligence import parse_rsn_information, summarize_network_security
from wifi.telemetry import PacketRateCounter


def rsn_info(akm_type=8, capabilities=0x00C0):
    return (
        b"\x01\x00"
        b"\x00\x0f\xac\x04"
        b"\x01\x00"
        b"\x00\x0f\xac\x04"
        b"\x01\x00"
        + bytes([0x00, 0x0F, 0xAC, akm_type])
        + capabilities.to_bytes(2, "little")
    )


class FakePacket:
    type = 0
    subtype = 8

    def haslayer(self, name):
        return False

    def getlayer(self, name):
        return None


class TechnicalIntelligenceTests(unittest.TestCase):
    def test_rsn_profile_detects_sae_and_pmf(self):
        profile = parse_rsn_information(rsn_info())

        self.assertIsNotNone(profile)
        self.assertIn("SAE", profile.akm_suites)
        self.assertTrue(profile.wpa3_capable)
        self.assertTrue(profile.pmf_capable)
        self.assertTrue(profile.pmf_required)

    def test_security_summary_detects_transition_mode(self):
        summary = summarize_network_security({"ssid": "Lab", "cipher": "WPA2/WPA3/SAE"})

        self.assertTrue(summary["wpa3"])
        self.assertTrue(summary["transition_mode"])

    def test_hash_capture_quality_scores_22000(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hash.22000"
            path.write_text(
                "WPA*01*abcdefabcdefabcdefabcdefabcdefab*aabbccddeeff*112233445566*4c61624e6574***\n",
                encoding="utf-8",
            )

            report = analyze_capture_quality(path, bssid="aa:bb:cc:dd:ee:ff", essid="LabNet")

            self.assertEqual(report.pmkid_records, 1)
            self.assertTrue(report.bssid_matched)
            self.assertGreaterEqual(report.score, 80)

    def test_eapol_key_frame_classification(self):
        raw = b"\x02\x03\x00_\x02" + (0x0080).to_bytes(2, "big") + b"\x00\x00" + (7).to_bytes(8, "big")

        parsed = parse_eapol_key_frame(raw)

        self.assertEqual(parsed.message, "M1")
        self.assertEqual(parsed.replay_counter, 7)

    def test_adaptive_channel_plan_prioritizes_clients(self):
        networks = {
            "aa": {"channel": 6, "signal": -45, "clients": {"c1", "c2"}, "wps": True},
            "bb": {"channel": 11, "signal": -80, "clients": set(), "wps": False},
        }

        plan = build_adaptive_channel_plan(networks)

        self.assertEqual(plan[0].channel, 6)
        self.assertGreater(plan[0].dwell_ms, plan[-1].dwell_ms)

    def test_artifact_index_deduplicates_and_keeps_best(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            content = "WPA*01*abcdefabcdefabcdefabcdefabcdefab*aabbccddeeff*112233445566*4c6162***\n"
            first = root / "pmkid_Lab_aabbccddeeff.22000"
            duplicate = root / "copy.22000"
            first.write_text(content, encoding="utf-8")
            duplicate.write_text(content, encoding="utf-8")

            artifacts = index_capture_artifacts(root)
            best = best_artifacts_by_identity(artifacts)

            self.assertEqual(len(artifacts), 1)
            self.assertEqual(len(best), 1)

    def test_hashcat_job_store_prevents_duplicate_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hash_file = root / "hash.22000"
            wordlist = root / "words.txt"
            hash_file.write_text("hash", encoding="utf-8")
            wordlist.write_text("password123\n", encoding="utf-8")
            store = HashcatJobStore(root / "jobs.json")

            first = store.create_job(hash_file=hash_file, wordlist=wordlist, mode=22000)
            second = store.create_job(hash_file=hash_file, wordlist=wordlist, mode=22000)

            self.assertEqual(first.job_id, second.job_id)
            self.assertIn("--session", first.command())

    def test_interface_capability_parser(self):
        output = """
Supported interface modes:
         * managed
         * AP
         * monitor
Band 2:
         * 5180 MHz [36]
HT Capabilities:
VHT Capabilities:
"""

        caps = parse_iw_list_capabilities(output, interface="wlan0", interface_type="managed")

        self.assertTrue(caps.supports_monitor)
        self.assertTrue(caps.supports_ap)
        self.assertTrue(caps.supports_5ghz)
        self.assertIn(36, caps.channels)

    def test_client_profiler_scores_clients(self):
        profiles = build_client_profiles(
            {
                "aa:bb:cc:dd:ee:ff": {
                    "ssid": "Lab",
                    "signal": -42,
                    "clients": {"3c:07:54:11:22:33"},
                }
            }
        )

        self.assertEqual(profiles[0].vendor, "Apple")
        self.assertGreater(profiles[0].target_score, 0)
        self.assertEqual(vendor_from_mac("00:00:00:00:00:00"), "Unknown")

    def test_packet_rate_counter(self):
        counter = PacketRateCounter()
        counter.observe_packet(FakePacket())

        snapshot = counter.snapshot(2)

        self.assertEqual(snapshot.counts["beacon"], 1)
        self.assertEqual(snapshot.rates_per_second["beacon"], 0.5)


if __name__ == "__main__":
    unittest.main()
