from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from wifi.advanced_tools import (
    analyze_rf_environment,
    analyze_wps_risk,
    build_wordlist_intelligence,
    check_capture_health,
    optimize_channel_hopper,
    validate_handshake_pmkid,
)


class _FakeResult:
    def __init__(self, ok: bool = True, stdout: str = "", stderr: str = "") -> None:
        self.ok = ok
        self.stdout = stdout
        self.stderr = stderr


class _FakeRunner:
    def __init__(self, tools: dict[str, bool], outputs: dict[str, _FakeResult]) -> None:
        self._tools = tools
        self._outputs = outputs

    def which(self, command: str):
        return f"/usr/bin/{command}" if self._tools.get(command, False) else None

    def run(self, command, capture_output: bool = False):  # noqa: ARG002
        cmd = command[0]
        return self._outputs.get(cmd, _FakeResult(ok=False, stderr="tool error"))


class AdvancedToolsTests(unittest.TestCase):
    def test_rf_environment_profiler_ranks_low_noise_channels(self):
        report = analyze_rf_environment(
            {
                "aa": {"channel": 1, "signal": -42},
                "bb": {"channel": 1, "signal": -50},
                "cc": {"channel": 6, "signal": -78},
                "dd": {"channel": 11, "signal": -81},
            }
        )
        self.assertGreaterEqual(len(report.channels), 3)
        self.assertIn(11, report.best_attack_channels)

    def test_handshake_validator_pro_combines_quality_and_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hash.22000"
            path.write_text(
                "WPA*01*abcdefabcdefabcdefabcdefabcdefab*aabbccddeeff*112233445566*4c61624e6574***\n",
                encoding="utf-8",
            )
            runner = _FakeRunner(
                tools={"aircrack-ng": True, "hcxhashtool": True},
                outputs={
                    "aircrack-ng": _FakeResult(stdout="1 handshake"),
                    "hcxhashtool": _FakeResult(stdout="PMKID data found"),
                },
            )
            report = validate_handshake_pmkid(path, expected_bssid="aa:bb:cc:dd:ee:ff", command_runner=runner)
            self.assertEqual(report.verdict, "valid")
            self.assertEqual(report.aircrack_result, "valid")
            self.assertEqual(report.hcx_result, "valid")

    def test_wordlist_intelligence_includes_ssid_and_vendor_mutations(self):
        words = build_wordlist_intelligence(ssid="OfficeNet", bssid="3c:07:54:11:22:33", max_words=80)
        values = {item.value for item in words}
        self.assertIn("officenet", values)
        self.assertTrue(any(value.startswith("apple") for value in values))

    def test_capture_health_checker_detects_duplicates_and_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capture.22000"
            path.write_text(
                "\n".join(
                    [
                        "WPA*01*abcdefabcdefabcdefabcdefabcdefab*aabbccddeeff*112233445566*4c6162***",
                        "WPA*01*abcdefabcdefabcdefabcdefabcdefab*aabbccddeeff*112233445566*4c6162***",
                        "BROKEN*LINE",
                    ]
                ),
                encoding="utf-8",
            )
            report = check_capture_health(path)
            self.assertEqual(report.duplicate_records, 1)
            self.assertEqual(report.corrupted_records, 1)
            self.assertEqual(report.verdict, "warning")

    def test_wps_risk_analyzer_scores_unlocked_strong_target_high(self):
        report = analyze_wps_risk(
            {"ssid": "Lab", "bssid": "aa:bb", "signal": -48, "wps": True, "clients": {"c1", "c2", "c3", "c4"}},
            lock_state="unlocked",
            rate_limit_hint="low",
        )
        self.assertGreaterEqual(report.risk_score, 80)
        self.assertEqual(report.success_window, "high")

    def test_channel_hopper_optimizer_creates_adaptive_intervals(self):
        optimized = optimize_channel_hopper(
            {
                "aa": {"channel": 6, "signal": -44, "clients": {"c1", "c2"}, "wps": True},
                "bb": {"channel": 11, "signal": -80, "clients": set(), "wps": False},
            }
        )
        self.assertGreater(len(optimized), 0)
        self.assertLessEqual(optimized[0].hop_interval_ms, optimized[-1].hop_interval_ms)


if __name__ == "__main__":
    unittest.main()
