from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cleanup import resolve_evil_twin_log_dir
from app.services.system.cleanup_flow import run_auto_hack_cleanup, run_kill_processes
from app.services.system.lifecycle_service import cleanup_and_exit


class CleanupPathTests(unittest.TestCase):
    def test_resolves_default_evil_twin_log_dir(self):
        self.assertEqual(
            resolve_evil_twin_log_dir(Path("logs/session")),
            Path("logs/session/evil_twin"),
        )

    def test_preserves_explicit_log_dir(self):
        explicit = Path("/tmp/wifiangel/evil_twin")

        self.assertEqual(resolve_evil_twin_log_dir(Path("logs/session"), explicit), explicit)


class AutoHackCleanupTests(unittest.TestCase):
    def test_cleanup_uses_exact_process_names(self):
        calls = []

        class Runner:
            def kill_processes(self, names, *, force=True):
                calls.append((tuple(names), force))

        app = SimpleNamespace(command_runner=Runner(), logger=SimpleNamespace(info=lambda *_a, **_k: None, error=lambda *_a, **_k: None))
        run_auto_hack_cleanup(app)
        self.assertEqual(calls[0][0], ("airodump-ng", "aireplay-ng", "hcxdumptool", "hashcat", "aircrack-ng"))
        run_kill_processes(app, ["reaver"])
        self.assertEqual(calls[1][0], ("reaver",))


class LifecycleCleanupTests(unittest.TestCase):
    def test_cleanup_and_exit_uses_nonzero_code_and_drops_nat(self):
        removed = []

        class Adapter:
            def set_managed_mode(self, iface):
                return iface

        app = SimpleNamespace(
            scanning=True,
            interface_name="wlan0mon",
            _mitm_out_iface="eth0",
            console=SimpleNamespace(print=lambda *_a, **_k: None),
            logger=SimpleNamespace(info=lambda *_a, **_k: None, error=lambda *_a, **_k: None),
            wifi_adapter=Adapter(),
        )

        with (
            patch("app.services.system.lifecycle_service.time.sleep", return_value=None),
            patch("app.services.system.lifecycle_service.remove_evil_twin_nat", side_effect=lambda: removed.append("et")),
            patch("app.services.system.lifecycle_service.remove_mitm_nat", side_effect=lambda **_k: removed.append("mitm")),
            patch("app.services.system.lifecycle_service.sys.exit", side_effect=SystemExit) as exit_mock,
        ):
            with self.assertRaises(SystemExit):
                cleanup_and_exit(app, exit_code=1)

        exit_mock.assert_called_once_with(1)
        self.assertEqual(removed, ["et", "mitm"])
        self.assertFalse(app.scanning)


if __name__ == "__main__":
    unittest.main()
