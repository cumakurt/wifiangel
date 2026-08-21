from pathlib import Path
from types import SimpleNamespace
import unittest

from cleanup import resolve_evil_twin_log_dir
from app.services.system.cleanup_flow import run_auto_hack_cleanup, run_kill_processes


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


if __name__ == "__main__":
    unittest.main()
