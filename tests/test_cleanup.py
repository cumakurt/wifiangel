from pathlib import Path
import unittest

from cleanup import resolve_evil_twin_log_dir


class CleanupPathTests(unittest.TestCase):
    def test_resolves_default_evil_twin_log_dir(self):
        self.assertEqual(
            resolve_evil_twin_log_dir(Path("logs/session")),
            Path("logs/session/evil_twin"),
        )

    def test_preserves_explicit_log_dir(self):
        explicit = Path("/tmp/wifiangel/evil_twin")

        self.assertEqual(resolve_evil_twin_log_dir(Path("logs/session"), explicit), explicit)


if __name__ == "__main__":
    unittest.main()
