import unittest
from unittest.mock import patch

from app.safety import confirm_legal_use, redact_sensitive_text, sanitize_filename


class DummyConsole:
    def __init__(self):
        self.messages = []

    def print(self, message):
        self.messages.append(message)


class SafetyHelperTests(unittest.TestCase):
    def test_sanitize_filename_removes_path_and_control_chars(self):
        self.assertEqual(sanitize_filename("../Lab\nSSID:01"), "Lab_SSID_01")

    def test_redact_sensitive_text_keeps_context(self):
        redacted = redact_sensitive_text("POST password=supersecret token:abc123 note=visible")

        self.assertIn("password=<redacted>", redacted)
        self.assertIn("token:<redacted>", redacted)
        self.assertIn("note=visible", redacted)
        self.assertNotIn("supersecret", redacted)
        self.assertNotIn("abc123", redacted)

    def test_startup_legal_confirmation_accepts_yes(self):
        with patch("app.safety.Prompt.ask", return_value="Y"):
            self.assertTrue(confirm_legal_use(DummyConsole()))

    def test_startup_legal_confirmation_rejects_other_input(self):
        with patch("app.safety.Prompt.ask", return_value="no"):
            self.assertFalse(confirm_legal_use(DummyConsole()))


if __name__ == "__main__":
    unittest.main()
