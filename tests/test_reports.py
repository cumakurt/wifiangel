from pathlib import Path
import tempfile
import unittest

from reports import generate_security_report
from app.services.attacks.auto_hack_orchestrator import generate_html_report


class DummyLogger:
    def info(self, _message):
        pass

    def error(self, _message):
        pass


class DummyApp:
    def __init__(self):
        self.networks = {"aa:bb:cc:dd:ee:ff": {"ssid": "Lab"}}
        self.logger = DummyLogger()


class ReportGenerationTests(unittest.TestCase):
    def test_report_escapes_log_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            (log_dir / "main.log").write_text(
                "2026-05-06 12:00:00 - INFO - <script>alert(1)</script>\n",
                encoding="utf-8",
            )

            report = generate_security_report(log_dir, "20260506_120000")
            html = report.read_text(encoding="utf-8")

            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
            self.assertNotIn("<script>alert(1)</script>", html)

    def test_auto_assessment_report_escapes_html_but_shows_passphrase(self):
        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / "20260509_120000"
            session_dir.mkdir()
            report = session_dir / "auto_hack_report.html"

            generate_html_report(
                DummyApp(),
                session_dir,
                [
                    (
                        "aa:bb:cc:dd:ee:ff",
                        {"ssid": "Lab<script>", "cipher": "WPA2"},
                        {
                            "handshake_status": "[green]Captured",
                            "pmkid_status": "[red]Failed",
                            "password": "Secret<Pass>&1",
                        },
                    )
                ],
                report,
            )
            html = report.read_text(encoding="utf-8")

            self.assertIn("Lab&lt;script&gt;", html)
            self.assertIn("Secret&lt;Pass&gt;&amp;1", html)
            self.assertNotIn("Lab<script>", html)
            self.assertNotIn("<redacted", html)


if __name__ == "__main__":
    unittest.main()
