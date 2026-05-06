from pathlib import Path
import tempfile
import unittest

from reports import generate_security_report


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


if __name__ == "__main__":
    unittest.main()
