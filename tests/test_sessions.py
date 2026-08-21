import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from reports import generate_security_report
from wifi.sessions import (
    KIND_AUTO_HACK,
    KIND_HANDSHAKE,
    KIND_HASHCAT,
    KIND_MITM,
    LabSession,
    attach_session,
    discover_lab_sessions,
    pick_hash_file,
    revalidate_session,
)


class SessionDiscoveryTests(unittest.TestCase):
    def test_discovers_handshake_auto_hack_mitm_and_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handshake = root / "handshake"
            session_dir = handshake / "Lab_aabbccddeeff_20260101_120000"
            session_dir.mkdir(parents=True)
            hash_path = session_dir / "pmkid.22000"
            hash_path.write_text("WPA*01*aabbccddeeff*ssid\n", encoding="utf-8")
            (session_dir / "capture_manifest.json").write_text(
                '{"status":"captured","best_verdict":"crackable","hash_file":"%s","target":{"ssid":"Lab","bssid":"aa:bb:cc:dd:ee:ff"}}'
                % hash_path,
                encoding="utf-8",
            )
            auto_hack = root / "auto_hack_sessions" / "20260101_130000"
            auto_hack.mkdir(parents=True)
            (auto_hack / "auto_hack_report.html").write_text("<html></html>", encoding="utf-8")
            mitm = root / "logs" / "mitm" / "20260101_140000"
            mitm.mkdir(parents=True)
            (mitm / "traffic.txt").write_text("ok\n", encoding="utf-8")
            job = SimpleNamespace(
                job_id="abc123",
                hash_file=str(hash_path),
                status="queued",
                created_at="2026-01-01T12:00:00",
                attack_mode=0,
                mode=22000,
            )

            sessions = discover_lab_sessions(
                handshake_dir=handshake,
                auto_hack_dir=root / "auto_hack_sessions",
                mitm_dir=root / "logs" / "mitm",
                hashcat_jobs=[job],
            )
            kinds = {item.kind for item in sessions}
            self.assertEqual(kinds, {KIND_HANDSHAKE, KIND_AUTO_HACK, KIND_MITM, KIND_HASHCAT})
            handshake_row = next(item for item in sessions if item.kind == KIND_HANDSHAKE)
            self.assertEqual(handshake_row.label, "Lab")
            self.assertEqual(handshake_row.hash_file, str(hash_path))
            self.assertEqual(pick_hash_file(session_dir), str(hash_path))

    def test_pick_hash_prefers_22000_over_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "capture.cap").write_bytes(b"cap")
            hashed = root / "export.22000"
            hashed.write_text("WPA*01\n", encoding="utf-8")
            self.assertEqual(pick_hash_file(root), str(hashed))

    def test_attach_dedupes_by_kind_and_path(self):
        session = LabSession(
            kind=KIND_MITM,
            path="/tmp/mitm",
            label="mitm",
            modified=1.0,
            status="logs",
            hash_file="",
            detail="1 file(s)",
        )
        once = attach_session([], session)
        twice = attach_session(once, session)
        self.assertEqual(len(once), 1)
        self.assertEqual(len(twice), 1)

    def test_revalidate_uses_injected_analyzer(self):
        with tempfile.TemporaryDirectory() as tmp:
            hashed = Path(tmp) / "lab.22000"
            hashed.write_text("WPA*01\n", encoding="utf-8")
            session = LabSession(
                kind=KIND_HANDSHAKE,
                path=str(hashed),
                label="lab",
                modified=1.0,
                status="file",
                hash_file=str(hashed),
                detail="",
            )

            class Report:
                verdict = "crackable"
                score = 91
                reasons = ("hash present",)

            result = revalidate_session(session, analyzer=lambda _path: Report())
            self.assertEqual(result["status"], "crackable")
            self.assertEqual(result["score"], 91)

    def test_mitm_revalidate_counts_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            mitm = Path(tmp)
            (mitm / "a.log").write_text("x", encoding="utf-8")
            session = LabSession(
                kind=KIND_MITM,
                path=str(mitm),
                label="mitm",
                modified=1.0,
                status="logs",
                hash_file="",
                detail="",
            )
            result = revalidate_session(session)
            self.assertEqual(result["status"], "logged")
            self.assertIn("1 MITM", result["detail"])


class SessionReportTests(unittest.TestCase):
    def test_html_report_includes_escaped_lab_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            (log_dir / "main.log").write_text("ok\n", encoding="utf-8")
            report = generate_security_report(
                log_dir,
                "20260506_120000",
                lab_sessions=[
                    {
                        "kind": "handshake",
                        "label": "Lab<script>",
                        "path": "/tmp/Lab<script>",
                        "status": "captured",
                        "hash_file": "/tmp/x.22000",
                        "detail": "ok",
                    }
                ],
            )
            html = report.read_text(encoding="utf-8")
            self.assertIn("Lab sessions", html)
            self.assertIn("Lab&lt;script&gt;", html)
            self.assertNotIn("Lab<script>", html)


if __name__ == "__main__":
    unittest.main()
