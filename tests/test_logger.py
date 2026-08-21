import logging
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from app.logger import Logger


class _FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 5, 9, 12, 0, 0)


class LoggerTests(unittest.TestCase):
    def tearDown(self):
        for name in (
            "WiFiAngel",
            "WiFiAngel.Attacks",
            "WiFiAngel.Networks",
            "WiFiAngel.Clients",
            "WiFiAngel.EvilTwin",
            "WiFiAngel.DNS",
            "WiFiAngel.Traffic",
        ):
            logger = logging.getLogger(name)
            logger.handlers.clear()
            logger.propagate = True

    def test_child_loggers_do_not_propagate_or_duplicate_handlers(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("app.logger.LOGS_ROOT", Path(tmp)), patch("app.logger.datetime", _FrozenDateTime):
                first = Logger()
                second = Logger()
                self.assertFalse(first.attack_logger.propagate)
                self.assertFalse(first.logger.propagate)
                self.assertEqual(len(first.attack_logger.handlers), 1)
                self.assertIs(first.attack_logger.handlers[0], second.attack_logger.handlers[0])

    def test_log_evil_twin_error_flag_uses_error_level(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("app.logger.LOGS_ROOT", Path(tmp)):
                logger = Logger()
                logger.log_evil_twin("boom", error=True)
                text = logger.evil_twin_log.read_text(encoding="utf-8")
                self.assertIn("boom", text)
                main = logger.main_log.read_text(encoding="utf-8")
                self.assertIn("ERROR", main)
                self.assertIn("Evil Twin: boom", main)
