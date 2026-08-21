import subprocess
import unittest
from unittest.mock import MagicMock

from adapters.system_tools import CommandRunner, terminate_process


class CommandRunnerTests(unittest.TestCase):
    def test_dry_run_does_not_execute_command(self):
        runner = CommandRunner(dry_run=True)

        result = runner.run(["definitely-not-a-real-command"])

        self.assertTrue(result.ok)
        self.assertTrue(result.dry_run)
        self.assertEqual(result.args, ("definitely-not-a-real-command",))

    def test_string_commands_are_split_safely(self):
        runner = CommandRunner(dry_run=True)

        result = runner.run("iwconfig wlan0 channel 6")

        self.assertEqual(result.args, ("iwconfig", "wlan0", "channel", "6"))

    def test_set_wireless_channel_prefers_iw(self):
        runner = CommandRunner(dry_run=True)
        result = runner.set_wireless_channel("wlan0mon", 36)
        self.assertTrue(result.ok)
        self.assertEqual(result.args, ("iw", "dev", "wlan0mon", "set", "channel", "36"))

    def test_kill_processes_uses_exact_name_match(self):
        runner = CommandRunner(dry_run=True)
        runner.kill_processes(["airodump-ng"])
        # dry-run still records via run(); last call is the force kill
        result = runner.run(["pkill", "-9", "-x", "airodump-ng"])
        self.assertEqual(result.args, ("pkill", "-9", "-x", "airodump-ng"))

    def test_terminate_process_skips_none_and_exited(self):
        terminate_process(None)
        proc = MagicMock()
        proc.poll.return_value = 0
        terminate_process(proc)
        proc.terminate.assert_not_called()

    def test_terminate_process_kills_after_timeout(self):
        proc = MagicMock()
        proc.poll.return_value = None
        proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="x", timeout=2), None]
        terminate_process(proc, timeout=0.01)
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()


if __name__ == "__main__":
    unittest.main()
