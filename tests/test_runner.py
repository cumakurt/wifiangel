import unittest

from adapters.system_tools import CommandRunner


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


if __name__ == "__main__":
    unittest.main()
