import unittest

from cleanup.iptables import (
    FILTER_CHAIN,
    INPUT_CHAIN,
    LAN_CIDR,
    NAT_CHAIN,
    PRE_CHAIN,
    apply_evil_twin_nat,
    evil_twin_nat_setup_commands,
    evil_twin_nat_teardown_commands,
    remove_evil_twin_nat,
)


def _is_global_table_flush(command: list[str]) -> bool:
    if not command or command[0] != "iptables":
        return False
    for flag in ("-F", "-X"):
        if flag not in command:
            continue
        idx = command.index(flag)
        has_chain = idx + 1 < len(command) and not command[idx + 1].startswith("-")
        if not has_chain:
            return True
    return False


class EvilTwinIptablesTests(unittest.TestCase):
    def test_setup_without_wan_is_empty(self):
        self.assertEqual(
            evil_twin_nat_setup_commands(ap_iface="wlan0", wan_iface=None),
            [],
        )

    def test_setup_with_wan_uses_dedicated_chains_only(self):
        commands = evil_twin_nat_setup_commands(ap_iface="wlan0", wan_iface="eth0")
        joined = [" ".join(cmd) for cmd in commands]

        self.assertTrue(any(cmd[0] == "iptables" for cmd in commands))
        self.assertFalse(any(_is_global_table_flush(cmd) for cmd in commands))
        self.assertIn(f"iptables -N {FILTER_CHAIN}", joined)
        self.assertIn(f"iptables -t nat -N {NAT_CHAIN}", joined)
        self.assertTrue(any("-j" in cmd and FILTER_CHAIN in cmd and "-I" in cmd for cmd in commands))
        self.assertTrue(any(cmd[-1] == "MASQUERADE" and NAT_CHAIN in cmd for cmd in commands))
        self.assertTrue(any("--ctstate" in cmd and "RELATED,ESTABLISHED" in cmd for cmd in commands))
        self.assertTrue(all(LAN_CIDR in cmd for cmd in commands if "-j" in cmd and cmd[-1] in {FILTER_CHAIN, NAT_CHAIN, "ACCEPT", "MASQUERADE"}))

    def test_setup_rejects_unsafe_interface_names(self):
        with self.assertRaises(ValueError):
            evil_twin_nat_setup_commands(ap_iface="wlan0; iptables -F", wan_iface="eth0")
        with self.assertRaises(ValueError):
            evil_twin_nat_setup_commands(ap_iface="wlan0", wan_iface="eth0 && reboot")

    def test_teardown_never_flushes_builtin_tables(self):
        commands = evil_twin_nat_teardown_commands()
        self.assertFalse(any(_is_global_table_flush(cmd) for cmd in commands))
        self.assertTrue(any(cmd == ["iptables", "-F", FILTER_CHAIN] for cmd in commands))
        self.assertTrue(any(cmd == ["iptables", "-X", FILTER_CHAIN] for cmd in commands))
        self.assertTrue(any(cmd == ["iptables", "-t", "nat", "-F", NAT_CHAIN] for cmd in commands))
        self.assertTrue(any(cmd == ["iptables", "-t", "nat", "-X", NAT_CHAIN] for cmd in commands))
        self.assertTrue(any(cmd == ["iptables", "-F", INPUT_CHAIN] for cmd in commands))
        self.assertTrue(any(cmd == ["iptables", "-t", "nat", "-F", PRE_CHAIN] for cmd in commands))
        self.assertFalse(any("iptables-restore" in cmd for cmd in commands))

    def test_portal_without_wan_uses_prerouting_dnat(self):
        commands = evil_twin_nat_setup_commands(ap_iface="wlan0", wan_iface=None, portal=True)
        joined = [" ".join(cmd) for cmd in commands]
        self.assertFalse(any(_is_global_table_flush(cmd) for cmd in commands))
        self.assertFalse(any(cmd[-1] == "MASQUERADE" for cmd in commands))
        self.assertIn(f"iptables -t nat -N {PRE_CHAIN}", joined)
        self.assertTrue(any("PREROUTING" in cmd and PRE_CHAIN in cmd for cmd in commands))
        self.assertTrue(any("DNAT" in cmd and "192.168.1.1:80" in cmd for cmd in commands))
        self.assertTrue(any(INPUT_CHAIN in cmd and "--dport" in cmd and "80" in cmd for cmd in commands))

    def test_isolate_without_wan_drops_ap_to_ap(self):
        commands = evil_twin_nat_setup_commands(
            ap_iface="wlan0", wan_iface=None, isolate_clients=True
        )
        self.assertFalse(any(_is_global_table_flush(cmd) for cmd in commands))
        self.assertTrue(
            any(cmd == ["iptables", "-A", FILTER_CHAIN, "-i", "wlan0", "-o", "wlan0", "-j", "DROP"] for cmd in commands)
        )
        self.assertFalse(any(cmd[-1] == "MASQUERADE" for cmd in commands))

    def test_portal_rejects_unsafe_portal_ip(self):
        with self.assertRaises(ValueError):
            evil_twin_nat_setup_commands(
                ap_iface="wlan0", wan_iface=None, portal=True, portal_ip="1.2.3.4; iptables -F"
            )

    def test_apply_with_wan_tears_down_then_installs(self):
        recorded: list[list[str]] = []

        def runner(command):
            recorded.append(list(command))
            return 0

        apply_evil_twin_nat(ap_iface="wlan0", wan_iface="eth0", run=runner)
        self.assertTrue(recorded)
        self.assertEqual(recorded[0][:3], ["iptables", "-D", "FORWARD"])
        self.assertTrue(any("-N" in cmd and FILTER_CHAIN in cmd for cmd in recorded))
        self.assertTrue(any(cmd[-1] == "MASQUERADE" for cmd in recorded))
        self.assertFalse(any(_is_global_table_flush(cmd) for cmd in recorded))

    def test_apply_without_wan_only_tears_down(self):
        recorded: list[list[str]] = []

        def runner(command):
            recorded.append(list(command))
            return 0

        apply_evil_twin_nat(ap_iface="wlan0", wan_iface=None, run=runner)
        self.assertTrue(any("-X" in cmd and FILTER_CHAIN in cmd for cmd in recorded))
        self.assertFalse(any("-N" in cmd for cmd in recorded))
        self.assertFalse(any(cmd[-1] == "MASQUERADE" for cmd in recorded))

    def test_remove_ignores_runner_errors(self):
        def runner(_command):
            return 1

        remove_evil_twin_nat(run=runner)

    def test_setup_raises_when_insert_fails(self):
        def runner(command):
            if "-I" in command:
                return 4
            return 0

        with self.assertRaises(RuntimeError):
            apply_evil_twin_nat(ap_iface="wlan0", wan_iface="eth0", run=runner)


if __name__ == "__main__":
    unittest.main()
