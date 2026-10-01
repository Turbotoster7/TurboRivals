"""Firewall rules the launcher adds - built only, never applied (netsh is not run)."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "launcher"))

import commands  # noqa: E402

OWN = ["26.1.2.3", "192.168.1.20"]


class FirewallRuleTests(unittest.TestCase):
    def test_host_rules_cover_only_the_chosen_address(self):
        rules = commands.firewall_commands("host", "26.1.2.3", own=OWN)
        self.assertEqual([name for name, _label, _cmd in rules],
                         [name for name, _proto, _ports in commands.FIREWALL_RULES["host"]])
        for _name, label, command in rules:
            self.assertIn("localip=26.1.2.3", command)
            self.assertTrue(label.endswith("on 26.1.2.3"))

    def test_host_without_an_address_keeps_the_open_rules(self):
        for _name, _label, command in commands.firewall_commands("host", "", own=OWN):
            self.assertFalse(any(arg.startswith("localip=") for arg in command))

    def test_address_this_pc_does_not_have_is_ignored(self):
        # A rule for someone else's address would block the players instead of letting them in.
        for _name, _label, command in commands.firewall_commands("host", "10.9.9.9", own=OWN):
            self.assertFalse(any(arg.startswith("localip=") for arg in command))

    def test_client_opens_only_player_traffic_unscoped(self):
        rules = commands.firewall_commands("client", "26.1.2.3", own=OWN)
        self.assertEqual(len(rules), 1)
        _name, _label, command = rules[0]
        self.assertIn("localport=3659", command)
        self.assertFalse(any(arg.startswith("localip=") for arg in command))


class FirewallStatusTests(unittest.TestCase):
    def status_with(self, present):
        with mock.patch.object(commands, "_rule_exists", side_effect=lambda name: name in present):
            return commands.firewall_status()

    def test_client_rule_alone_does_not_count_as_host(self):
        # The P2P rule is shared, so a guest's rules must not light up the host's row.
        self.assertEqual(self.status_with({"NFS Rivals P2P"}),
                         {"host": False, "client": True, "any": True})

    def test_all_host_rules(self):
        names = {name for name, _proto, _ports in commands.FIREWALL_RULES["host"]}
        self.assertEqual(self.status_with(names), {"host": True, "client": True, "any": True})

    def test_none(self):
        self.assertEqual(self.status_with(set()), {"host": False, "client": False, "any": False})


if __name__ == "__main__":
    unittest.main()
