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


def netsh_show(name, proto, ports, local="Any"):
    """`netsh advfirewall firewall show rule` for one rule (the labels are translated on other
    Windows languages; the values never are)."""
    return (f"\nRule Name:                            {name}\n"
            f"----------------------------------------------------------------------\n"
            f"Enabled:                              Yes\nDirection:                            In\n"
            f"LocalIP:                              {local}\nRemoteIP:                             Any\n"
            f"Protocol:                             {proto}\nLocalPort:                            {ports}\n"
            f"Action:                               Allow\nOk.\n")


@unittest.skipUnless(commands.IS_WINDOWS, "the status reads netsh")
class FirewallStatusTests(unittest.TestCase):
    def status_with(self, rules, mode, local_ip=""):
        """rules: name -> the LocalIP netsh prints for it ("Any", "26.1.2.3/255.255.255.255")."""
        spec = {name: (proto, ports) for rs in commands.FIREWALL_RULES.values()
                for name, proto, ports in rs}
        show = lambda name: (netsh_show(name, *spec[name], rules[name]) if name in rules  # noqa: E731
                             else "No rules match the specified criteria.")
        with mock.patch.object(commands, "_show_rule", side_effect=show), \
                mock.patch.object(commands, "local_addresses", lambda: [{"ip": ip} for ip in OWN]):
            return commands.firewall_status(mode, local_ip)

    def test_client_rule_alone_does_not_count_as_host(self):
        # The P2P rule is shared, so a guest's rules must not light up the host's row.
        self.assertFalse(self.status_with({"NFS Rivals P2P": "Any"}, "host")["ok"])
        self.assertTrue(self.status_with({"NFS Rivals P2P": "Any"}, "client")["ok"])

    def test_all_host_rules(self):
        names = {name: "Any" for name, _proto, _ports in commands.FIREWALL_RULES["host"]}
        self.assertTrue(self.status_with(names, "host")["ok"])

    def test_none(self):
        status = self.status_with({}, "host")
        self.assertFalse(status["ok"])
        self.assertEqual({r["state"] for r in status["rules"]}, {"missing"})

    def test_a_rule_for_another_address_is_outdated(self):
        # 1.0.7 scopes a host's rules to its address: moving to another VPN must update them,
        # and rules open to every address are not what a host with an address asked for
        scoped = {name: "26.1.2.3/255.255.255.255" for name, _p, _q in commands.FIREWALL_RULES["host"]}
        self.assertTrue(self.status_with(scoped, "host", "26.1.2.3")["ok"])
        self.assertFalse(self.status_with(scoped, "host", "192.168.1.20")["ok"])
        self.assertFalse(self.status_with(scoped, "host")["ok"])
        anywhere = {name: "Any" for name in scoped}
        self.assertFalse(self.status_with(anywhere, "host", "26.1.2.3")["ok"])

    def test_off_with_no_rules_needs_no_admin(self):
        with mock.patch.object(commands, "_show_rule", lambda name: "No rules match."), \
                mock.patch.object(commands, "is_admin", lambda: False):
            self.assertEqual(commands.firewall_off(), {"ok": True, "removed": []})


if __name__ == "__main__":
    unittest.main()
