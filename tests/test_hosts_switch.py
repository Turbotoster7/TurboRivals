"""The hosts file: turning the redirect on and off must give back every byte we did not write.

Runs on a temporary copy, never on the real hosts file.
"""
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "launcher"))

import hosts_switch  # noqa: E402
import commands  # noqa: E402

# A cp1250 comment (0xE9, and 0x85 - the ellipsis, which str.splitlines() would treat as a line
# break), CRLF endings, and an unrelated mapping.
ORIGINAL = (b"# Copyright (c) Microsoft Corp.\r\n"
            b"# caf\xe9 \x85 edited by hand\r\n"
            b"127.0.0.1\tlocalhost\r\n"
            b"10.0.0.5 nas.local\r\n")


class HostsFileTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="turborivals-hosts-")
        self.addCleanup(tmp.cleanup)
        self.hosts = Path(tmp.name) / "hosts"
        self.hosts.write_bytes(ORIGINAL)
        # The launcher's own code path, pointed at the copy: hosts_switch reads and writes
        # through its module-level HOSTS, commands backs up through its own.
        for target in (mock.patch.object(hosts_switch, "HOSTS", self.hosts),
                       mock.patch.object(commands, "HOSTS", self.hosts),
                       mock.patch.object(commands, "is_admin", lambda: True),
                       mock.patch.object(commands, "flush_dns", lambda: True)):
            target.start()
            self.addCleanup(target.stop)

    def test_on_then_off_restores_every_byte(self):
        self.assertTrue(commands.hosts_on("26.1.2.3")["ok"])
        text = self.hosts.read_bytes()
        self.assertIn(b"26.1.2.3\tgosredirector.ea.com\r\n", text)
        self.assertTrue(text.startswith(ORIGINAL))
        self.assertEqual(commands.hosts_status()["effective_ip"], "26.1.2.3")
        self.assertTrue(commands.hosts_off()["ok"])
        self.assertEqual(self.hosts.read_bytes(), ORIGINAL)

    def test_switching_address_keeps_one_block(self):
        commands.hosts_on("26.1.2.3")
        commands.hosts_on("100.64.0.9")
        status = commands.hosts_status()
        self.assertEqual(status["entries"], ["100.64.0.9\tgosredirector.ea.com"])
        self.assertEqual(self.hosts.read_bytes().count(hosts_switch.BEGIN.encode()), 1)

    def test_lf_file_stays_lf(self):
        lf = ORIGINAL.replace(b"\r\n", b"\n")
        self.hosts.write_bytes(lf)
        commands.hosts_on("127.0.0.1")
        self.assertNotIn(b"\r\n", self.hosts.read_bytes())
        commands.hosts_off()
        self.assertEqual(self.hosts.read_bytes(), lf)

    def test_stale_line_outside_the_block_goes_other_names_stay(self):
        self.hosts.write_bytes(ORIGINAL + b"127.0.0.1 gosredirector.ea.com other.local\r\n")
        result = commands.hosts_on("26.1.2.3")
        self.assertEqual(result["removed"], ["127.0.0.1 gosredirector.ea.com other.local"])
        self.assertEqual(commands.hosts_status()["foreign"], [])
        self.assertEqual(commands.hosts_status()["effective_ip"], "26.1.2.3")
        self.assertIn(b"127.0.0.1\tother.local\r\n", self.hosts.read_bytes())

    def test_a_missing_hosts_file_is_created(self):
        # A player had no hosts file at all, only hosts.ics (01.10): TURN ON failed.
        self.hosts.unlink()
        self.assertEqual(hosts_switch.read_hosts(), [])
        self.assertTrue(commands.hosts_off()["ok"])                  # nothing to remove
        result = commands.hosts_on("10.147.17.5")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertIsNone(result["backup"])
        self.assertEqual(self.hosts.read_bytes(),
                         f"{hosts_switch.BEGIN}\r\n10.147.17.5\tgosredirector.ea.com\r\n"
                         f"{hosts_switch.END}\r\n".encode())
        self.assertEqual(commands.hosts_status()["effective_ip"], "10.147.17.5")

    def test_a_read_only_hosts_file_is_made_writable(self):
        os.chmod(self.hosts, stat.S_IREAD)
        self.addCleanup(lambda: os.chmod(self.hosts, stat.S_IREAD | stat.S_IWRITE))
        result = commands.hosts_on("10.147.17.5")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertIn(b"10.147.17.5\tgosredirector.ea.com", self.hosts.read_bytes())
        self.assertTrue(commands.hosts_off()["ok"])
        self.assertEqual(self.hosts.read_bytes(), ORIGINAL)

    def test_a_guarded_hosts_file_names_the_line_to_add_by_hand(self):
        with mock.patch.object(hosts_switch, "write_hosts", side_effect=PermissionError(13, "denied")):
            result = commands.hosts_on("10.147.17.5")
        self.assertFalse(result["ok"])
        self.assertIn("10.147.17.5  gosredirector.ea.com", result["error"])

    def test_off_with_nothing_to_remove_needs_no_admin(self):
        with mock.patch.object(commands, "is_admin", lambda: False):
            self.assertTrue(commands.hosts_off()["ok"])
            self.hosts.write_bytes(ORIGINAL + b"1.2.3.4 gosredirector.ea.com\r\n")
            self.assertFalse(commands.hosts_off()["ok"])
        self.assertTrue(self.hosts.read_bytes().endswith(b"1.2.3.4 gosredirector.ea.com\r\n"))


if __name__ == "__main__":
    unittest.main()
