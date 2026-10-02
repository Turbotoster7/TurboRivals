import support  # noqa: F401  (sets up the throw-away hosts file first)

import os
import unittest

import hosts_switch as hs

EOL = os.linesep.encode()           # write_hosts writes the platform's line end, CRLF on Windows


class StripRedirects(unittest.TestCase):
    def test_block_and_foreign_lines_go_other_names_stay(self):
        lines = [
            "127.0.0.1 gosredirector.ea.com",                 # stale, by hand, above the block
            "10.0.0.5 nas.local",
            "127.0.0.1 gosredirector.ea.com other.example",   # shares a line with another name
            hs.BEGIN, "26.48.21.54\tgosredirector.ea.com", hs.END,
        ]
        cleaned, removed = hs.strip_redirects(lines)
        self.assertEqual(cleaned, ["10.0.0.5 nas.local", "127.0.0.1\tother.example"])
        self.assertEqual(removed, ["127.0.0.1 gosredirector.ea.com",
                                   "127.0.0.1 gosredirector.ea.com other.example"])

    def test_effective_address_is_the_first_mapping(self):
        lines = ["# 1.2.3.4 gosredirector.ea.com", "127.0.0.1 GOSREDIRECTOR.EA.COM",
                 hs.BEGIN, "26.48.21.54 gosredirector.ea.com", hs.END]
        self.assertEqual(hs.effective_address(lines, "gosredirector.ea.com"), "127.0.0.1")
        self.assertIsNone(hs.effective_address(["10.0.0.5 nas.local"], "gosredirector.ea.com"))


class FileHandling(unittest.TestCase):
    def test_utf8_bom_is_dropped(self):
        support.write_hosts("\ufeff10.0.0.5 nas.local\n")
        text, encoding = hs.read_hosts_text()
        self.assertEqual((text, encoding), ("10.0.0.5 nas.local\n", "utf-8"))
        hs.write_hosts(text.splitlines(), encoding)
        self.assertEqual(support.HOSTS.read_bytes(), b"10.0.0.5 nas.local" + EOL)

    def test_legacy_codepage_survives_a_rewrite_byte_for_byte(self):
        # "# serwer Łukasza" saved in cp1250 - not valid UTF-8. Decoding it as UTF-8 with
        # replacement (the old read_hosts) turned the comment into U+FFFD on the next write.
        original = f"# serwer Łukasza{os.linesep}10.0.0.5 nas.local{os.linesep}".encode("cp1250")
        support.HOSTS.write_bytes(original)
        text, encoding = hs.read_hosts_text()
        self.assertEqual(encoding, "latin-1")
        hs.write_hosts(text.splitlines(), encoding)
        self.assertEqual(support.HOSTS.read_bytes(), original)

    def test_backups_are_capped(self):
        support.write_hosts()
        for old in support.HOSTS.parent.glob(hs.BACKUP_GLOB):
            old.unlink()
        for i in range(hs.BACKUPS_KEPT + 3):
            (support.HOSTS.parent / f"hosts.turborivals-20260101-0000{i:02d}.bak").write_text("x")
        made = hs.backup()
        left = sorted(support.HOSTS.parent.glob(hs.BACKUP_GLOB))
        self.assertEqual(len(left), hs.BACKUPS_KEPT)
        self.assertIn(made, left)

    def test_restore_puts_the_copy_back(self):
        support.write_hosts()
        copy = hs.backup()
        support.HOSTS.write_text("garbage\n")
        self.assertTrue(hs.restore(copy))
        self.assertEqual(support.HOSTS.read_text(), support.SAMPLE_HOSTS)


class Addresses(unittest.TestCase):
    def test_valid_and_invalid(self):
        for ip in ("127.0.0.1", "26.48.21.54", " 192.168.1.10 "):
            self.assertTrue(hs.valid_address(ip), ip)
        for ip in ("", "localhost", "192.168.1", "192.168.1.300", "192.168.001.5", "::1",
                   "0.0.0.0", "255.255.255.255", "224.0.0.1", "26.48.21.54:42127", "1.2.3.4 x"):
            self.assertFalse(hs.valid_address(ip), ip)


if __name__ == "__main__":
    unittest.main()
