"""TLS records the server writes: at most 2^14 B of plaintext each. Up to 1.0.9 Wire.send_record
put any payload into ONE record, and a profile picture over 16 KB (ByteVault) dropped the game
a few seconds into a session. Offline, on a socket pair."""
import os
import socket
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "proto-lab"))

import tls_terminator as tls  # noqa: E402

KEY, MAC = b"k" * 16, b"m" * 20


class RecordSplitTests(unittest.TestCase):
    def pair(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        b.settimeout(5)
        sender, receiver = tls.Wire(a), tls.Wire(b)
        sender.activate_write(tls.RC4(KEY), MAC)
        receiver.activate_read(tls.RC4(KEY), MAC)
        return sender, receiver

    def received(self, receiver, total: int) -> list[bytes]:
        parts, got = [], 0
        while got < total:
            kind, _ver, body = receiver.recv_record()     # MAC checked on every record
            self.assertEqual(kind, tls.RT_APPDATA)
            parts.append(body)
            got += len(body)
        return parts

    def test_a_40_kb_picture_goes_in_records_of_at_most_16_kb(self):
        sender, receiver = self.pair()
        picture = b"\xff\xd8\xff" + os.urandom(40 * 1024)
        sender.send_record(tls.RT_APPDATA, picture)
        parts = self.received(receiver, len(picture))
        self.assertEqual([len(p) for p in parts], [16384, 16384, len(picture) - 32768])
        self.assertEqual(b"".join(parts), picture)

    def test_small_and_empty_records_stay_single(self):
        sender, receiver = self.pair()
        sender.send_record(tls.RT_APPDATA, b"ping")
        sender.send_record(tls.RT_APPDATA, b"")
        sender.send_record(tls.RT_APPDATA, b"x" * 16384)          # exactly the limit: one record
        self.assertEqual(receiver.recv_record()[2], b"ping")
        self.assertEqual(receiver.recv_record()[2], b"")
        self.assertEqual(len(receiver.recv_record()[2]), 16384)


if __name__ == "__main__":
    unittest.main()
