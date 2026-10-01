"""The real server on loopback, driven by a synthetic client: TLS handshake, a Blaze RPC,
ByteVault HTTP and QoS. No game, no EA account, no hosts or firewall changes.

Adapted from RivalsNET's transport tests (tests/turborivals/test_backend.py in 49Ssr/RivalsNET).
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

sys.dont_write_bytecode = True
PROTO_LAB = Path(__file__).resolve().parents[1] / "proto-lab"
sys.path.insert(0, str(PROTO_LAB))

import blaze  # noqa: E402
import make_stub_cert  # noqa: E402
import tls_terminator as tls  # noqa: E402

HANDSHAKE_TIMEOUT = 2


def free_ports(count: int) -> list[int]:
    """Ports nobody uses right now. The QoS UDP responder also takes the port after its own."""
    while True:
        socks = []
        try:
            for _ in range(count):
                s = socket.socket()
                s.bind(("127.0.0.1", 0))
                socks.append(s)
            ports = [s.getsockname()[1] for s in socks]
        finally:
            for s in socks:
                s.close()
        qos = ports[-1]
        if qos + 1 not in ports and qos < 65535:
            return ports


class LoopbackServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # ignore_cleanup_errors: right after the server exits, Windows (a virus scanner) may still
        # hold server.log for a moment, and the cleanup then failed a run whose tests all passed.
        cls.tmp = tempfile.TemporaryDirectory(prefix="turborivals-test-",
                                              ignore_cleanup_errors=True)
        cls.root = Path(cls.tmp.name)
        make_stub_cert.generate(cls.root / "pki")
        cls.port, cls.blaze_port, cls.qos = free_ports(3)
        cls.log_path = cls.root / "server.log"
        cls.log = cls.log_path.open("w", encoding="utf-8")
        cls.process = subprocess.Popen(
            [sys.executable, "-u", str(PROTO_LAB / "tls_terminator.py"),
             "--bind-ip", "127.0.0.1", "--public-ip", "127.0.0.1",
             "--port", str(cls.port), "--blaze-port", str(cls.blaze_port),
             "--qos-port", str(cls.qos), "--handshake-timeout", str(HANDSHAKE_TIMEOUT),
             "--cert", str(cls.root / "pki" / "server.der"),
             "--key", str(cls.root / "pki" / "server.key"),
             "--data-dir", str(cls.root / "players"), "--local-id", "10001",
             "--out", str(cls.root / "capture"), "--no-capture"],
            stdout=cls.log, stderr=subprocess.STDOUT,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                text = cls.log_path.read_text(encoding="utf-8", errors="replace")
                # redirector, Blaze, two QoS UDP ports and QoS HTTP
                if text.count("listening on ") == 5 and "handing the game" in text:
                    return
                if cls.process.poll() is not None:
                    raise RuntimeError(f"the server exited:\n{text}")
                time.sleep(0.05)
            raise RuntimeError(f"not every listener came up:\n{text}")
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.log.close()
        cls.tmp.cleanup()

    def server_log(self) -> str:
        return self.log_path.read_text(encoding="utf-8", errors="replace")

    def connect(self, port: int | None = None, bad_finished: bool = False):
        """A full handshake as the game does it: RC4_SHA, RSA key exchange. Returns the Wire
        with both directions encrypted, or None after a rejected Finished."""
        sock = socket.create_connection(("127.0.0.1", port or self.port), timeout=5)
        self.addCleanup(sock.close)
        wire = tls.Wire(sock)
        client_random = os.urandom(32)
        hello = tls.hs_msg(tls.HS_CLIENT_HELLO, struct.pack(">H", tls.VER_TLS11) + client_random
                           + b"\0" + struct.pack(">H", 2) + struct.pack(">H", tls.CIPHER_RC4_SHA)
                           + b"\1\0")
        wire.send_record(tls.RT_HANDSHAKE, hello)
        messages = [wire.recv_record()[2] for _ in range(3)]      # ServerHello, Certificate, Done
        transcript = hello + b"".join(messages)
        server_random = messages[0][6:38]
        cert = x509.load_der_x509_certificate(messages[1][10:])
        pre_master = struct.pack(">H", tls.VER_TLS11) + os.urandom(46)
        encrypted = cert.public_key().encrypt(pre_master, padding.PKCS1v15())
        cke = tls.hs_msg(tls.HS_CLIENT_KEY_EXCHANGE, struct.pack(">H", len(encrypted)) + encrypted)
        wire.send_record(tls.RT_HANDSHAKE, cke)
        transcript += cke
        master, cmac, smac, ckey, skey = tls.derive_keys(pre_master, client_random, server_random)
        wire.send_record(tls.RT_CCS, b"\1")
        wire.activate_write(tls.RC4(ckey), cmac)
        verify = tls.finished_verify(master, b"client finished", transcript)
        if bad_finished:
            verify = bytes([verify[0] ^ 1]) + verify[1:]
        fin = tls.hs_msg(tls.HS_FINISHED, verify)
        wire.send_record(tls.RT_HANDSHAKE, fin)
        if bad_finished:
            with self.assertRaises(OSError):              # ConnectionError or a reset
                wire.recv_record()
            return None
        self.assertEqual(wire.recv_record()[0], tls.RT_CCS)
        wire.activate_read(tls.RC4(skey), smac)
        server_fin = wire.recv_record()[2]
        self.assertEqual(server_fin[4:],
                         tls.finished_verify(master, b"server finished", transcript + fin))
        return wire

    def test_handshake_and_redirector_rpc(self):
        wire = self.connect()
        wire.send_record(tls.RT_APPDATA, blaze.Fire2(5, 1, b"", seq=17).encode())
        kind, _ver, body = wire.recv_record()
        reply = blaze.Fire2.decode(body)
        self.assertEqual(kind, tls.RT_APPDATA)
        self.assertEqual((reply.component, reply.command, reply.seq, reply.error), (5, 1, 17, 0))
        self.assertIn(b"gosredirector.ea.com", reply.payload)

    def test_no_capture_writes_no_frames(self):
        wire = self.connect()
        wire.send_record(tls.RT_APPDATA, blaze.Fire2(5, 1, b"", seq=3).encode())
        wire.recv_record()
        self.assertFalse(list((self.root / "capture").glob("*.bin")))

    def test_bad_finished_is_rejected(self):
        self.connect(bad_finished=True)

    def test_bad_record_mac_is_rejected(self):
        wire = self.connect()
        body = blaze.Fire2(5, 1, b"", seq=18).encode()
        sealed = wire.tx.crypt(body + b"\0" * 20)                 # a zero MAC
        wire.sock.sendall(struct.pack(">BHH", tls.RT_APPDATA, tls.VER_TLS11, len(sealed)) + sealed)
        with self.assertRaises(OSError):
            wire.recv_record()

    def test_silent_connection_is_closed(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=HANDSHAKE_TIMEOUT + 5) as s:
            started = time.monotonic()
            try:
                data = s.recv(1)
            except ConnectionResetError:
                data = b""
            self.assertEqual(data, b"")
            self.assertLess(time.monotonic() - started, HANDSHAKE_TIMEOUT + 4)

    def test_bytevault_http_on_the_blaze_port(self):
        wire = self.connect(self.blaze_port)
        wire.send_record(tls.RT_APPDATA,
                         b"GET /1.0/contexts/nfs-rivals-pc/categories/Unlocks/recordinfo"
                         b"?recordName=&ownerId=10001&ownerType=NUCLEUS%5FPERSONA&offset=0"
                         b"&maxresultcount=100 HTTP/1.1\r\nHost: gosredirector.ea.com\r\n"
                         b"Connection: Close\r\n\r\n")
        self.assertTrue(wire.recv_record()[2].startswith(b"HTTP/1.1 200"))

    def test_the_ea_token_in_bytevault_headers_stays_out_of_the_log(self):
        # 01.10: a guest's ByteVault Authorization was the player's real EA access token.
        # (The same check RivalsNET's transport tests make.)
        wire = self.connect(self.blaze_port)
        wire.send_record(tls.RT_APPDATA,
                         b"GET /1.0/contexts/nfs-rivals-pc/categories/Unlocks/recordinfo?ownerId=1 HTTP/1.1\r\n"
                         b"Host: gosredirector.ea.com\r\nX-TOKEN-TYPE: NUCLEUS_AUTH_TOKEN\r\n"
                         b"Authorization: QVQwfixture-ea-token-secret\r\nCookie: sid=fixture-cookie-secret\r\n"
                         b"Connection: Close\r\n\r\n")
        self.assertTrue(wire.recv_record()[2].startswith(b"HTTP/1.1 200"))
        redacted = f"Authorization: QVQwfi... (redacted, {len('QVQwfixture-ea-token-secret')} chars)"
        deadline = time.monotonic() + 5
        while redacted not in self.server_log() and "fixture-ea-token" not in self.server_log():
            self.assertLess(time.monotonic(), deadline, "the request never reached the log")
            time.sleep(0.05)
        log = self.server_log()
        self.assertNotIn("fixture-ea-token-secret", log)
        self.assertNotIn("fixture-cookie-secret", log)
        self.assertIn(redacted, log)
        self.assertIn("X-TOKEN-TYPE: NUCLEUS_AUTH_TOKEN", log)        # the type is no secret

    def test_a_big_profile_picture_reaches_the_game_whole(self):
        # 40 KB, as an older launcher could send: more than one TLS record may carry.
        picture = b"\xff\xd8\xff" + os.urandom(40 * 1024)
        avatars = self.root / "players" / "avatars"
        avatars.mkdir(parents=True, exist_ok=True)
        (avatars / "4242.jpg").write_bytes(picture)
        wire = self.connect(self.blaze_port)
        wire.send_record(tls.RT_APPDATA,
                         b"GET /1.0/contexts/nfs-rivals-common/categories/Pictures/records/4242"
                         b"?ownerId=4242&ownerType=NUCLEUS%5FUSER&subrecord= HTTP/1.1\r\n"
                         b"Host: gosredirector.ea.com\r\nConnection: Close\r\n\r\n")
        data, sizes = b"", []
        while b"\r\n\r\n" not in data or len(data.partition(b"\r\n\r\n")[2]) < len(picture):
            body = wire.recv_record()[2]
            sizes.append(len(body))
            data += body
        head, _, payload = data.partition(b"\r\n\r\n")
        self.assertIn(b"Content-Type: image/jpeg", head)
        self.assertIn(f"Content-Length: {len(picture)}".encode(), head)
        self.assertEqual(payload, picture)
        self.assertLessEqual(max(sizes), tls.MAX_FRAGMENT)
        self.assertGreater(len(sizes), 1)

    def test_resume_session_after_a_server_restart(self):
        # The local player (--local-id 10001) comes back with the key of a login the server
        # never saw - as after a restart - and gets the session plus the login notifications.
        wire = self.connect(self.blaze_port)
        request = blaze.encode_tdf([blaze.f_str("SKEY", "1_10001_sess")])
        wire.send_record(tls.RT_APPDATA, blaze.Fire2(0x7802, 0x23, request, seq=5).encode())
        frames, buf = [], b""
        while len(frames) < 4:
            buf += wire.recv_record()[2]
            while len(buf) >= blaze.FIRE2_HDR and len(buf) >= blaze.FIRE2_HDR + int.from_bytes(buf[:2], "big"):
                size = blaze.FIRE2_HDR + int.from_bytes(buf[:2], "big")
                frames.append(blaze.Fire2.decode(buf[:size]))
                buf = buf[size:]
        reply = frames[0]
        self.assertEqual((reply.component, reply.command, reply.seq, reply.error), (0x7802, 0x23, 5, 0))
        self.assertEqual([f.command for f in frames[1:4]], [2, 1, 8])   # UserAdded, data, authenticated

    def test_an_unknown_session_key_is_refused(self):
        wire = self.connect(self.blaze_port)
        request = blaze.encode_tdf([blaze.f_str("SKEY", "1_4242_sess")])
        wire.send_record(tls.RT_APPDATA, blaze.Fire2(0x7802, 0x23, request, seq=6).encode())
        reply = blaze.Fire2.decode(wire.recv_record()[2])
        self.assertEqual((reply.command, reply.error), (0x23, tls.RESUME_REFUSED))

    def launcher(self, method: str, body: bytes = b"") -> bytes:
        """A launcher request on the QoS HTTP port, from 127.0.0.1 - the host (--local-id)."""
        with socket.create_connection(("127.0.0.1", self.qos), timeout=5) as s:
            s.sendall(f"{method} /turborivals/avatar HTTP/1.1\r\nHost: localhost\r\n"
                      f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
            reply = b""
            while chunk := s.recv(4096):
                reply += chunk
        return reply

    def test_picture_upload_removal_and_refusal(self):
        avatar = self.root / "players" / "avatars" / "10001.png"
        self.assertIn(b"200 OK", self.launcher("POST", b"\x89PNG\r\n\x1a\n" + b"\0" * 64))
        self.assertTrue(avatar.exists())
        self.assertIn(b"200 OK", self.launcher("DELETE"))
        self.assertFalse(avatar.exists())
        self.assertIn(b"400 Bad Request", self.launcher("POST", b"not a picture"))
        deadline = time.monotonic() + 5
        while "[avatar] 127.0.0.1: refused" not in self.server_log():
            self.assertLess(time.monotonic(), deadline, "the refusal never reached the log")
            time.sleep(0.05)
        self.assertIn("picture of uid 10001 removed (png)", self.server_log())

    def test_qos_http_and_both_udp_ports(self):
        with socket.create_connection(("127.0.0.1", self.qos), timeout=5) as s:
            s.sendall(b"GET /qos/firetype HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertIn(b"200 OK", s.recv(4096))
        for port in (self.qos, self.qos + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5)
                s.sendto(struct.pack(">5I", 1, 1234, 0, 0, 10), ("127.0.0.1", port))
                self.assertGreaterEqual(len(s.recv(4096)), 30)    # latency probe reply


if __name__ == "__main__":
    unittest.main()
