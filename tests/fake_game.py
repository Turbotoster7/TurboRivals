"""A stand-in for NFS14.exe's Blaze client, for driving the real server in tests.

Makes the handshake the game makes - TLS 1.0 ClientHello, RSA key exchange, RC4-128-SHA, the
record layer in tls_terminator.Wire - and sends Fire2 requests over it. Enough to take the server
through Util.preAuth and Authentication.originLogin without the game or a Windows machine.

The test owns the server's private key, and the public half of it (n, e=65537) is all the client
needs: make_stub_cert.py generates every key with that exponent.
"""
from __future__ import annotations

import os
import socket
import struct
from pathlib import Path

import blaze
import tls_terminator as tls

PUBLIC_EXPONENT = 65537


def _rsa_encrypt(message: bytes, n: int, k: int) -> bytes:
    """PKCS#1 v1.5 type 2 padding, then raw RSA - what tls_terminator.rsa_decrypt_pkcs1 undoes."""
    padding = bytes(b or 1 for b in os.urandom(k - 3 - len(message)))
    block = b"\x00\x02" + padding + b"\x00" + message
    return pow(int.from_bytes(block, "big"), PUBLIC_EXPONENT, n).to_bytes(k, "big")


class FakeGame:
    def __init__(self, host: str, port: int, key_path: Path, source_ip: str | None = None):
        n, _d, k = tls.load_rsa_priv(Path(key_path))
        self.sock = socket.create_connection(
            (host, port), timeout=5, source_address=(source_ip, 0) if source_ip else None)
        self.wire = tls.Wire(self.sock)
        self.seq = 0
        self.buf = b""
        self._handshake(n, k)

    def _handshake(self, n: int, k: int) -> None:
        w = self.wire
        client_random = os.urandom(32)
        hello = (struct.pack(">H", 0x0301) + client_random + b"\x00"
                 + struct.pack(">HH", 2, tls.CIPHER_RC4_SHA) + b"\x01\x00")
        client_hello = tls.hs_msg(tls.HS_CLIENT_HELLO, hello)
        w.record_version = 0x0300                 # the game sends its ClientHello as SSL 3.0
        w.send_record(tls.RT_HANDSHAKE, client_hello)
        transcript = client_hello

        replies = []
        while len(replies) < 3:                   # ServerHello, Certificate, ServerHelloDone
            rtype, _ver, body = w.recv_record()
            if rtype != tls.RT_HANDSHAKE:
                raise ConnectionError(f"expected a handshake record, got type {rtype}")
            replies.append(body)
        server_random = replies[0][6:38]
        transcript += b"".join(replies)

        pre_master = struct.pack(">H", 0x0301) + os.urandom(46)
        encrypted = _rsa_encrypt(pre_master, n, k)
        key_exchange = tls.hs_msg(tls.HS_CLIENT_KEY_EXCHANGE,
                                  struct.pack(">H", len(encrypted)) + encrypted)
        w.record_version = tls.VER_TLS11
        w.send_record(tls.RT_HANDSHAKE, key_exchange)
        transcript += key_exchange

        master, cmac, smac, ckey, skey = tls.derive_keys(pre_master, client_random, server_random)
        w.send_record(tls.RT_CCS, b"\x01")
        w.activate_write(tls.RC4(ckey), cmac)
        finished = tls.hs_msg(tls.HS_FINISHED,
                              tls.finished_verify(master, b"client finished", transcript))
        w.send_record(tls.RT_HANDSHAKE, finished)
        transcript += finished

        rtype, _ver, _ = w.recv_record()
        if rtype != tls.RT_CCS:
            raise ConnectionError(f"expected ChangeCipherSpec, got type {rtype}")
        w.activate_read(tls.RC4(skey), smac)
        rtype, _ver, server_finished = w.recv_record()
        if server_finished[4:16] != tls.finished_verify(master, b"server finished", transcript):
            raise ConnectionError("the server's Finished does not verify")

    def rpc(self, component: int, command: int, payload: bytes = b"") -> blaze.Fire2:
        """Sends one request and returns the server's reply to it (notifications are skipped)."""
        seq = self.seq
        self.seq += 1
        frame = blaze.Fire2(component=component, command=command, payload=payload, seq=seq)
        self.wire.send_record(tls.RT_APPDATA, frame.encode())
        while True:
            reply = self._next_frame()
            if (reply.component, reply.command, reply.seq) == (component, command, seq):
                return reply

    def _next_frame(self) -> blaze.Fire2:
        while True:
            if len(self.buf) >= blaze.FIRE2_HDR:
                size = struct.unpack_from(">H", self.buf, 0)[0]
                total = blaze.FIRE2_HDR + size
                if len(self.buf) >= total:
                    frame, self.buf = self.buf[:total], self.buf[total:]
                    return blaze.Fire2.decode(frame)
            rtype, _ver, body = self.wire.recv_record()
            if rtype == tls.RT_APPDATA:
                self.buf += body

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
