#!/usr/bin/env python3
"""TurboRivals replacement server for Need for Speed Rivals.

Terminates TLS, speaks Blaze, and stands in for the online services EA shut down
on 2025-10-07. Handles login, the client config, QoS, matchmaking, shared
AllDrive sessions and progress saving.

It runs its own TLS handshake, presents a stand-in certificate (patched around a
ProtoSSL bug - see make_stub_cert.py), decrypts the premaster with its own
private key and reads the payload in the clear. That was originally the bridge to
the first readable Fire/Fire2 + TDF header; the game client will not talk to a
passive proxy, because it sends encrypted ApplicationData straight after the
handshake.

Handshake parameters (see docs/protocol.md):
  - negotiated version: TLS 1.1 (0x0302),
  - key exchange: RSA (the client encrypts the premaster with our public key),
  - cipher: TLS_RSA_WITH_RC4_128_SHA (0x0005) - offered by the client; we pick
    RC4 because without an IV or padding, record protection is trivial to
    implement compared with AES-CBC,
  - TLS 1.0/1.1 crypto: PRF = P_MD5 XOR P_SHA1, MAC = HMAC-SHA1.

No external dependencies: RSA decryption and RC4 are pure Python, in keeping with
the rest of proto-lab, which assembles TLS by hand. The key (n, d) is read once at
startup via `openssl rsa -text`. `cryptography` is not required.

Usage (the hosts file points gosredirector.ea.com at this machine):
    python proto-lab/make_stub_cert.py    # once, generates pki/
    python proto-lab/tls_terminator.py    # then start it and launch the game
"""

from __future__ import annotations

import argparse
import datetime as dt
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from tcp_proxy import hexdump, parse_records  # noqa: E402  (reused reporting)
import blaze  # noqa: E402  (Fire2 + TDF: request decoding and reply building)
import player_store  # noqa: E402  (progress saving from GameReporting reports)
import lobby  # noqa: E402  (player sessions and games - multiplayer)
import ea_identity  # noqa: E402  (which EA save id a player must log in under)

# --- protocol constants ---
VER_TLS11 = 0x0302
CIPHER_RC4_SHA = 0x0005
RT_CCS, RT_ALERT, RT_HANDSHAKE, RT_APPDATA = 20, 21, 22, 23
HS_CLIENT_HELLO, HS_SERVER_HELLO, HS_CERTIFICATE = 1, 2, 11
HS_SERVER_HELLO_DONE, HS_CLIENT_KEY_EXCHANGE, HS_FINISHED = 14, 16, 20
MAC_LEN = 20            # HMAC-SHA1
MAX_FRAGMENT = 16384    # TLS: at most 2^14 B of plaintext per record (RFC 4346 6.2.1)
RC4_KEY_LEN = 16        # RC4_128


# ---------------------------------------------------------------- cryptography
class RC4:
    """Stream RC4 - the state lasts for the whole life of the cipher state (per direction)."""

    def __init__(self, key: bytes) -> None:
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]
        self.s, self.i, self.j = s, 0, 0

    def crypt(self, data: bytes) -> bytes:
        s, i, j = self.s, self.i, self.j
        out = bytearray(len(data))
        for k, b in enumerate(data):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out[k] = b ^ s[(s[i] + s[j]) & 0xFF]
        self.i, self.j = i, j
        return bytes(out)


def p_hash(hashmod, secret: bytes, seed: bytes, n: int) -> bytes:
    out = b""
    a = seed
    while len(out) < n:
        a = hmac.new(secret, a, hashmod).digest()
        out += hmac.new(secret, a + seed, hashmod).digest()
    return out[:n]


def prf_tls10(secret: bytes, label: bytes, seed: bytes, n: int) -> bytes:
    """TLS 1.0/1.1 PRF: P_MD5(S1) XOR P_SHA1(S2), S1/S2 = the halves of the secret."""
    half = (len(secret) + 1) // 2
    s1, s2 = secret[:half], secret[-half:]
    md5 = p_hash(hashlib.md5, s1, label + seed, n)
    sha = p_hash(hashlib.sha1, s2, label + seed, n)
    return bytes(a ^ b for a, b in zip(md5, sha))


def der_tlv(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    """One DER element: returns (tag, content, position after the element)."""
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:                      # multi-byte length
        count = length & 0x7F
        length = int.from_bytes(buf[pos:pos + count], "big")
        pos += count
    return tag, buf[pos:pos + length], pos + length


def load_rsa_priv(key_path: Path) -> tuple[int, int, int]:
    """Returns (n, d, k_bytes) from the private key - our own DER parser.

    This used to go through `openssl rsa -text`, which required the openssl binary in
    PATH on EVERY server start. A clean Windows does not have it (we only had it from
    Git for Windows), so the packaged launcher would fail for anyone who does not have
    Git. Reading two numbers out of ASN.1 needs no cryptography - we stick to the
    "proto-lab without external dependencies" rule.

    Handles both formats that can end up in pki/:
      PKCS#1  "BEGIN RSA PRIVATE KEY" - SEQUENCE { ver, n, e, d, ... }
      PKCS#8  "BEGIN PRIVATE KEY"     - SEQUENCE { ver, alg, OCTET STRING{ ^ } }
    """
    raw = key_path.read_bytes()
    if b"-----BEGIN" in raw:
        body64 = b"".join(line for line in raw.splitlines()
                          if line and not line.startswith(b"-----"))
        der = base64.b64decode(body64)
    else:
        der = raw

    tag, body, _ = der_tlv(der, 0)
    if tag != 0x30:
        raise SystemExit(f"{key_path}: not a DER sequence (tag 0x{tag:02x})")

    # The second element decides the format: INTEGER => PKCS#1, SEQUENCE => PKCS#8.
    _, _, after_version = der_tlv(body, 0)
    tag2, _, after_alg = der_tlv(body, after_version)
    if tag2 == 0x30:
        tag3, inner, _ = der_tlv(body, after_alg)
        if tag3 != 0x04:
            raise SystemExit(f"{key_path}: PKCS#8 without an OCTET STRING holding the key")
        _, body, _ = der_tlv(inner, 0)

    # RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent,
    #                              privateExponent, ... } - we take the first 4.
    values, pos = [], 0
    for _ in range(4):
        tag, val, pos = der_tlv(body, pos)
        if tag != 0x02:
            raise SystemExit(f"{key_path}: expected INTEGER, got 0x{tag:02x}")
        values.append(int.from_bytes(val, "big"))

    _, n, _, d = values
    k = (n.bit_length() + 7) // 8
    return n, d, k


def rsa_decrypt_pkcs1(ct: bytes, n: int, d: int, k: int) -> bytes:
    """Raw RSA + stripping PKCS#1 v1.5 type 2 padding. Returns the premaster."""
    m = pow(int.from_bytes(ct, "big"), d, n)
    em = m.to_bytes(k, "big")
    if em[0] != 0x00 or em[1] != 0x02:
        raise ValueError(f"bad PKCS#1 padding: {em[:2].hex()}")
    sep = em.find(b"\x00", 2)
    if sep < 10:                       # PS must be >= 8 bytes
        raise ValueError("could not find the padding separator")
    return em[sep + 1:]


# ---------------------------------------------------------------- record layer
class Wire:
    """Buffer on the TCP stream: reads and writes TLS records, computes MAC/RC4."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""
        # Record layer version for what we send = TLS 1.1 (0x0302), EXACTLY as the
        # live EA server did it. The capture (docs/recon/capture/120822-003-s2c.bin)
        # shows the server sent ALL records as 0x0302 (ServerHello, Cert, Done, CCS,
        # Finished, AppData). The client uses 0x0300 ONLY for ClientHello, and from
        # ClientKeyExchange on it sends 0x0302 itself. So we do not echo the 0x0300 from
        # ClientHello - an earlier version did, and the client ended with a FIN right
        # after our Finished, without sending the first Blaze packet.
        self.record_version = VER_TLS11
        self.rx = None            # RC4 for decrypting (client->us), after CCS
        self.tx = None            # RC4 for encrypting (us->client), after CCS
        self.rx_mac = b""
        self.tx_mac = b""
        self.rx_seq = 0
        self.tx_seq = 0

    def _recv_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed in the middle of a record")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv_record(self) -> tuple[int, int, bytes]:
        head = self._recv_exact(5)
        rtype, ver, rlen = head[0], struct.unpack(">H", head[1:3])[0], \
            struct.unpack(">H", head[3:5])[0]
        try:
            frag = self._recv_exact(rlen)
        except socket.timeout:
            # Timeout in the MIDDLE of a record: put the header back into the buffer,
            # so the next recv_record resumes from the same place, not from halfway.
            self.buf = head + self.buf
            raise
        if self.rx is not None:                       # cipher state active
            frag = self._decrypt(rtype, ver, frag)
        return rtype, ver, frag

    def _decrypt(self, rtype: int, ver: int, frag: bytes) -> bytes:
        plain = self.rx.crypt(frag)
        if len(plain) < MAC_LEN:
            raise ValueError("record shorter than the MAC")
        body, mac = plain[:-MAC_LEN], plain[-MAC_LEN:]
        want = self._mac(self.rx_mac, self.rx_seq, rtype, ver, body)
        # Rejected, not just logged: the game's MAC has matched in every session so far (400 of
        # 400 handshakes in the run logs), so a mismatch means a broken or forged stream.
        if not hmac.compare_digest(mac, want):
            raise ValueError(f"bad record MAC (seq {self.rx_seq})")
        self.rx_seq += 1
        return body

    def send_record(self, rtype: int, body: bytes) -> None:
        """Sends body in as many records as it takes: TLS caps a record's plaintext at 2^14 B.
        Up to 1.0.9 everything went out as ONE record, and a profile picture over 16 KB
        (ByteVault, _serve_http) broke the game's connection a few seconds into a session."""
        ver = self.record_version
        out = b""
        for start in range(0, max(len(body), 1), MAX_FRAGMENT):
            frag = body[start:start + MAX_FRAGMENT]
            if self.tx is not None:
                mac = self._mac(self.tx_mac, self.tx_seq, rtype, ver, frag)
                frag = self.tx.crypt(frag + mac)
                self.tx_seq += 1
            out += struct.pack(">BHH", rtype, ver, len(frag)) + frag
        self.sock.sendall(out)

    @staticmethod
    def _mac(key: bytes, seq: int, rtype: int, ver: int, body: bytes) -> bytes:
        data = struct.pack(">QBHH", seq, rtype, ver, len(body)) + body
        return hmac.new(key, data, hashlib.sha1).digest()

    def activate_read(self, rc4: RC4, mac: bytes) -> None:
        self.rx, self.rx_mac, self.rx_seq = rc4, mac, 0

    def activate_write(self, rc4: RC4, mac: bytes) -> None:
        self.tx, self.tx_mac, self.tx_seq = rc4, mac, 0


# ---------------------------------------------------------------- handshake
def build_server_hello() -> tuple[bytes, bytes]:
    """Returns (server_random 32B, the ServerHello message with the handshake header)."""
    rnd = struct.pack(">I", int(time.time())) + os.urandom(28)
    body = struct.pack(">H", VER_TLS11) + rnd
    body += b"\x00"                                   # no session id
    body += struct.pack(">H", CIPHER_RC4_SHA)         # chosen cipher
    body += b"\x00"                                   # compression: null
    return rnd, hs_msg(HS_SERVER_HELLO, body)


def hs_msg(htype: int, body: bytes) -> bytes:
    return struct.pack(">B", htype) + len(body).to_bytes(3, "big") + body


def build_certificate(der: bytes) -> bytes:
    entry = len(der).to_bytes(3, "big") + der
    body = len(entry).to_bytes(3, "big") + entry      # cert list (length)
    return hs_msg(HS_CERTIFICATE, body)


def parse_client_hello(msg: bytes) -> tuple[bytes, list[int]]:
    """Returns (client_random 32B, list of ciphers). msg = handshake body (without the record header)."""
    body = msg[4:]                                    # skip the handshake header
    client_random = body[2:34]
    p = 34
    sid_len = body[p]; p += 1 + sid_len
    cs_len = struct.unpack_from(">H", body, p)[0]; p += 2
    suites = [struct.unpack_from(">H", body, p + i)[0] for i in range(0, cs_len, 2)]
    return client_random, suites


def derive_keys(pre_master: bytes, client_random: bytes, server_random: bytes):
    master = prf_tls10(pre_master, b"master secret",
                       client_random + server_random, 48)
    kb = prf_tls10(master, b"key expansion",
                   server_random + client_random, 2 * MAC_LEN + 2 * RC4_KEY_LEN)
    p = 0
    client_mac = kb[p:p + MAC_LEN]; p += MAC_LEN
    server_mac = kb[p:p + MAC_LEN]; p += MAC_LEN
    client_key = kb[p:p + RC4_KEY_LEN]; p += RC4_KEY_LEN
    server_key = kb[p:p + RC4_KEY_LEN]; p += RC4_KEY_LEN
    return master, client_mac, server_mac, client_key, server_key


def finished_verify(master: bytes, label: bytes, transcript: bytes) -> bytes:
    seed = hashlib.md5(transcript).digest() + hashlib.sha1(transcript).digest()
    return prf_tls10(master, label, seed, 12)


# ---------------------------------------------------------------- session
def handle(conn: socket.socket, addr, args, out_dir: Path,
           counter: list[int], lock: threading.Lock,
           rsa: tuple[int, int, int], cert_der: bytes) -> None:
    with lock:
        counter[0] += 1
        n = counter[0]
    tag = f"{dt.datetime.now():%H%M%S}-{n:03d}"
    try:
        local_port = conn.getsockname()[1]
    except OSError:
        local_port = 0
    role = "BLAZE" if local_port == args.blaze_port else "redirector"
    print(f"\n=== [{tag}] client {addr[0]}:{addr[1]} -> our port {local_port} "
          f"({role}) ===")

    # Until the handshake is done: a connection that opens and then says nothing would otherwise
    # hold this thread forever. The session timeouts replace it below.
    conn.settimeout(args.handshake_timeout)
    w = Wire(conn)
    sess = None                                       # Blaze session (lobby.py) - after the handshake
    transcript = b""                                  # handshake messages (with headers)
    bytevault = False                                 # this connection turned out to be ByteVault HTTP
    try:
        # 1. ClientHello
        rtype, ver, ch = w.recv_record()
        if rtype != RT_HANDSHAKE or not ch or ch[0] != HS_CLIENT_HELLO:
            print(f"  expected ClientHello, got type {rtype}")
            return
        transcript += ch
        # We do NOT echo the client's record version (0x0300 from ClientHello) - the live server
        # answered 0x0302 to everything (see the comment in Wire). record_version
        # stays VER_TLS11.
        client_random, suites = parse_client_hello(ch)
        print(f"  ClientHello: record {hex(ver)}, {len(suites)} cipher suites"
              f"{' (RC4_SHA offered)' if CIPHER_RC4_SHA in suites else ' (!) no RC4_SHA'}")

        # 2-4. ServerHello + Certificate + ServerHelloDone (separate records)
        server_random, sh = build_server_hello()
        cert = build_certificate(cert_der)
        shd = hs_msg(HS_SERVER_HELLO_DONE, b"")
        for m in (sh, cert, shd):
            transcript += m
            w.send_record(RT_HANDSHAKE, m)
        print(f"  -> ServerHello (RC4_SHA) + Certificate ({len(cert_der)} B) + Done")

        # 5. ClientKeyExchange
        try:
            rtype, ver, cke = w.recv_record()
        except ConnectionError:
            print("  [!] client dropped the connection right after Certificate (RST, no "
                  "Alert) - it most likely REJECTED the cert. Check the leaf issuer: "
                  "it must be DN OTG3 (make_stub_cert.py).")
            raise
        if rtype != RT_HANDSHAKE or not cke or cke[0] != HS_CLIENT_KEY_EXCHANGE:
            print(f"  expected ClientKeyExchange, got type {rtype}")
            _drain_alert(rtype, cke)
            return
        transcript += cke
        enc = cke[4:]                                 # CKE body
        enc = enc[2:] if len(enc) > (rsa[2]) else enc  # strip the 2B length (TLS)
        pre_master = rsa_decrypt_pkcs1(enc, *rsa)
        print(f"  ClientKeyExchange: premaster {len(pre_master)} B, "
              f"version inside premaster {pre_master[:2].hex()}")

        master, cmac, smac, ckey, skey = derive_keys(
            pre_master, client_random, server_random)

        # 6-7. ChangeCipherSpec + client Finished
        rtype, ver, ccs = w.recv_record()
        if rtype != RT_CCS:
            print(f"  expected ChangeCipherSpec, got type {rtype}")
            _drain_alert(rtype, ccs)
            return
        w.activate_read(RC4(ckey), cmac)              # from now on the client encrypts
        rtype, ver, fin = w.recv_record()
        if rtype != RT_HANDSHAKE or not fin or fin[0] != HS_FINISHED:
            print(f"  expected Finished, got type {rtype}")
            return
        want = finished_verify(master, b"client finished", transcript)
        got = fin[4:16]
        if not hmac.compare_digest(got, want):
            raise ValueError("client Finished: verify_data MISMATCH")
        print("  client Finished: verify_data OK")
        transcript += fin                             # for the server Finished

        # 8. ChangeCipherSpec + server Finished
        w.send_record(RT_CCS, b"\x01")
        w.activate_write(RC4(skey), smac)
        sfin = hs_msg(HS_FINISHED, finished_verify(master, b"server finished", transcript))
        w.send_record(RT_HANDSHAKE, sfin)
        print("  -> ChangeCipherSpec + server Finished")

        # 9. First ApplicationData = the first Blaze packet in the clear
        rtype, ver, app = w.recv_record()
        while rtype == RT_HANDSHAKE:                  # ignore any repeats
            rtype, ver, app = w.recv_record()
        if rtype != RT_APPDATA:
            print(f"  after the handshake got type {rtype}, not ApplicationData")
            _drain_alert(rtype, app)
            return

        if not args.no_capture:
            out_dir.mkdir(parents=True, exist_ok=True)

        # ByteVault connects to THE SAME port, but speaks HTTP (REST), not Fire2. In run-22
        # such connections hung on "tail ... waiting for the rest of the frame".
        if bytes(app[:7]).split(b" ")[0] in (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD"):
            print("  (this is HTTP, not Fire2 - ByteVault handling)")
            bytevault = True
            conn.settimeout(args.idle_timeout)
            _serve_http(w, bytearray(app), args)
            return

        # 10. Blaze server loop: decode EVERY Fire2 request and reply.
        #     NOTE: TLS record boundary != Fire2 frame boundary. The Blaze client
        #     can send several RPCs in one record (and split one RPC across two
        #     records). So we join the stream in a buffer and cut ALL COMPLETE frames
        #     out of it (12 B header + size). Previously only the first frame of a
        #     record was taken, and the tail went to the bin -> the client's RPC
        #     never finished (the "Connecting" screen).
        conn.settimeout(args.idle_timeout)
        buf = bytearray(app)
        frameno = 0
        # Every send on this connection goes through the session (lock + its own notification
        # msgIds): notifications to this player can also be sent by another player's thread (multiplayer).
        sess = lobby.Session(addr[0], lambda frame: w.send_record(RT_APPDATA, frame))
        logged_in = False                             # after 1/152; enables the keepalive
        ping_seq = 0                                  # msgId of server PINGs
        try:
            while True:
                # a) handle everything we already have in the buffer
                while len(buf) >= blaze.FIRE2_HDR:
                    size = struct.unpack_from(">H", buf, 0)[0]
                    total = blaze.FIRE2_HDR + size
                    if len(buf) < total:              # frame still incomplete
                        break
                    pkt = bytes(buf[:total])
                    del buf[:total]
                    frameno += 1
                    if not args.no_capture:
                        # Includes Authentication.login, whose AUTH is the player's EA code -
                        # the installed launcher passes --no-capture.
                        (out_dir / f"blaze-{tag}-{frameno:02d}.bin").write_bytes(pkt)
                    try:
                        fr = blaze.Fire2.decode(pkt)
                    except Exception as e:            # noqa: BLE001
                        print(f"  [!] could not decode Fire2: {e}")
                        print(hexdump(pkt, 256)); continue
                    if fr.component == GAME_REPORTING and fr.msg_type == 0:
                        _ack_game_report(sess, fr, args)
                        continue
                    name = blaze.rpc_name(fr.component, fr.command)
                    print(f"\n  <- Fire2 comp={fr.component} cmd={fr.command} "
                          f"err={fr.error} type=0x{fr.msg_type:02x} seq={fr.seq} "
                          f"payload={len(fr.payload)}B" + (f"  [{name}]" if name else ""))
                    if args.dump_tdf and fr.payload:
                        try:
                            print(blaze.dump_tdf(blaze.decode_tdf(fr.payload), 3))
                        except Exception as e:            # noqa: BLE001
                            print(f"      (could not decode the request TDF: {e})")
                    resp = _dispatch_blaze(fr, args, sess)
                    if resp is not None:
                        sess.send(resp)
                        print(f"  -> reply comp={fr.component} cmd={fr.command} "
                              f"({len(resp)} B)")
                        # After login - or a resumed session - we switch on a short timeout, so
                        # we wake up every keepalive seconds and keep the Blaze connection alive
                        # (see below - otherwise the game drops it with error 0x800e0000).
                        if not logged_in and sess.uid and args.keepalive:
                            logged_in = True
                            conn.settimeout(args.keepalive)
                        _deliver(sess, _after_reply(fr, args, sess))
                    else:
                        if name and "#" not in name:
                            # A command known from the binary; the raw frame is in the capture
                            # anyway, and --dump-tdf shows the fields - the hexdump only cluttered the log.
                            print(f"  *** no handler: {name} ***")
                        else:
                            print("  *** no handler - hexdump (next piece to build) ***")
                            print(hexdump(pkt, 384))
                        # By default we answer with an empty acknowledgement (err=0, empty
                        # payload = a reply with default values). Without it the game's RPC
                        # never finishes and the game waits forever. run-20: right after
                        # login 7 such requests arrived at once. --no-ack-unknown switches
                        # it off (to see which RPC the game is really stuck on).
                        if getattr(args, "ack_unknown", True) and fr.msg_type == 0:
                            ack = blaze.build_empty_reply(fr.component, fr.command, fr.seq,
                                                          msg_type=args.reply_msgtype)
                            sess.send(ack)
                            print(f"  -> empty acknowledgement comp={fr.component} "
                                  f"cmd={fr.command} ({len(ack)} B)")
                if buf:
                    print(f"  ({len(buf)} B tail - waiting for the rest of the frame)")

                # b) fetch the next record from the stream
                try:
                    rtype, ver, rec = w.recv_record()
                except socket.timeout:
                    # Silence != end of the session. The game keeps the Blaze connection
                    # open and may send nothing for a long time - we do NOT close it.
                    if logged_in and args.keepalive:
                        # Keepalive: after login the game runs QoS on separate sockets,
                        # and Blaze TCP goes quiet. The per-frame connection update
                        # (0xf3a580), once the idle threshold [conn+0x2fc] is exceeded,
                        # drops the connection with error 0x800e0000 -> teardown -> crash.
                        # A server PING resets the client's activity counter.
                        sess.send(blaze.build_server_ping(ping_seq))
                        print(f"  -> keepalive PING seq={ping_seq}")
                        ping_seq += 1
                        continue
                    print(f"  ({args.idle_timeout} s of silence - connection held, waiting)")
                    continue
                while rtype == RT_HANDSHAKE:
                    rtype, ver, rec = w.recv_record()
                if rtype == RT_ALERT:
                    _drain_alert(rtype, rec); break
                if rtype != RT_APPDATA:
                    print(f"  after the reply got type {rtype}, not ApplicationData")
                    break
                buf += rec
        except ConnectionError:
            print("  (client closed the connection)")

    except socket.timeout:
        # The session loop handles its own timeouts, so this is the handshake or ByteVault HTTP.
        if bytevault:
            print(f"  (ByteVault connection idle for {args.idle_timeout} s - closed; the game "
                  f"opens a new one when it needs one)")
        else:
            print(f"  (handshake not finished within {args.handshake_timeout:g} s - closed)")
    except (ConnectionError, ValueError, struct.error) as e:
        print(f"  session error: {e}")
    finally:
        if sess is not None:
            _cancel_matchmaking(sess)
        if sess is not None and sess.uid:
            # Disconnecting = leaving all games; the other players get notifications.
            _deliver(sess, _lobby(args).logout(sess))
            _arm_migrations(_lobby(args), args)
        try:
            conn.close()
        except OSError:
            pass


def _deliver(sess, notes) -> None:
    """Sends notifications (session, frame) - to our own connection and to other players. Another
    player's connection may already be closed: such an error is only logged."""
    for target, note in notes:
        nfr = blaze.Fire2.decode(note)
        who = "" if target is sess else f" -> to {target!r}"
        try:
            seq = target.notify(note)
        except OSError as e:
            print(f"  -> NOTIFY comp={nfr.component} cmd={nfr.command}{who} NOT SENT ({e})")
            continue
        print(f"  -> async NOTIFY comp={nfr.component} cmd={nfr.command} seq={seq} "
              f"({len(note)} B){who}")


def _bind_exclusive(s: socket.socket, ip: str, port: int, purpose: str) -> None:
    """A bind that fails LOUDLY when the port already belongs to someone. Called from the main
    thread only: sys.exit in any other thread ends just that thread, without a word.

    Why not SO_REUSEADDR (which used to be here): on Windows that option lets a
    SECOND process take the same address:port, and then only one of them gets the
    connections - in practice the one that bound first. So a new terminator printed
    the full set of listeners and received NOTHING, because the game was served by
    the old instance running the previous code. That cost the whole A/B run of
    2026-09-11: the logs of the new servers had only the banner, while Frida showed
    the game connecting and talking. SO_EXCLUSIVEADDRUSE reverses this: the second
    bind fails immediately, instead of silently posing as the running server."""
    excl = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
    if excl is not None:
        s.setsockopt(socket.SOL_SOCKET, excl, 1)
    try:
        s.bind((ip, port))
    except OSError as e:
        sys.exit(f"\nPORT {ip}:{port} ({purpose}) IS ALREADY IN USE: {e}\n"
                 f"Most likely a terminator from an earlier run is still running "
                 f"(and the game then talks to THAT one, not to this process).\n"
                 f"Check:  netstat -ano | Select-String {port}\n"
                 f"and stop that process before starting this one.")


def _qos_body(req: bytes, args, peer=None) -> bytes:
    """Body of the QoS coordinator reply. Format: XML (DirtySDK xmlparse).

    Established from disassembling a memory dump (RVA, module base 0x140000000):
    _QosApiParseResponse @0xfdb070 takes the HTTP reply buffer
    (*(QosApiRef+0x128) + 0x112) and tries in turn XmlFind(buf, "firewall"),
    XmlFind(buf, "firetype"), XmlFind(buf, "qos"); when none hits -> -2.

    XmlFind @0xfee910 scans to '<', skips <?..?> and <!..>, stops at '</',
    and the element name terminator is the mask 0x40008001FFFFFFFF = {0x00-0x20, '/',
    '>'} - there is NO '=' in it, so the names from the binary (".numprobes", ".probesize",
    ".qosport", ".requestid", ".reqsecret") are XML ELEMENT names, not
    "key=value" keys or attributes. The values are read by
    XmlContentGetInteger @0xfee6a0 (after '<' it skips to '>', <tag/> = default),
    and XmlNext @0xfeeaf0 walks the siblings (the ips/ports lists).

    That is why the previous reply ("qos.numprobes=1 qos.probesize=64 ...",
    TagField format) did not contain A SINGLE '<' - the parser returned -2 and the
    game stayed silent on UDP, even though it had read the reply.

    The game's validation (0xfdb3f1-0xfdb424), returns 0 only if it passes:
      * qosport  != 0  (always)
      * requestid != 0 (always)
      * for qtyp == 2 (bandwidth test) additionally probesize != 0 and numprobes >= 2
    probesize is the probe packet length, so it has to be sensible for
    qtyp == 1 too.

    We point qosport at ourselves: the client will send UDP probes there, which
    the echo responder bounces back. A probe (builder @0xfdbc30) carries big-endian
    requestid, reqsecret, the probe counter and numprobes, and the receiver @0xfdb9c9
    compares those fields with its state - a byte-for-byte echo satisfies all three
    conditions.
    """
    path = req.split(b" ", 2)[1] if b" " in req else b"/"
    port = args.qos_port
    if b"/qos/firewall" in path:
        # The keys of this branch are NESTED PATHS, not flat names: .rdata holds a
        # single string ".ips.ips" with a NUL at the end (@0x170ef18) and ".ports.ports"
        # (@0x170ef28) - one NUL at the end each, the dot in the middle means descending
        # into a child. So the game looks for an `ips` element INSIDE an `ips` element:
        #     <ips><ips>A</ips><ips>B</ips></ips>
        # A flat <ips>A</ips> is not found - confirmed by the live state from a memory
        # dump: numinterfaces was stored (0xfdb0b6), while ips[0] and ports[0] stayed
        # zero, because XmlFind(".ips.ips") returned NULL and the parser exited with -2
        # (0xfdb100 -> 0xfdb269).
        # By contrast, the /qos/qos branch has flat keys (".numprobes" etc.).
        #
        # Successive pairs are successive PORTS on the same IP - the NAT test compares
        # the external port seen from two different server endpoints, so they must
        # differ. The UDP listeners on those ports are brought up by main()
        # (--qos-interfaces).
        nint = 1
        for part in path.split(b"&"):
            if part.startswith(b"nint=") or part.startswith(b"?nint="):
                try:
                    nint = int(part.split(b"=", 1)[1])
                except ValueError:
                    pass
        nint = max(1, min(nint, args.qos_interfaces))      # only as many as are listening
        # A client on another computer has to reach the UDP probes at the server's network address.
        server_ip = args.redirect_ip if peer is None or peer[0] in lobby.LOCAL_IPS \
            else _public_ip(args)
        ip = int.from_bytes(bytes(int(o) for o in server_ip.split(".")), "big")
        ips = "".join(f"<ips>{ip}</ips>" for _ in range(nint))
        ports = "".join(f"<ports>{port + i}</ports>" for i in range(nint))
        return (f"<firewall><numinterfaces>{nint}</numinterfaces>"
                f"<ips>{ips}</ips><ports>{ports}</ports>"
                f"<requestid>{args.qos_requestid}</requestid>"
                f"<reqsecret>1</reqsecret></firewall>").encode()
    if b"/qos/firetype" in path:
        # The value ends up in [conn+0x1b0]; when == 5, the game does not call the callback
        # (5 = the "unknown" sentinel), so we send something else. We do not know the enum's
        # semantics - hence the --qos-firetype flag for bisecting.
        return (f"<firetype><firetype>{args.qos_firetype}</firetype>"
                f"</firetype>").encode()
    # /qos/qos?vers=1&qtyp=N&prpt=P  (prpt = the port the client probes from)
    return (f"<qos><numprobes>{args.qos_numprobes}</numprobes>"
            f"<probesize>{args.qos_probesize}</probesize>"
            f"<qosport>{port}</qosport>"
            f"<requestid>{args.qos_requestid}</requestid>"
            f"<reqsecret>1</reqsecret></qos>").encode()


IDENTIFY_PATH = "/turborivals/identify"


NAME_MAX = 32                   # a nickname from a guest's launcher is cut to this
NAME_FOLD = str.maketrans("ŁłØøĐđßÆæŒœ", "LlOoDdsAaOo")   # letters NFKD does not decompose


def _clean_name(name: str) -> str:
    """A nickname as the other players will see it: printable ASCII, like every EA nickname -
    accents are folded (Ł -> L, é -> e), anything else dropped - trimmed to NAME_MAX. Also keeps
    the log printable on a console codepage."""
    folded = unicodedata.normalize("NFKD", name.translate(NAME_FOLD))
    return "".join(ch for ch in folded if " " <= ch <= "~").strip()[:NAME_MAX].strip()


def _identify(req: bytes, args, peer) -> tuple[bytes, bytes] | None:
    """GET /turborivals/identify?id=<save id>&user=<EA App user>&saves=<id,id,...>&src=<how the
    id was found>&name=<nickname> - a guest's launcher (launcher/commands.identify_to_host)
    reporting, before it starts the game, the id of the save that game loads and the name the
    player wants. Registered for the address it comes from (lobby.register), so the login from
    there gets that uid and name; user also vouches for an id whose suffix differs from the
    token's. saves and src are only logged: with no access to the guest's machine they are how
    to tell whether its launcher picked the right save. Rides on the QoS HTTP port, which the
    host already opens. Returns (status, body), or None for another path."""
    try:
        target = req.split(b" ", 2)[1].decode("ascii")
    except (IndexError, UnicodeDecodeError):
        return None
    url = urllib.parse.urlsplit(target)
    if url.path != IDENTIFY_PATH:
        return None
    query = urllib.parse.parse_qs(url.query)
    uid, user, saves, src, name = (query.get(k, [""])[0]
                                   for k in ("id", "user", "saves", "src", "name"))
    name = _clean_name(name)
    print(f"\n  [identity] {peer[0]} launcher: name {name or '-'}, save id {uid or '-'} "
          f"({src or 'source not sent'}), EA App user {user or '-'}, saves {saves or '-'}")
    if not uid.isdigit() or ea_identity.is_synthetic(int(uid)):
        print(f"  [identity] WARNING {peer[0]}: no usable save id - that player gets a synthetic "
              f"uid and its progress will not survive a restart")
        if name:
            _lobby(args).names[peer[0]] = name    # the name still counts
        return b"400 Bad Request", b"no usable save id"
    _lobby(args).register(peer[0], int(uid), name=name,
                          user=int(user) if user.isdigit() else 0,
                          guess=src == ea_identity.SOURCE_GUESS)
    return b"200 OK", b"ok"


LAUNCHER_PREFIX = "/turborivals/"
AVATAR_MAX = 64 * 1024              # a launcher sends a 128 px PNG, well under this
GAME_PICTURE_MAX = 16 * 1024        # the JPEG a 1.0.10 launcher makes for the game, at most
HTTP_HEAD_MAX = 8192
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"


def _read_request(conn: socket.socket, limit: int = AVATAR_MAX) -> tuple[bytes, bytes | None]:
    """(head, body) of one HTTP request. The head is read up to the blank line - the game's QoS
    GETs arrive in one piece, so that costs them nothing - and the body per Content-Length, up
    to `limit`. body is None when the request announces more than that."""
    data = b""
    while b"\r\n\r\n" not in data and len(data) < HTTP_HEAD_MAX:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length" and value.strip().isdigit():
            length = int(value.strip())
    if length > limit:
        return head, None
    while len(body) < length:
        chunk = conn.recv(min(65536, length - len(body)))
        if not chunk:
            break
        body += chunk
    return head, body[:length]


def _avatar_path(args, uid: int) -> Path:
    return _data_root(args) / "avatars" / f"{uid}.png"


def _launcher_request(head: bytes, body: bytes | None, args,
                      peer) -> tuple[bytes, bytes, bytes] | None:
    """Requests from a launcher, on the QoS HTTP port (which every player already reaches):
    (status, content type, body), or None for anything else - that is the game's QoS.

      GET  /turborivals/identify         save id and name before the game starts (_identify)
      POST /turborivals/avatar           the sender's own picture, at most AVATAR_MAX: a PNG for
                                         the launchers, a JPEG for the game. Whose it is comes
                                         from the sender's ADDRESS (Lobby.uid_for), so nobody can
                                         replace someone else's
      DELETE /turborivals/avatar         removes the sender's own picture, both files
      GET  /turborivals/players          who is logged in right now (ONLINE NOW), JSON
      GET  /turborivals/avatar/<uid>     that player's picture
    """
    try:
        method, target = head.split(b" ", 2)[:2]
        path = urllib.parse.urlsplit(target.decode("ascii")).path
    except (ValueError, UnicodeDecodeError):
        return None
    if not path.startswith(LAUNCHER_PREFIX):
        return None
    text = b"text/plain"
    if path == IDENTIFY_PATH:
        status, reply = _identify(head, args, peer)
        return status, text, reply
    if path == LAUNCHER_PREFIX + "avatar" and method in (b"POST", b"DELETE"):
        # Refusals go into the log too: a launcher only shows "picture not sent" to its own
        # player, and the host had no way to tell why.
        def refused(status: bytes, why: str):
            print(f"  [avatar] {peer[0]}: refused - {why}")
            return status, text, why.encode()

        uid = _lobby(args).uid_for(peer[0])
        if not uid:
            return refused(b"409 Conflict", "unknown player - connect first (JOIN A SESSION)")
        if method == b"DELETE":
            removed = []
            for suffix in (".png", ".jpg"):
                f = _avatar_path(args, uid).with_suffix(suffix)
                try:
                    f.unlink()
                    removed.append(suffix[1:])
                except FileNotFoundError:
                    pass
                except OSError as e:
                    return b"500 Internal Server Error", text, str(e).encode(errors="replace")
            print(f"  [avatar] {peer[0]}: picture of uid {uid} removed ({', '.join(removed) or 'none'})")
            return b"200 OK", text, b"ok"
        # PNG for the launchers, JPEG for the game (ByteVault Pictures, _bytevault_record)
        kind = ".png" if body and body.startswith(PNG_MAGIC) else \
               ".jpg" if body and body.startswith(JPEG_MAGIC) else ""
        if body is None or len(body) > AVATAR_MAX or not kind:
            return refused(b"400 Bad Request", "a PNG or JPEG of at most 64 KB")
        target_file = _avatar_path(args, uid).with_suffix(kind)
        try:
            target_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = target_file.with_suffix(".tmp")
            tmp.write_bytes(body)
            os.replace(tmp, target_file)
        except OSError as e:
            return b"500 Internal Server Error", text, str(e).encode(errors="replace")
        print(f"  [avatar] {peer[0]}: picture of uid {uid} saved ({kind[1:]}, {len(body)} B)"
              + (" - more than a 1.0.10 launcher makes; the game gets it in several TLS records"
                 if kind == ".jpg" and len(body) > GAME_PICTURE_MAX else ""))
        return b"200 OK", text, b"ok"
    if path == LAUNCHER_PREFIX + "players":
        players = []
        for p in _lobby(args).online():
            f = _avatar_path(args, p["uid"])
            # the picture's version: launchers re-download it only when this changes
            players.append({**p, "avatar": f.stat().st_mtime_ns // 1_000_000 if f.exists() else 0})
        return b"200 OK", b"application/json", json.dumps(players).encode()
    if path.startswith(LAUNCHER_PREFIX + "avatar/"):
        uid = path.rsplit("/", 1)[-1]
        f = _avatar_path(args, int(uid)) if uid.isdigit() else None
        if f is None or not f.exists():
            return b"404 Not Found", text, b"no picture"
        return b"200 OK", b"image/png", f.read_bytes()
    return b"404 Not Found", text, b"unknown launcher request"


def _qos_probe_reply(data: bytes, peer, args) -> bytes:
    """Reply to a QoS UDP probe. A bare echo is NOT ENOUGH, and the two kinds of
    probes need DIFFERENT replies.

    The receiver @0xfdb6a0 picks the path by the +0x04 field of OUR reply
    (0xfdb76d: `cmp r15d, 2; jae ...`), not by what the client sent:
      ntohl(+0x04) <  2  -> latency / external address path
      ntohl(+0x04) >= 2  -> bandwidth path, comparing requestid and reqsecret
    That is why the requestid in the HTTP reply MUST be >= 2 (otherwise the bandwidth
    path is unreachable), and in the reply to a latency probe we hardcode 1.

    LATENCY PROBE - 20 B, builder @0xfdbe80 (length hardcoded 0x14), BE:
        +0x00 ping site id    +0x04 requestid  +0x08 reqsecret
        +0x0c [QosApi+0x14]   +0x10 send time (NetTick)
    The reply MUST be >= 0x1e = 30 B (0xfdb777) and contain:
        +0x04 = 1             selects the latency path
        +0x10 = probe time    RTT = receive_time - ntohl(+0x10)   (0xfdb82e)
        +0x14 = client IP     stored in the state as the external address (0xfdb7cb)
        +0x18 = client port   u16 (0xfdb804)
        +0x1a = 0             tail length; memcpy from +0x1e only when
                              (length - 1) <= 0xff, so 0 = no tail
    Point of the probe: the client learns its external address and measures the RTT.

    BANDWIDTH PROBE - probesize long, builder @0xfdbc30, BE:
        +0x00 id  +0x04 requestid  +0x08 reqsecret
        +0x0c sent counter (0, 1, 2, ...)   +0x10 numprobes
    The reply has a DIFFERENT layout from the probe (the code reads other offsets from it):
        +0x04 = requestid, +0x08 = reqsecret  - compared with the state (0xfdb9d0)
        +0x0c = HOW MANY PROBES WE HAVE RECEIVED; once it equals numprobes (0xfdba7b),
                the bandwidth test is closed: 0xfdba94 sets bit0 "done"
                (with firetype != 5; when == 5, 0xfdbaa0 moves on to qtyp 5)
        +0x14 = the client's UPLOAD bandwidth measured by the server, in bits/s -
                read ONLY from the first reply (0xfdba05)
    The DOWNLOAD bandwidth the client computes itself from the timing of our replies
    (0xfdba1f: received * probesize * 8000 / time), so it is enough to answer
    every probe.

    We take the received counter from the probe (+0x0c) + 1 - the probe numbers itself
    from zero, so we keep no state at all, and on the last probe it comes out as
    exactly numprobes.
    """
    if len(data) < 0x10:
        return data                        # too short, the game will reject it anyway
    buf = bytearray(data)
    if len(data) == 0x14:                  # latency probe
        buf[0x04:0x08] = (1).to_bytes(4, "big")
        # The external address the client later reports to other players (HNET/PNET). The local
        # player probes from 127.0.0.1 - a second computer cannot connect to such an address, so we
        # give this computer's network address (--public-ip or the detected LAN one). --public-ip
        # 127.0.0.1 restores the old behaviour.
        seen = _public_ip(args) if peer[0] in lobby.LOCAL_IPS else peer[0]
        ip = bytes(int(o) for o in seen.split("."))
        return bytes(buf) + ip + peer[1].to_bytes(2, "big") + bytes(4)
    got = int.from_bytes(data[0x0c:0x10], "big") + 1
    buf[0x0c:0x10] = got.to_bytes(4, "big")
    if len(buf) >= 0x18:
        buf[0x14:0x18] = args.qos_upstream_bps.to_bytes(4, "big")
    return bytes(buf)


RECOMMENDATIONS_PER_RIVAL = 20       # "beat you" entries per rival (1.0.12.3 sent 20 fine)
EVENT_RECOMMENDATIONS_PER_RIVAL = 10  # of which events at most; the speed walls fill the rest


def _autolog_players(args, lb, me: int) -> tuple[set[int], set[int]]:
    """Whose results Autolog and the speed walls show the asker: (shown, left out).

    Lobby.ranked_uids (and --autolog-rival), less any OTHER player online whose identity is not
    confirmed (Lobby.unconfirmed_uids: EA save id unknown, guessed, or not the PersonaId its game
    reports). The asker's game cannot tie such a player's car to his Blaze user, so his results
    from the session leave his rows empty there. On 02.10 (Player_15: no launcher, a cracked
    game) that crashed the host's rival card, and the cameras he had just driven ahead of the
    host showed nobody - he led most of them. Offline such a player is not ranked anyway.
    --autolog-unconfirmed-rivals shows them as up to 1.0.12.6 (A/B)."""
    shown = lb.ranked_uids() | set(getattr(args, "autolog_rival", None) or [])
    if getattr(args, "autolog_unconfirmed_rivals", False):
        return shown, set()
    out = (lb.unconfirmed_uids() - {me}) & shown
    return shown - out, out


def _autolog_recommendations(fr, args, sess) -> bytes:
    """NFS.getInGameRecommendations (2050/21): Autolog's rivals and their speed walls.

    The game asks this after login and now and then (3x in a session). It used to get an empty
    acknowledgement, and the speed walls showed no rival although getInGameSpeedWalls carried
    their rows: InGameRecommendationsResponse::mSpeedWallIDToSpeedWallMap says the rivals' walls
    come from here. A rival = every other player with a known career save or online
    (Lobby.ranked_uids) who has a speed wall result; PLSC/RISC = on how many shared walls the asker /
    the rival leads. The map holds every wall a rival has a result on, shared ones first, as many
    as fit in a Fire2 frame.

    RECM = "X beat you": the shared walls the rival leads. Events (races, pursuits ...) come first,
    up to 10, and cameras, zones and jumps fill the rest up to 20, newest first in each group. The
    newest 20 alone were all cameras, which left the events out. A rival with no entry is left
    out of the list but stays on the walls: an empty RECM crashes the game (confirmed 02.10,
    decisions.md). --autolog-world-only drops the event entries (the 1.0.12.4 behaviour).

    A player online whose identity is not confirmed is neither a rival nor on the walls
    (_autolog_players). On 02.10 clicking Player_15 (no launcher, a cracked game, a synthetic uid)
    crashed the host's game (NFS14.exe+0x9731bb): the card reads the rival's row on the wall of
    each of its entries, and right after Player_15 drove through one of those cameras in the
    host's session his row there had no stats - the host's game could not tie his car to his
    Blaze user. --autolog-no-session-rivals leaves everyone in the asker's game off the list
    (they stay on the walls), should the same ever happen with a confirmed player.

    --autolog-vehicles (A/B): a rival's car (vehicleUsed) none of the asker's own results was driven
    in - keep = as stored, drop = left out, swap = the asker's most used car. Suspected first, ruled
    out on 02.10: offline, Player_15 with 18 such entries clicked fine.
    --autolog-rival UID treats a stored player as if online (tests only)."""
    req = _req_fields(fr)
    mt = args.reply_msgtype
    me = int(req.get("BLID", 0) or 0) or sess.uid
    store, lb = _player_store(args), _lobby(args)
    if not store or not me:
        return blaze.build_empty_reply(2050, 21, fr.seq, msg_type=mt)
    ranked, unconfirmed = _autolog_players(args, lb, me)
    mine = store.speedwall_ids(me)
    rows_of: dict[int, dict[int, dict]] = {}

    def rows(swid: int) -> dict[int, dict]:
        if swid not in rows_of:
            rows_of[swid] = {r["blaze_id"]: r for r in store.rows_for_entity(swid)
                             if r["blaze_id"] in ranked}
        return rows_of[swid]

    vehicles = getattr(args, "autolog_vehicles", "keep")
    my_cars = store.vehicles(me) if vehicles != "keep" else {}
    my_car = max(my_cars, key=my_cars.get) if my_cars else None
    hidden: set[int] = set()

    def shown(row: dict) -> dict:
        """The row as the asker's game gets it: a copy, without a car it may not have."""
        car = row.get("int", {}).get("vehicleUsed")
        if vehicles == "keep" or car is None or car in my_cars:
            return dict(row)
        hidden.add(car)
        ints = {k: v for k, v in row["int"].items() if k != "vehicleUsed"}
        if vehicles == "swap" and my_car is not None:
            ints["vehicleUsed"] = my_car
        return {**row, "int": ints}

    beat_type = getattr(args, "autolog_beat_type", blaze.RECOMMENDATION_BEAT_YOU)
    world_only = getattr(args, "autolog_world_only", False)
    world_ids = store.speedwall_ids(me, world_only=True)
    # never a Speedlist: the rival card cannot name one ("INVALID SPEEDWALL: 12", no route)
    recommendable = (world_ids if world_only else mine) - store.speedwall_ids(
        me, kinds=player_store.UNNAMED_SPEEDWALL_CATEGORIES)
    mates = lb.game_mates(me) if getattr(args, "autolog_no_session_rivals", False) else set()
    rivals, left_out, theirs_all = [], [], set()
    kept_off = [lb.persona_of(pid) + " (identity not confirmed)" for pid in sorted(unconfirmed)]
    for pid in sorted(ranked - {me}):
        theirs = store.speedwall_ids(pid)
        if not theirs:
            continue
        theirs_all |= theirs                  # on the walls either way
        persona = lb.persona_of(pid)
        if pid in mates:
            kept_off.append(persona + " (in your game)")
            continue
        lead = trail = 0
        beaten = []
        for swid in mine & theirs:
            a = player_store.primary_stat(rows(swid).get(me))
            b = player_store.primary_stat(rows(swid).get(pid))
            if a and b and a[0] == b[0] and a[1] != b[1]:
                if (a[1] < b[1]) if a[2] else (a[1] > b[1]):
                    lead += 1
                    continue
                trail += 1
                if swid in recommendable:
                    # the rival is ahead here: "X beat you" - a target to go and beat
                    beaten.append({"swid": swid, "blaze_id": pid, "persona": persona,
                                   "type": beat_type, "row": shown(rows(swid)[pid]),
                                   "title": blaze.RECOMMENDATION_TITLES.get(beat_type,
                                                                            "ID_REC_TITLE_BEAT")})
        if not beaten and not getattr(args, "autolog_empty_rivals", False):
            left_out.append(persona)
            continue
        beaten.sort(key=lambda rec: rec["row"].get("updated", 0), reverse=True)
        events = [rec for rec in beaten if rec["swid"] not in world_ids][:EVENT_RECOMMENDATIONS_PER_RIVAL]
        world = [rec for rec in beaten if rec["swid"] in world_ids]
        rivals.append({"blaze_id": pid, "persona": persona, "player_score": lead,
                       "rival_score": trail, "events": len(events),
                       "recommendations": events + world[:RECOMMENDATIONS_PER_RIVAL - len(events)]})
    if not rivals:
        # a first-time or solo player: an empty RILI never reached the game, and an empty RECM
        # crashes it, so the bare acknowledgement it got without trouble until 1.0.12.1
        print(f"  [autolog] {lb.persona_of(me)}: no rival"
              + (f" (left out with nothing to beat: {', '.join(left_out)})" if left_out else "")
              + (f" (not listed: {', '.join(kept_off)})" if kept_off else "")
              + " - bare acknowledgement")
        return blaze.build_empty_reply(2050, 21, fr.seq, msg_type=mt)
    walls = []
    for swid in sorted(theirs_all & mine) + sorted(theirs_all - mine):
        walls.append((swid, [{**shown(r), "persona": lb.persona_of(r["blaze_id"])}
                             for r in rows(swid).values()]))
    frame, sent = blaze.build_in_game_recommendations_response(
        fr.seq, rivals, walls, local_id=me, rival_relation=args.speedwall_relation, msg_type=mt)
    print(f"  [autolog] {lb.persona_of(me)}: {len(rivals)} rival(s)"
          + (" (" + "; ".join(f"{r['persona']}: you lead {r['player_score']}, they lead "
                              f"{r['rival_score']}, {len(r['recommendations'])} \"beat you\" "
                              f"({r['events']} on events)" for r in rivals) + ")" if rivals else "")
          + (f", left out with nothing to beat: {', '.join(left_out)}" if left_out else "")
          + (f", not listed: {', '.join(kept_off)}" if kept_off else "")
          + (", \"beat you\" on speed walls only" if world_only else "")
          + f", {sent} of {len(walls)} speed wall(s) sent"
          + (f", {len(hidden)} car(s) not in your game "
             + ("swapped for yours" if vehicles == "swap" and my_car is not None else "left out")
             if hidden else ""))
    return frame


def _speed_walls(fr, args, sess) -> bytes:
    """NFS.getInGameSpeedWalls (2050/20): the game asks about a speed wall when it approaches a
    speed camera, a zone or an event (run-25: 46 queries about 35 ids). The id is the ENTI from
    GameReporting reports, so the rows come from the stored state - the players
    _autolog_players shows the asker. --no-speed-walls goes back to an empty acknowledgement."""
    req = _req_fields(fr)
    store, lb = _player_store(args), _lobby(args)
    me = int(req.get("BLID", 0) or 0) or sess.uid
    shown, unconfirmed = _autolog_players(args, lb, me)
    walls = []
    for swid in req.get("SWIS") or []:
        stored = store.rows_for_entity(swid) if store else []
        rows = [{**r, "persona": lb.persona_of(r["blaze_id"])}
                for r in stored if r["blaze_id"] in shown]
        walls.append((int(swid), rows))

        def score(r) -> str:
            # the row's main value (speed, AverageSpeed, distance, eventTime), so the log
            # shows who is ahead
            main = player_store.primary_stat(r)
            return f"{main[1]:.1f} {main[0]}" if main else "-"
        hidden = [lb.persona_of(r["blaze_id"]) for r in stored if r["blaze_id"] in unconfirmed]
        print(f"  [speed wall] {swid}: " + (", ".join(
            f"{'you' if r['blaze_id'] == me else r['persona']} {score(r)}" for r in rows)
            or "no results yet")
            + (f" (not shown, identity not confirmed: {', '.join(hidden)})" if hidden else ""))
    return blaze.build_in_game_speed_walls_response(
        fr.seq, walls, local_id=me, rival_relation=args.speedwall_relation,
        msg_type=args.reply_msgtype)


def _autolog_other(fr, args, sess) -> bytes | None:
    """The rest of Autolog on the NFS component, or None for another command:
      39 getSpecialGuestInfo      - an empty, well-formed reply (no Special Guests exist any more);
                                    the bare acknowledgement had the game ask ~700 times a session
      41 getSpecialGuestSpeedWall - empty speed walls for the ids asked about
      29 getAutologPlaylist       - empty playlist (its entries' layout is unknown)
      31 setRecommendationRivalScore {BLID PLSC RIBL RISC} - logged and acknowledged"""
    mt = args.reply_msgtype
    req = _req_fields(fr)
    if fr.command == 39:
        return blaze.build_special_guest_info_response(fr.seq, msg_type=mt)
    if fr.command == 41:
        walls = [(int(swid), []) for swid in req.get("SWIS") or []]
        return blaze.build_in_game_speed_walls_response(fr.seq, walls, command=41, msg_type=mt)
    if fr.command == 29:
        return blaze.build_autolog_playlist_response(
            fr.seq, int(req.get("BLID", 0) or 0) or sess.uid, msg_type=mt)
    if fr.command == 31:
        print(f"  [autolog] {sess!r} reports its score against rival {req.get('RIBL')}: "
              f"{req.get('PLSC')}:{req.get('RISC')}")
        return blaze.build_empty_reply(2050, 31, fr.seq, msg_type=mt)
    return None


# The key our login reply gives every session (build_login_response, KEY = "1_<uid>_sess").
SESSION_KEY_RE = re.compile(r"^1_(\d+)_sess$")
# Error code for a session that cannot be resumed here. ASSUMED: ERR_SYSTEM (1) - the numeric
# value of USER_ERR_RESUMABLE_SESSION_NOT_FOUND is not known. Any error beats the old empty
# acknowledgement, which told the game "resumed" while the server did not know who it was.
RESUME_REFUSED = 1


def _resume_session(fr, args, sess) -> bytes:
    """UserSessions.resumeSession (0x7802/0x23), ResumeSessionRequest {SKEY mSessionKey}.

    A game whose Blaze connection dropped - the host's server restarted, the PC slept - comes
    back with the session key of its earlier login instead of logging in again (01.10,
    server-20261001-203209: straight on the Blaze port, 23 B = "1_1802434674_sess"). It used to
    get an empty acknowledgement, pinged once and gave up. Now the key's uid takes the session
    back (Lobby.resume) and the login notifications follow (_after_reply); a key that cannot be
    resumed gets an error, so the game logs in from scratch."""
    key = str(_req_fields(fr).get("SKEY", ""))
    m = SESSION_KEY_RE.match(key)
    uid = int(m.group(1)) if m else 0
    if uid and sess.uid == uid:
        notes = []                                    # this connection already is that player
    else:
        notes = _lobby(args).resume(sess, uid) if uid and not sess.uid else None
    if notes is None:
        print(f"  [resume] WARNING {sess.ip}: session key {key!r} cannot be resumed here - "
              f"answering with an error, so the game logs in again")
        return blaze.Fire2(component=0x7802, command=0x23, payload=b"", error=RESUME_REFUSED,
                           seq=fr.seq, msg_type=args.reply_msgtype).encode()
    sess.outbox += notes
    sess.resumed = True
    print(f"  [player] {sess.ip} -> {sess.persona} (uid {sess.uid}, resumeSession)")
    return blaze.build_empty_reply(0x7802, 0x23, fr.seq, msg_type=args.reply_msgtype)


def _lookup_users(fr, args, sess) -> bytes:
    """UserSessions.lookupUsers (0x7802/13): the game asks who owns a car whose id no Blaze user
    has (LTYP 0 = by BlazeId). Unanswered, that car stays an ordinary racer - icon and name only
    up close (1.0.0 after a session change; log-40). Lobby.resolve finds the player; the reply
    carries the id the game asked about, so its car and the Blaze user match from then on."""
    req = _req_fields(fr)
    lb = _lobby(args)
    found = []
    for ident in req.get("ULST") or []:
        fields = {t.strip(): v for t, _w, v in ident} if isinstance(ident, list) else {}
        asked = int(fields.get("ID", 0) or 0)
        if not asked:
            continue
        user = lb.resolve(sess, asked)
        if user is None:
            print(f"  [lookup] WARNING {sess!r} asks about id {asked}, which is no player's - the car "
                  f"behind it stays an ordinary racer (name only up close). Check that player's "
                  f"career save in its launcher (orange = guessed), or pass --player-id IP=<id>")
            continue
        print(f"  [lookup] {sess!r} asks about id {asked} -> {user['persona']} ({user['how']})")
        found.append(user)
    return blaze.build_lookup_users_response(fr.seq, found, msg_type=args.reply_msgtype)


def _dispatch_blaze(fr, args, sess):
    """Returns the Fire2 reply bytes for a known request, or None (no handler).
    `sess` = this connection's lobby.Session (player identity, address, games)."""
    if fr.component == 5 and fr.command == 1:          # Redirector.getServerInstance
        return blaze.build_getserverinstance_response(
            args.redirect_ip, args.blaze_port, seq=fr.seq,
            addr_index=args.addr_index, minimal=args.addr_only,
            msg_type=args.reply_msgtype, host=args.blaze_host)
    if fr.component == 9 and fr.command == 7:           # Util.preAuth
        if args.no_client_config:
            conf = {}                                   # empty CONF (old behaviour)
        elif args.client_config is not None:
            conf = dict(kv.split("=", 1) for kv in args.client_config.split(",") if kv)
        else:
            conf = dict(blaze.DEFAULT_CLIENT_CONFIG)
            if not args.no_bytevault:
                # ByteVault: right after login (the game's online state 9 -> 10 in 0xa1bb00) the
                # game reads these keys and initializes the ByteVault connection (0xf71b40). Without
                # them it takes the default EA host, which is dead. Formats from the code: port via
                # atoi (getter +0x48), secure = comparison with "true", host as a string.
                # We point it at our Blaze - unknown RPCs show up in the log as "no handler".
                conf.update({
                    "bytevaultHostname": args.bytevault_host or args.blaze_host,
                    "bytevaultPort": str(args.bytevault_port or args.blaze_port),
                    "bytevaultSecure": "true",
                })
        return blaze.build_preauth_response(
            fr.seq, msg_type=args.reply_msgtype, client_config=conf,
            qos=not args.no_qoss, qos_host=_client_facing_ip(sess, args),
            qos_port=args.qos_port, pad_to=args.pad_preauth)
    if fr.component == 9 and fr.command == 2:           # Util.ping
        return blaze.build_ping_response(fr.seq, msg_type=args.reply_msgtype)
    if fr.component == 1 and fr.command == 152:         # Authentication.login (Origin)
        # Per-player identity from players.json (lobby.py). The uid must be the id of the save
        # the game loads; the Origin token's account suffix confirms a claimed id is this
        # player's own.
        suffix = ea_identity.token_suffix(_req_fields(fr).get("AUTH"))
        sess.outbox += _lobby(args).login(sess, suffix)
        print(f"  [player] {sess.ip} -> {sess.persona} (uid {sess.uid}, {sess.id_source}, "
              f"{sess.id_check})")
        if sess.id_source == lobby.SYNTHETIC:
            print(f"  [identity] WARNING {sess.ip}: EA save id unknown - this player's progress "
                  f"goes to {sess.uid}.sav, which the game never loads, and the other players' "
                  f"games may show its car as an ordinary racer (name only up close). Connect "
                  f"with the launcher (JOIN A SESSION) or pass --player-id {sess.ip}=<id>")
        return blaze.build_login_response(fr.seq, sess.uid, sess.persona,
                                          msg_type=args.reply_msgtype)
    if fr.component == 9 and fr.command == 8:           # Util.postAuth
        return blaze.build_postauth_response(fr.seq, sess.uid, msg_type=args.reply_msgtype,
                                             subsystems=not args.postauth_minimal)
    # --- Util commands called AFTER postAuth (numbering from the BF3 emulator, the same
    #     engine; NFS uses component 9 for Util). No reply to one of them most likely
    #     kept the game on "Connecting" (the client's RPC never finished).
    if fr.component == 9 and fr.command == 1:           # Util.fetchClientConfig
        return blaze.build_fetch_client_config_response(fr.seq, msg_type=args.reply_msgtype)
    if fr.component == 9 and fr.command == 5:           # Util.getTelemetryServer
        return blaze.build_telemetry_response(fr.seq, msg_type=args.reply_msgtype,
                                              ip=args.redirect_ip)
    if fr.component == 9 and fr.command == 0xB:         # Util.userSettingsSave
        return blaze.build_empty_reply(9, 0xB, fr.seq, msg_type=args.reply_msgtype)
    if fr.component == 9 and fr.command == 0xC:         # Util.userSettingsLoadAll
        return blaze.build_user_settings_load_all_response(fr.seq, msg_type=args.reply_msgtype)
    # --- UserSessions (component 0x7802). The command numbers are NOT guessed:
    #     getCommandName @0xf285b0 has a jump table @0xf2867c (index = cmd - 3),
    #     from which it follows directly: 3=fetchExtendedData, 5=updateExtendedDataAttribute,
    #     8=updateHardwareFlags, 0xC=lookupUser, 0x14=updateNetworkInfo,
    #     0x19=updateUserSessionClientData, 0x1A=setUserInfoAttribute,
    #     0x20=lookupUserSessionId, 0x23=resumeSession.
    #     updateNetworkInfo arrives after the QoS test is closed (it carries
    #     NetworkInfo{ADDR,NLMP,NQOS}) and returns no data - an empty acknowledgement
    #     is enough for the client's RPC to finish.
    if fr.component == 0x7802 and fr.command in (0x14, 0x08, 0x1A):
        if fr.command == 0x14:
            # The player's address for the others (UserAdded, game roster). The first report, still
            # before QoS, has EXIP 0 - we do not store that one.
            addr = _union_ip_pair(_req_fields(fr).get("ADDR"))
            if addr and addr[0]:
                sess.addr = addr
        return blaze.build_empty_reply(fr.component, fr.command, fr.seq,
                                       msg_type=args.reply_msgtype)
    if fr.component == 0x7802 and fr.command == 0xD and not args.no_lookup_users:
        return _lookup_users(fr, args, sess)
    if fr.component == 0x7802 and fr.command == 0x23 and not args.no_resume:
        return _resume_session(fr, args, sess)
    if fr.component == 2050 and fr.command == 21 and not args.no_autolog:
        return _autolog_recommendations(fr, args, sess)
    if fr.component == 2050 and fr.command in (29, 31, 39, 41) and not args.no_autolog:
        return _autolog_other(fr, args, sess)
    # --- post-login RPCs (run-20/21b). Names from emulating getCommandName in the binary,
    #     reply layouts from the TDF field tables - see the builders in blaze.py.
    req = _req_fields(fr)
    mt = args.reply_msgtype
    if fr.component == 9 and fr.command == 10:          # Util.userSettingsLoad
        # Logged: a click on a rival in Autolog's list asks this (02.10, right before the crash),
        # and whose settings it wants is not known yet
        print(f"  [settings] {sess!r} loads " + ", ".join(f"{k}={v!r}" for k, v in req.items()))
        return blaze.build_user_settings_load_response(fr.seq, str(req.get("KEY", "")), msg_type=mt)
    if fr.component == 7 and fr.command == 15:          # Stats.getKeyScopesMap
        return blaze.build_key_scopes_response(fr.seq, msg_type=mt)
    if fr.component == 7 and fr.command == 4:           # Stats.getStatGroup
        return blaze.build_stat_group_response(fr.seq, str(req.get("NAME", "")), msg_type=mt)
    if fr.component == 7 and fr.command == 16:          # Stats.getStatsByGroupAsync
        return blaze.build_empty_reply(7, 16, fr.seq, msg_type=mt)   # the data goes in notification 7/0x32
    if fr.component == 25 and fr.command == 6:          # AssociationLists.getLists
        return blaze.build_get_lists_response(fr.seq, msg_type=mt)
    if fr.component == 2050 and fr.command == 38:       # NFS.getGeolocationInfo
        return blaze.build_geolocation_info_response(fr.seq, int(req.get("BLID", 0) or 0), msg_type=mt)
    if fr.component == 1 and fr.command == 36:          # Authentication.getAuthToken
        return blaze.build_get_auth_token_response(fr.seq, f"TR_AUTH_{sess.uid}", msg_type=mt)
    if fr.component == 1 and fr.command == 29:          # Authentication.listUserEntitlements2
        # BUID = the EA persona id for this game (e.g. 1006431274704) - stored in the session. Entitlements
        # are empty by default (Steam Complete Edition: DLC works locally), so a generic reply.
        if req.get("BUID"):
            sess.persona_id = int(req["BUID"])
        if getattr(args, "entitlements", "none") == "online":
            # A/B 15.09: the joiner leaves someone else's game ~230 ms after these queries (log-30..32).
            # Hypothesis: it waits for an ONLINE_ACCESS entitlement in the game's group. Only NFS14PC - the
            # NFS13PC (loyalty) group could unlock rewards in the career save.
            groups = [str(g) for g in (req.get("GNLS") or []) if str(g) == "NFS14PC"]
            ents = [dict(id=1000 + i, group=g, type=blaze.ENTITLEMENT_TYPE["ONLINE_ACCESS"],
                         tag="ONLINE_ACCESS", persona_id=sess.persona_id,
                         product_id="Origin.OFR.50.0000676", grant_date="2013-11-19T00:00Z")
                    for i, g in enumerate(groups)]
            print(f"  [entitlements] {sess.persona}: {len(ents)} ONLINE_ACCESS entry/entries for {groups}")
            return blaze.build_list_entitlements_response(fr.seq, ents, msg_type=mt)
        return None
    # --- GameManager (run-22: "Searching for a game" = createGame without a reply).
    #     Games and players in the lobby.py registry; notifications (also to other players) are sent by _after_reply.
    if fr.component == 4 and fr.command == 1:           # GameManager.createGame
        lb = _lobby(args)
        sess.addr = _raw_ip_pair(fr.payload)
        lb.learn_persona(sess, _raw_str(fr.payload, "GNAM", ""))
        g = lb.create_game(sess, _create_game_params(fr.payload), getattr(args, "gm_player_state", 4))
        sess.pending = ("created_game", 0, g)
        print(f"  [game] {sess!r} creates game {g.gid:#x} ({'public' if g.public else 'private'})")
        return blaze.build_create_game_response(fr.seq, g.gid, msg_type=mt)
    if fr.component == 4 and fr.command == 25:          # GameManager.resetDedicatedServer
        # run-36/37: a game with a PRIVATE session does not matchmake - instead of startMatchmaking it
        # asks to reset a dedicated server for its own game (ATTR gameMembershipRequirements=
        # 'Private', GSET 276 instead of 287 = without the "open to browsing/matchmaking" bits).
        # The request has the same tags as createGame (ATTR GNAM GSET NTOP PRES VOIP VSTR PCAP TIDS
        # HNET), so we read the parameters with the same code. Without a reply the game sits forever
        # on "Searching for a game" (log-36 and log-37: an empty ack and silence until the game closed).
        lb = _lobby(args)
        sess.addr = _raw_ip_pair(fr.payload)
        lb.learn_persona(sess, _raw_str(fr.payload, "GNAM", ""))
        g = lb.create_game(sess, _create_game_params(fr.payload),
                           getattr(args, "gm_player_state", 4))
        sess.pending = ("reset_dedicated", 0, g)
        print(f"  [game] {sess!r} resets the dedicated server -> game {g.gid:#x} "
              f"({'public' if g.public else 'private'})")
        return blaze.build_reset_dedicated_server_response(fr.seq, g.gid, msg_type=mt)
    if fr.component == 4 and fr.command == 13:          # GameManager.startMatchmaking
        # run-26: "find a session" = leaveGameByGroup + startMatchmaking (MODE 3 = find or create);
        # the matchmaking result arrives as a notification. First we look for another player's public
        # game (joining, SUCCESS_JOINED_EXISTING_GAME), and when there is none - a new game with the
        # player as host (SUCCESS_CREATED_GAME). --mm-fail: NotifyMatchmakingFailed SESSION_TIMED_OUT (A/B).
        # We read the address and nickname HERE, in the connection thread: sess.addr later goes into the
        # roster, and the nickname from GNAM has to be known before anyone sees this player. The decision
        # itself (which game) goes on a timer - see _resolve_matchmaking and --mm-delay.
        lb = _lobby(args)
        msid = lb.new_msid()
        pnet = _union_ip_pair(req.get("PNET"))
        if pnet and pnet[0]:
            sess.addr = pnet
        lb.learn_persona(sess, str(req.get("GNAM", "")))
        delay = int(getattr(args, "mm_delay", 0) or 0)
        dur = int(req.get("DUR", 0) or 0)
        if dur > 0:
            delay = min(delay, dur)
        if delay > 0:
            _arm_matchmaking(lb, args, sess, msid, req, delay)
            print(f"  [matchmaking] session {msid}, MODE={req.get('MODE')} DUR={dur} ms -> "
                  f"deciding in {delay} ms")
        else:                                           # --mm-delay 0: as up to and including run-38
            sess.outbox.extend(_resolve_matchmaking(lb, args, sess, msid, req))
        return blaze.build_start_matchmaking_response(fr.seq, msid, msg_type=mt)
    if fr.component == 4 and fr.command == 14:          # GameManager.cancelMatchmaking
        # run-38: sent when giving up the search, and it ended up as "no handler". With a deferred
        # decision the timer has to be killed, otherwise the player would get a game they just gave up on.
        _cancel_matchmaking(sess)
        print(f"  [matchmaking] {sess!r} cancels the search")
        return blaze.build_empty_reply(4, fr.command, fr.seq, msg_type=mt)
    if fr.component == 4 and fr.command == 24:          # GameManager.updateGameHostMigrationStatus
        # The new host reports on its migration. Nobody has seen this RPC from NFS Rivals yet, so
        # print every field - the first live migration shows what the client actually sends.
        print(f"  [migration] {sess!r} reports status: {req}")
        return blaze.build_empty_reply(4, fr.command, fr.seq, msg_type=mt)
    if fr.component == 4 and fr.command in (2, 3, 11, 15, 22, 29, 106, 107):
        # destroyGame, advanceGameState, removePlayer, finalizeGameCreation, leaveGameByGroup,
        # updateMeshConnection, addAdminPlayer, removeAdminPlayer - just an acknowledgement; the effects
        # (notifications) are sent by _after_reply
        return blaze.build_empty_reply(4, fr.command, fr.seq, msg_type=mt)
    if fr.component == 2050 and fr.command == 20 and not getattr(args, "no_speed_walls", False):
        return _speed_walls(fr, args, sess)
    if fr.component == 9 and fr.command == 20:          # Util.filterForProfanity
        # run-23: TLST [{DIRT 2, UTXT ''}] - the empty acknowledgement returned an EMPTY list, so
        # the game got zero results for one text. We send every text back unchanged.
        texts = []
        for item in req.get("TLST") or []:
            vals = {t.strip(): v for t, _w, v in item} if isinstance(item, list) else {}
            texts.append(str(vals.get("UTXT", "")))
        return blaze.build_filter_profanity_response(fr.seq, texts, msg_type=mt)
    return None


GAME_REPORTING = 28
_REPORTS = {"n": 0}


def _ack_game_report(sess, fr, args) -> None:
    """GameReporting (component 28): game state reports. In run-23 there were 429 of them in about
    2 min of driving (Collectables, DistanceDriven*, CarCustomization, LicensesPart1/2 ...) and they
    took up 95% of the log. Request class @0x141a32ad0 {FNSH mFinishedStatus, PRVT mPrivateReport,
    RPRT mGameReport}; the report sits in a variable-type field, which our decoder does not unpack.
    We answer with an empty acknowledgement, as in run-23 (the game accepts it). The full frame is
    in the capture (blaze-<tag>-NN.bin), so the log keeps one line with the names from the report."""
    import re
    _REPORTS["n"] += 1
    sess.send(blaze.build_empty_reply(fr.component, fr.command, fr.seq,
                                      msg_type=args.reply_msgtype))
    # Progress saving (player_store.py). A parse/save error must not stop the game - the ack
    # went out above, here we only log.
    store = _player_store(args)
    try:
        rep = player_store.parse_game_report(fr.payload)
        stats = sum(len(p[k]) for p in rep["players"].values() for k in ("int", "float", "str"))
        entity = next(iter(rep["players"].values()))["entity"] if rep["players"] else "-"
        desc = f"{rep['category']} ENTI={entity} ({stats} stat.)"
        saved = ""
        if store is not None:
            store.record(rep)
            saved = " [saved]"
    except Exception as e:                              # noqa: BLE001
        words = [m.decode() for m in re.findall(rb"[A-Za-z][A-Za-z0-9_]{5,}", fr.payload)]
        desc, saved = " ".join(words[:4]), f" [NOT SAVED: {e!r}]"
    print(f"  <- GameReporting 28/{fr.command} #{_REPORTS['n']} seq={fr.seq} "
          f"({len(fr.payload)} B): {desc} -> ack{saved}")


_STORE_LOCK = threading.Lock()
_STORE: dict = {}


def _player_store(args):
    """Shared PlayerStore for all connections; None with --no-store."""
    if getattr(args, "no_store", False):
        return None
    root = getattr(args, "data_dir", None) or player_store.DATA_DIR
    with _STORE_LOCK:
        if root not in _STORE:
            _STORE[root] = player_store.PlayerStore(root)
        return _STORE[root]


DEFAULT_GAME_NAME = "Player"         # when the request carries no GNAM (game name = the creator's nickname)
_LOBBY: dict = {}


def _data_root(args) -> Path:
    """Where players.json, the saved progress and the players' pictures live."""
    return Path(getattr(args, "data_dir", None) or player_store.DATA_DIR)


def _lobby(args) -> lobby.Lobby:
    """Shared registry of players and games (one per process). players.json sits next to the saved progress."""
    with _STORE_LOCK:
        if "lobby" not in _LOBBY:
            root = _data_root(args)
            forced = dict(p.split("=", 1) for p in (getattr(args, "player", None) or []) if "=" in p)
            player_ids = {ip: int(uid) for ip, uid in (
                p.split("=", 1) for p in (getattr(args, "player_id", None) or []) if "=" in p)}
            local_id, source = getattr(args, "local_id", 0), "--local-id"
            if not local_id:
                # The save this machine's game loads, found through its EA App (ea_identity.py)
                found = ea_identity.resolve()
                local_id = found["id"] or 0
                source = f"local-auto, {found['source']}" if local_id else "local-auto"
                print(f"[identity] local player: EA App user {found['user'] or '-'}, saves "
                      f"{', '.join(map(str, found['saves'])) or '-'} -> uid "
                      f"{local_id or 'unknown, keeping the stored one'}"
                      f"{' (' + found['source'] + ')' if local_id else ''}")
            _LOBBY["lobby"] = lobby.Lobby(
                root / "players.json", forced,
                player_state_notify=getattr(args, "player_state_notify", True),
                local_id=local_id, local_id_source=source, player_ids=player_ids,
                local_persona=getattr(args, "local_persona", ""),
                host_migration=getattr(args, "host_migration", True),
                migration_player_removed=getattr(args, "migration_player_removed", True),
                migration_type=getattr(args, "migration_type", 2),
                platform_host_init=getattr(args, "platform_host_init", True),
                admin_tracking=getattr(args, "admin_tracking", True),
                join_migrated=getattr(args, "join_migrated", False))
        return _LOBBY["lobby"]


_MIGRATION_TIMERS: dict[int, threading.Timer] = {}


def _arm_migrations(lb, args) -> None:
    """Logs every host migration that started since the last call and arms its safety timer: if
    the new host never reports updateGameHostMigrationStatus, the timer finishes the migration
    anyway and says so, instead of leaving the game stuck in MIGRATING. Called after anything
    that can remove a player - a game RPC in _after_reply and a disconnect in the session loop."""
    timeout = float(getattr(args, "migration_timeout", 10.0) or 0)
    for gid in lb.take_migrations_started():
        g = lb.game(gid)
        if g is None:
            continue
        print(f"  [migration] game {gid:#x}: host {lb.persona_of(g.migrating_from)} left -> "
              f"new host {lb.persona_of(g.host_uid)} (slot {g.players[g.host_uid]['slot']})")
        old = _MIGRATION_TIMERS.pop(gid, None)
        if old is not None:
            old.cancel()
        if timeout <= 0:
            continue

        def fire(gid=gid):
            _MIGRATION_TIMERS.pop(gid, None)
            notes = lb.finish_migration(gid)
            if notes:
                print(f"  [migration] game {gid:#x}: no status from the new host after "
                      f"{timeout:g} s - finishing anyway (timeout)")
                _deliver(None, notes)

        t = threading.Timer(timeout, fire)
        t.daemon = True
        _MIGRATION_TIMERS[gid] = t
        t.start()


def _migration_status(lb, gid: int, migration_type: int, who) -> list:
    """Feeds one status report of the new host into the lobby; when it completes the migration,
    cancels the safety timer."""
    notes, finished = lb.migration_status(gid, migration_type)
    if finished:
        t = _MIGRATION_TIMERS.pop(gid, None)
        if t is not None:
            t.cancel()
        print(f"  [migration] game {gid:#x}: finished (status from {who!r})")
    elif notes:
        print(f"  [migration] game {gid:#x}: platform host initialized (MTYP {migration_type}), "
              f"waiting for the rest")
    return notes


def _public_ip(args) -> str:
    """This computer's address as seen from another computer on the network: --public-ip or the detected LAN one."""
    ip = getattr(args, "public_ip", None)
    if not ip:
        ip = _detect_lan_ip()
        args.public_ip = ip
    return ip


def _detect_lan_ip() -> str:
    """The main IPv4 address on the local network. connect() on a UDP socket sends no packet - the
    system only picks the interface with the default route and its address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _client_facing_ip(sess, args) -> str:
    """The server address for this client: 127.0.0.1 for the local player, the network address for another computer."""
    if sess is None or sess.is_local:
        return args.redirect_ip
    return _public_ip(args)


def _req_fields(fr) -> dict:
    """Top-level fields of the client request: tag (without spaces) -> value."""
    if not fr.payload:
        return {}
    try:
        return {tag.strip(): val for tag, _wtype, val in blaze.decode_tdf(fr.payload)}
    except Exception:                                   # noqa: BLE001
        return {}


# --- Reading single fields from the RAW request. Our decoder does not unpack the whole
#     createGame (a list of HNET unions, variable types), and we only need a few values.
#     We look for the "tag + type" bytes - for these fields in createGame the hits are unambiguous.
def _enc_tag(tag: str) -> bytes:
    v = 0
    for ch in tag.ljust(4)[:4]:
        v = (v << 6) | ((ord(ch) - 0x20) & 0x3F)
    return v.to_bytes(3, "big")


def _dec_varint(b: bytes, p: int) -> tuple[int, int]:
    v = b[p] & 0x3F
    neg = b[p] & 0x40
    shift = 6
    while b[p] & 0x80:
        p += 1
        v |= (b[p] & 0x7F) << shift
        shift += 7
    return (-v if neg else v), p + 1


def _raw_int(payload: bytes, tag: str, default: int = 0) -> int:
    i = payload.find(_enc_tag(tag) + b"\x00")
    return _dec_varint(payload, i + 4)[0] if i >= 0 else default


def _raw_str(payload: bytes, tag: str, default: str = "") -> str:
    i = payload.find(_enc_tag(tag) + b"\x01")
    if i < 0:
        return default
    n, p = _dec_varint(payload, i + 4)
    return payload[p:p + n].rstrip(b"\x00").decode("latin1")


def _raw_list_int(payload: bytes, tag: str, default: list[int]) -> list[int]:
    i = payload.find(_enc_tag(tag) + b"\x04\x00")
    if i < 0:
        return default
    n, p = _dec_varint(payload, i + 5)
    out = []
    for _ in range(n):
        v, p = _dec_varint(payload, p)
        out.append(v)
    return out


def _raw_map_str(payload: bytes, tag: str) -> dict[str, str]:
    i = payload.find(_enc_tag(tag) + b"\x05\x01\x01")
    if i < 0:
        return {}
    n, p = _dec_varint(payload, i + 6)
    out = {}
    for _ in range(n):
        kl, p = _dec_varint(payload, p)
        k = payload[p:p + kl].rstrip(b"\x00").decode("latin1")
        p += kl
        vl, p = _dec_varint(payload, p)
        out[k] = payload[p:p + vl].rstrip(b"\x00").decode("latin1")
        p += vl
    return out


def _union_ip_pair(u) -> tuple[int, int, int, int, int] | None:
    """(exip, export, inip, inport, maci) from a decoded NetworkAddress union, variant 2 (IpPair
    {EXIP{IP MACI PORT} INIP{..} MACI}): PNET in startMatchmaking, ADDR in updateNetworkInfo.
    None when the layout is different."""
    try:
        _union, _variant, (_tag, _wtype, fields) = u
        f = {t.strip(): v for t, _w, v in fields}
        ex = {t.strip(): v for t, _w, v in f["EXIP"]}
        inn = {t.strip(): v for t, _w, v in f["INIP"]}
        return ex["IP"], ex["PORT"], inn["IP"], inn["PORT"], f.get("MACI", 0)
    except (KeyError, TypeError, ValueError):
        return None


def _objid_uid(v) -> int:
    """uid from an ObjectId (0x7802, 2, uid) - SCG/TCG in updateMeshConnection."""
    return int(v[2]) if isinstance(v, tuple) and len(v) == 3 else 0


def _create_game_params(p: bytes) -> dict:
    """Game parameters from the RAW createGame request (our decoder does not unpack HNET)."""
    cap = _raw_list_int(p, "PCAP", [6, 0, 0, 0])
    # resetDedicatedServer sends PMAX=0, and the capacity only in PCAP ([6,0,0,0]) - when PMAX
    # is zero, we take the sum of the slots, otherwise the game gets MCAP=0 and has nowhere to go.
    return dict(game_name=_raw_str(p, "GNAM", DEFAULT_GAME_NAME), game_settings=_raw_int(p, "GSET", 0),
                network_topology=_raw_int(p, "NTOP", 0), presence_mode=_raw_int(p, "PRES", 1),
                voip=_raw_int(p, "VOIP", 0), version_string=_raw_str(p, "VSTR", ""),
                max_players=_raw_int(p, "PMAX", 0) or sum(cap) or 6,
                slot_capacities=cap,
                team_ids=_raw_list_int(p, "TIDS", [65535]), attributes=_raw_map_str(p, "ATTR"))


def _mm_game_params(req: dict) -> dict:
    """Parameters of a game created by matchmaking - from the decoded startMatchmaking request."""
    pmax = int(req.get("PMAX", 6))
    attrs = {str(k): str(v) for k, v in (req.get("ATTR") or {}).items()}
    # The membership rule from the criteria (RLST: gameMembershipRule = ['Public']) stored as a game
    # attribute under the name from createGame (gameMembershipRequirements) - that is how a second
    # player searching for a public game finds it (Lobby.find_public_game). Attribute name taken from createGame.
    crit = {t.strip(): v for t, _w, v in (req.get("CRIT") or [])}
    for rule in crit.get("RLST") or []:
        rf = {t.strip(): v for t, _w, v in rule}
        if rf.get("NAME") == "gameMembershipRule" and rf.get("VALU"):
            attrs.setdefault("gameMembershipRequirements", str(rf["VALU"][0]))
    return dict(game_name=str(req.get("GNAM", DEFAULT_GAME_NAME)), game_settings=int(req.get("GSET", 0)),
                network_topology=int(req.get("NTOP", 0)), presence_mode=int(req.get("PRES", 1)),
                voip=int(req.get("VOIP", 0)), version_string=str(req.get("GVER", "")),
                max_players=pmax, slot_capacities=[pmax, 0, 0, 0],
                team_ids=[int(req.get("TID", 65535))], attributes=attrs)


def _game_setup(lb, g, setup_context) -> bytes:
    """NotifyGameSetup for a game from the registry: roster of all players, host address, current game state."""
    roster = lb.roster(g)
    host = next((p for p in roster if p["uid"] == g.host_uid), None)
    host_addr = host["addr"] if host else lobby.DEFAULT_ADDR
    return blaze.build_notify_game_setup(g.gid, g.host_uid, roster, host_addr=host_addr,
                                         game_state=g.state, setup_context=setup_context,
                                         host_slot=host["slot"] if host else 0,
                                         creator_id=g.creator_uid,
                                         admins=g.admins if lb.admin_tracking else None,
                                         **g.params)


def _resolve_matchmaking(lb, args, sess, msid, req) -> list:
    """The matchmaking decision together with its notifications, as a list of (session, frame).

    First we look for another player's public game (SUCCESS_JOINED_EXISTING_GAME), and when there is
    none - a new game with the player as host (SUCCESS_CREATED_GAME). --mm-fail: NotifyMatchmakingFailed.

    Up to run-38 the decision was made synchronously, at the moment of the request - and that is what
    broke it. When a player leaves the garage for the world, the client sends startMatchmaking, and
    removePlayer for the old game only one FRAME later (log-38: seq=95 and seq=96). So the player was
    still a member of that game, find_public_game skipped it because of `sess.uid not in g.players`
    and the server created a new game instead of letting them back in. The real Blaze delivers the
    result as a notification after the DUR from the request, so it already sees the completed
    departure - hence the deferral (--mm-delay)."""
    if getattr(args, "mm_fail", False):
        print(f"  [matchmaking] session {msid} -> NotifyMatchmakingFailed SESSION_TIMED_OUT (--mm-fail)")
        return [(sess, blaze.build_notify_matchmaking_failed(
            msid, sess.uid, blaze.MATCHMAKING_RESULT["SESSION_TIMED_OUT"]))]
    crit = {t.strip(): v for t, _w, v in (req.get("CRIT") or [])}
    agam = {t.strip(): v for t, _w, v in (crit.get("AGAM") or [])}
    # One decision under one lock, frames included: two decisions firing together (each on its own
    # timer thread) could otherwise both see the last free slot and both take it - three players in
    # a two-slot game (RivalsNET's two-thread fixture, tests/test_matchmaking.py). The lock is
    # re-entrant, so the lobby calls below take it again freely; sending happens in _deliver, after
    # it is released.
    avoid = {int(x) for x in (agam.get("GIDL") or [])}
    strict = getattr(args, "strict_avoid", False)
    with lb.lock:
        g = lb.find_public_game(sess, avoid, strict=strict)
        if avoid:
            listed = ", ".join(f"{x:#x}" for x in sorted(avoid))
            left = [(x, lb.left_ago(sess.uid, x)) for x in sorted(avoid)]
            left = [(x, ago) for x, ago in left if ago is not None]
            if g is not None and g.gid in avoid:
                why = " - it is the only one, joining it anyway (--strict-avoid would not)"
            elif g is None and left:
                why = (f", which it left {left[0][1]:.0f} s ago - a new game (an immediate "
                       f"rejoin fails: the host's game is still closing the old connection)")
            else:
                why = ""
            print(f"  [matchmaking] session {msid}: the game asks to avoid {listed}{why}")
        if g is None:
            skipped = lb.migrated_games_skipped(sess)
            g = lb.create_game(sess, _mm_game_params(req), getattr(args, "gm_player_state", 4))
            print(f"  [matchmaking] session {msid}, MODE={req.get('MODE')} DUR={req.get('DUR')} ms -> "
                  f"new game {g.gid:#x} (SUCCESS_CREATED_GAME)")
            if skipped:
                print(f"  [matchmaking] skipped game(s) after a host migration: "
                      f"{', '.join(f'{x:#x}' for x in skipped)} - a player joining one never gets game "
                      f"traffic from the migrated host (test 62). Players in it rejoin with 'Search session'.")
            return [(sess, _game_setup(lb, g, (msid, blaze.MATCHMAKING_RESULT["SUCCESS_CREATED_GAME"],
                                               sess.uid)))]
        lb.join(sess, g)
        print(f"  [matchmaking] session {msid}: {sess!r} JOINS game {g.gid:#x} hosted by "
              f"{lb.persona_of(g.host_uid)} (players: {len(g.players)})")
        # The joiner has to know the other players (UserAdded with their addresses) before it gets the
        # game with the roster; players already in the game get the joiner's UserAdded and NotifyPlayerJoining.
        others = lb.members(g, exclude=sess.uid)
        out = [(sess, blaze.build_useradded_notify(o.uid, o.persona, component=args.notify_comp,
                                                   command=2, addr=o.addr)) for o in others]
        out.append((sess, _game_setup(
            lb, g, (msid, blaze.MATCHMAKING_RESULT["SUCCESS_JOINED_EXISTING_GAME"], sess.uid))))
        joiner = next(p for p in lb.roster(g) if p["uid"] == sess.uid)
        for o in others:
            out.append((o, blaze.build_useradded_notify(sess.uid, sess.persona,
                                                        component=args.notify_comp,
                                                        command=2, addr=sess.addr)))
            out.append((o, blaze.build_notify_player_joining(g.gid, joiner)))
        return out


def _cancel_matchmaking(sess) -> None:
    """Kills the deferred decision, if one is pending (cancelMatchmaking, another search, disconnect)."""
    t = sess.mm_timer
    if t is not None:
        t.cancel()
        sess.mm_timer = None


def _arm_matchmaking(lb, args, sess, msid, req, delay_ms: int) -> None:
    """Arms the matchmaking decision timer. Sending from the timer thread is safe: Session.notify has
    its own lock and sequence, and _deliver swallows OSError from a closed connection."""
    _cancel_matchmaking(sess)

    def fire():
        if not sess.alive:
            print(f"  [matchmaking] session {msid}: connection closed, not sending the decision")
            return
        try:
            _deliver(sess, _resolve_matchmaking(lb, args, sess, msid, req))
        except Exception as e:      # timer thread: an unhandled exception would die silently
            print(f"  [matchmaking] session {msid}: decision failed: {e!r}")

    sess.mm_timer = threading.Timer(delay_ms / 1000.0, fire)
    sess.mm_timer.daemon = True
    sess.mm_timer.start()


def _raw_ip_pair(payload: bytes) -> tuple[int, int, int, int, int]:
    """(exip, export, inip, inport, maci) from the HNET of a createGame request; local by default."""
    def sub(tag):
        i = payload.find(_enc_tag(tag) + b"\x03")
        if i < 0:
            return 0x7F000001, 3659
        part = payload[i + 4:i + 40]
        return _raw_int(part, "IP", 0x7F000001), _raw_int(part, "PORT", 3659)
    exip, export = sub("EXIP")
    inip, inport = sub("INIP")
    j = payload.find(_enc_tag("INIP") + b"\x03")
    maci = _raw_int(payload[j + 4:], "MACI", 0) if j >= 0 else 0
    # MACI inside INIP is 0, the pair's real MACI comes after the INIP struct - take the last hit
    k = payload.rfind(_enc_tag("MACI") + b"\x00")
    if k >= 0:
        maci = _dec_varint(payload, k + 4)[0]
    return exip, export, inip, inport, maci


BYTEVAULT_RECORD_RE = re.compile(
    r"^/1\.0/contexts/([^/?]+)/categories/([^/?]+)/records/([^/?]+)")
PICTURES_CATEGORY = "Pictures"
_SAFE_PART_RE = re.compile(r"[^A-Za-z0-9_.-]")


def _sniff(data: bytes) -> str:
    """What a blob looks like, by its first bytes - for the log."""
    for magic, name in ((b"\xff\xd8\xff", "JPEG"), (PNG_MAGIC, "PNG"), (b"DDS ", "DDS"),
                        (b"{", "JSON"), (b"[", "JSON")):
        if data.startswith(magic):
            return name
    return "unknown"


def _bytevault_file(args, ctx: str, cat: str, name: str) -> Path:
    """Where a record the game wrote is kept. The parts come off the network, so anything but
    [A-Za-z0-9_.-] is replaced - no way out of the folder."""
    ctx, cat, name = (_SAFE_PART_RE.sub("_", p).lstrip(".") or "_" for p in (ctx, cat, name))
    return _data_root(args) / "bytevault" / ctx / cat / f"{name}.body"


def _bytevault_record(method: str, path: str, body: bytes, args,
                      headers: dict) -> tuple[str, str, bytes] | None:
    """A single record (.../categories/<cat>/records/<name>), or None for anything else.

    Profile pictures: the game asks for GET .../categories/Pictures/records/<uid> for every
    player it shows (log-29/log-32, 15.09), and it had always got "{}". What it expects back is
    NOT known yet (the JSON keys are not in the binary; the record classes are Record {DELT INFO
    LOAD} @0x141a2c8e0 and payload {DATA blob, MIME} @0x1416b50c0, and the game links libjpeg).
    Settled on 30.09 (1.0.6): the bare JPEG bytes with Content-Type image/jpeg.
      - every WRITE the game makes is kept as is (<data_dir>/bytevault/...) and logged in full -
        setting a profile picture in the game shows the exact upload format;
      - a GET gets the launcher's picture (avatars/<uid>.jpg) in the --bytevault-pictures shape:
        raw JPEG, a JSON guess, or off. Until 1.0.9 it got what the game itself had written there
        first - an unknown format, now only kept.
    Every Pictures answer is logged: one GET per player = accepted, a loop = rejected."""
    m = BYTEVAULT_RECORD_RE.match(path)
    if not m:
        return None
    ctx, cat, name = (urllib.parse.unquote(p) for p in m.groups())
    stored = _bytevault_file(args, ctx, cat, name)
    if method in ("PUT", "POST", "PATCH"):
        kind = _sniff(body)
        print(f"  [bytevault] WRITE {cat}/{name} ({ctx}): {len(body)} B, looks like {kind}, "
              f"Content-Type {headers.get('content-type', '-')}")
        print(hexdump(body, 512))
        try:
            stored.parent.mkdir(parents=True, exist_ok=True)
            stored.write_bytes(body)
            stored.with_suffix(".meta.json").write_text(json.dumps(
                {"method": method, "path": path, "headers": headers, "size": len(body),
                 "kind": kind}, indent=1), encoding="utf-8")
            print(f"  [bytevault] kept in {stored}")
        except OSError as e:
            print(f"  [bytevault] could not keep it: {e}")
        return None                          # the reply itself stays as before
    if method != "GET" or cat != PICTURES_CATEGORY:
        return None
    # What the game itself wrote stays on disk for research, but is not served back: its format
    # is unknown, and the launcher's raw JPEG is the one the game is known to take (1.0.6).
    mode = getattr(args, "bytevault_pictures", "raw")
    jpg = _avatar_path(args, int(name)).with_suffix(".jpg") if name.isdigit() else None
    if mode == "off" or jpg is None or not jpg.exists():
        print(f"  [bytevault] Pictures/{name} -> none ({'off' if mode == 'off' else 'no picture'})")
        return None
    data = jpg.read_bytes()
    if mode == "json":
        doc = {"info": {"recordName": name, "context": ctx, "categoryName": cat},
               "payload": {"contentType": "image/jpeg",
                           "blob": base64.b64encode(data).decode("ascii")}}
        out = json.dumps(doc).encode()
        print(f"  [bytevault] Pictures/{name} -> launcher picture as JSON ({len(out)} B)")
        return "200 OK", "application/json", out
    records = -(-len(data) // MAX_FRAGMENT)
    print(f"  [bytevault] Pictures/{name} -> launcher picture, raw JPEG ({len(data)} B, "
          f"{records} TLS record(s))"
          + (" - sent by a launcher before 1.0.10, a new pick makes it smaller"
             if len(data) > GAME_PICTURE_MAX else ""))
    return "200 OK", "image/jpeg", data


def _bytevault_reply(method: str, path: str, body: bytes, args,
                     headers: dict | None = None) -> tuple[str, str, bytes]:
    """ByteVault (REST) reply. Record list layout: candidate {LIST mRecords, TOTL
    mTotalCount} (@0x1416b6748). The JSON keys are NOT stored in the binary - we assume the field
    names without the m prefix; --bytevault-format heat sends the same TDF in binary. Single
    records (profile pictures) go through _bytevault_record first."""
    record = _bytevault_record(method, path, body, args, headers or {})
    if record is not None:
        return record
    fmt = getattr(args, "bytevault_format", "json")
    listing = "/recordinfo" in path or path.split("?")[0].rstrip("/").endswith("/records")
    if fmt == "heat":
        payload = blaze.encode_tdf([blaze.f_list_struct("LIST", []), blaze.f_int("TOTL", 0)]) \
            if listing else b""
        return "200 OK", "application/heat", payload
    return "200 OK", "application/json", (b'{"records":[],"totalCount":0}' if listing else b"{}")


def _redact_header(line: str) -> str:
    """An HTTP header line for the log, with credentials cut. ByteVault's Authorization can be
    the player's real EA access token (01.10: "AT0:3.0:...:sesdm", X-TOKEN-TYPE NUCLEUS_AUTH_TOKEN),
    not only our own TR_AUTH_<uid> - and since 1.0.9 the log is a file players send around."""
    name, sep, value = line.partition(":")
    key = name.strip().lower()
    secret = (key in ("authorization", "cookie", "set-cookie") or key.startswith("x-auth")
              or ("token" in key and key != "x-token-type"))
    value = value.strip()
    if not sep or not secret or not value:
        return line
    return f"{name}: {value[:6]}... (redacted, {len(value)} chars)"


def _serve_http(w, buf: bytearray, args) -> None:
    """HTTP session over TLS on the Blaze port - that is how ByteVault connects (run-22: GET
    /1.0/contexts/nfs-rivals-common/categories/Unlocks/recordinfo?...). Handles successive
    requests on the same connection (keep-alive) until the client closes it."""
    while True:
        while b"\r\n\r\n" not in buf:
            rtype, _ver, rec = w.recv_record()
            if rtype != RT_APPDATA:
                return
            buf += rec
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        lines = head.decode("latin1").split("\r\n")
        parts = (lines[0].split(" ") + ["", "", ""])[:3]
        method, path = parts[0], parts[1]
        headers = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
        clen = int(headers.get("content-length", "0") or 0)
        rest = bytearray(rest)
        while len(rest) < clen:
            rtype, _ver, rec = w.recv_record()
            if rtype != RT_APPDATA:
                return
            rest += rec
        body, buf = bytes(rest[:clen]), bytearray(rest[clen:])
        print(f"  [HTTP] {method} {path}")
        for ln in lines[1:]:
            print(f"      {_redact_header(ln)}")
        if body:
            print(f"      BODY ({len(body)} B): {body[:300]!r}")
        status, ctype, payload = _bytevault_reply(method, path, body, args, headers)
        resp = (f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n"
                f"Content-Length: {len(payload)}\r\n\r\n").encode() + payload
        w.send_record(RT_APPDATA, resp)
        print(f"  -> HTTP {status} {ctype} ({len(payload)} B) {payload[:120]!r}")
        if headers.get("connection", "").lower() == "close":
            # ByteVault sends "Connection: Close" and closes the socket after the reply; waiting
            # further for a record ended in a bogus "session error" in the log (run-23).
            return


def _after_reply(fr, args, sess):
    """Async notifications sent AFTER the reply: a list of (session, frame). Usually to the same
    player, and in multiplayer also to the game's other players (join, leave, mesh). The msgId is
    assigned by Session.notify - every session has its own increasing sequence."""
    lb = _lobby(args)
    out = list(sess.outbox)
    sess.outbox.clear()

    def me(frame):
        out.append((sess, frame))

    resumed = fr.component == 0x7802 and fr.command == 0x23 and sess.resumed
    if (fr.component == 1 and fr.command == 152) or resumed:   # after login / a resumed session
        sess.resumed = False
        if args.notify_probe:
            for cmd in range(1, 11):
                me(blaze.build_usersession_update(sess.uid, component=args.notify_comp, command=cmd))
        else:
            # Order as in Blaze after login: UserAdded (cmd 2, creates the user),
            # ExtendedDataUpdate (cmd 1, session data), UserAuthenticated (cmd 8,
            # the "logged in" signal -> triggers postAuth).
            rich = not args.plain_session_data
            # USER in UserAdded = UserIdentification (ID = BlazeId). The old layout with
            # UserSessionLoginInfo tags gave a user with ID=0 -> the game never got onAuthenticated.
            me(blaze.build_useradded_notify(sess.uid, sess.persona, component=args.notify_comp,
                                            command=2, rich_data=rich,
                                            legacy_user=getattr(args, "legacy_user_added", False)))
            me(blaze.build_usersession_update(sess.uid, component=args.notify_comp, command=1,
                                              rich_data=rich))
            # UserAuthenticated with the full UserSessionLoginInfo (class from the binary
            # @0x141a2f160). An empty payload gave BUID=0 and the game's online state never reached
            # 9 ("Logging in"). --empty-user-auth restores the old empty variant (A/B).
            if args.empty_user_auth:
                me(blaze.build_notification(args.notify_comp, 8, b""))
            else:
                me(blaze.build_user_authenticated_notify(sess.uid, sess.persona,
                                                         component=args.notify_comp, command=8))
    if fr.component == 7 and fr.command == 16:          # Stats.getStatsByGroupAsync
        # The result of an asynchronous query arrives as notification 7/0x32 with the same VID;
        # LAST=1 closes the view. Without it the game waits for the stats forever.
        req = _req_fields(fr)
        eids = req.get("EID") or []
        if not isinstance(eids, list):
            eids = [eids]
        me(blaze.build_stats_async_notification(
            int(req.get("VID", 0) or 0), str(req.get("NAME", "")),
            [int(e) for e in eids if isinstance(e, int)]))
    if fr.component == 4 and fr.command in (1, 25) and sess.pending:
        # createGame / resetDedicatedServer: the game was created by dispatch. Matchmaking (cmd 13)
        # does not come here - its decision goes through _resolve_matchmaking (straight into the
        # outbox with --mm-delay 0, otherwise from the timer thread).
        kind, _msid, g = sess.pending
        sess.pending = None
        if kind == "created_game":                     # DatalessSetupContext
            me(_game_setup(lb, g, None))
        elif kind == "reset_dedicated":                # ResetDedicatedServerSetupContext
            me(_game_setup(lb, g, "reset_dedicated"))
    if fr.component == 4 and fr.command == 3:           # GameManager.advanceGameState
        req = _req_fields(fr)
        gid = int(req.get("GID", 0) or 0)
        state = int(req.get("GSTA", blaze.GAME_STATE["PRE_GAME"]))
        g = lb.set_state(gid, state)
        note = blaze.build_notify_game_state_change(gid, state)
        targets = lb.members(g) if g is not None else []
        if sess not in targets:
            targets.append(sess)
        out += [(t, note) for t in targets]
    if fr.component == 4 and fr.command == 29:          # GameManager.updateMeshConnection
        req = _req_fields(fr)
        gid = int(req.get("GID", 0) or 0)
        src, tgt = _objid_uid(req.get("SCG")), _objid_uid(req.get("TCG"))
        stat = int(req.get("STAT", 0) or 0)
        if src != tgt:
            print(f"  [mesh] game {gid:#x}: {lb.persona_of(src)} -> {lb.persona_of(tgt)} STAT={stat}")
        out += lb.mesh(gid, src, tgt, stat)
    if fr.component == 4 and fr.command in (106, 107):  # addAdminPlayer, removeAdminPlayer
        # Blaze broadcasts an admin list change to all players of the game. log-30: the host added the
        # guest as admin 13 ms after the mesh connection (4/106 {GID, PID}), and we only sent back the ack.
        req = _req_fields(fr)
        g = lb.game(int(req.get("GID", 0) or 0))
        pid = int(req.get("PID", 0) or 0)
        if g is not None and pid:
            added = fr.command == 106
            lb.set_admin(g, pid, added)
            op = blaze.GM_ADMIN_OPERATION["GM_ADMIN_ADDED" if added else "GM_ADMIN_REMOVED"]
            note = blaze.build_notify_admin_list_change(g.gid, pid, op, sess.uid)
            print(f"  [game] {lb.persona_of(sess.uid)} {'adds' if added else 'removes'} admin "
                  f"{lb.persona_of(pid)} in game {g.gid:#x}")
            out += [(t, note) for t in lb.members(g)]
    if fr.component == 4 and fr.command in (2, 11, 22):  # destroyGame, removePlayer, leaveGameByGroup
        req = _req_fields(fr)
        g = lb.game(int(req.get("GID", 0) or 0))
        if g is not None:
            if fr.command == 2:
                uid, reason = sess.uid, blaze.PLAYER_REMOVED_REASON["PLAYER_LEFT"]
            else:
                uid = int(req.get("PID", 0) or sess.uid)
                reason = int(req.get("REAS", blaze.PLAYER_REMOVED_REASON["PLAYER_LEFT"]))
            notes = lb.remove_player(g, uid, reason)
            print(f"  [game] {lb.persona_of(uid)} leaves game {g.gid:#x} (REAS {reason}), "
                  f"notifications for others: {len(notes)}")
            out += notes
    if fr.component == 4 and fr.command == 24:          # updateGameHostMigrationStatus
        req = _req_fields(fr)
        g = lb.game(int(req.get("GID", 0) or 0))
        if g is not None and g.migrating_from and sess.uid == g.host_uid:
            out += _migration_status(lb, g.gid, int(req.get("MTYP", 0) or 0), sess)
    # Any path above can start a host migration (removePlayer, leaveGameByGroup, destroyGame, and a
    # re-login that drops the player's old session) - arm the safety timers in one place.
    _arm_migrations(lb, args)
    return out


def _drain_alert(rtype: int, body: bytes) -> None:
    if rtype == RT_ALERT and len(body) >= 2:
        level = "fatal" if body[0] == 2 else "warning"
        print(f"    ALERT {level}: desc {body[1]}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-p", "--port", type=int, default=42127)
    pki = Path(__file__).parent / "pki"
    ap.add_argument("--cert", type=Path, default=pki / "server.der",
                    help="DER certificate (patched OID); defaults to pki/server.der")
    ap.add_argument("--key", type=Path, default=pki / "server.key")
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon/capture"))
    ap.add_argument("--no-capture", action="store_true",
                    help="do not save raw Fire2 frames (blaze-*.bin) to --out. They include "
                         "Authentication.login with the player's EA auth code; the installed "
                         "launcher always passes this")
    ap.add_argument("--bind-ip", default="0.0.0.0", metavar="IP[,IP...]",
                    help="local IPv4 address(es) to listen on, comma-separated. The default "
                         "takes every interface. A host whose own game should stay the local "
                         "player (127.0.0.1) needs 127.0.0.1 in the list")
    ap.add_argument("--handshake-timeout", type=float, default=10.0, metavar="SEC",
                    help="close a connection that has not finished the TLS handshake and sent "
                         "its first packet within SEC seconds")
    ap.add_argument("--redirect-ip", default="127.0.0.1",
                    help="address handed back in the getServerInstance reply (by default "
                         "ourselves, so the client comes back for the next packet)")
    ap.add_argument("--blaze-port", type=int, default=14219,
                    help="Blaze server port returned by getServerInstance (DIFFERENT from the "
                         "redirector's --port); the terminator listens on it as well")
    ap.add_argument("--blaze-host", default="gosredirector.ea.com",
                    help="hostname in the reply's HOST field. Must be in the hosts file and "
                         "match the certificate CN - the game connects to it.")
    ap.add_argument("--no-bytevault", action="store_true",
                    help="do NOT add bytevaultHostname/Port/Secure to CONF in preAuth (the game "
                         "then aims at EA's default, dead host)")
    ap.add_argument("--bytevault-host", default=None,
                    help="bytevaultHostname in CONF (defaults to --blaze-host; must match the "
                         "certificate CN, because bytevaultSecure=true)")
    ap.add_argument("--bytevault-port", type=int, default=0,
                    help="bytevaultPort in CONF (defaults to --blaze-port, so the ByteVault "
                         "connection lands on our Blaze)")
    ap.add_argument("--addr-index", type=int, default=0,
                    help="index of the active ADDR union member (0=IpAddress for "
                         "ServerAddressInfo; for experiments when the client will not connect)")
    ap.add_argument("--addr-only", action="store_true",
                    help="reply with the ADDR field only (union isolation, diagnostics)")
    ap.add_argument("--notify-comp", type=lambda x: int(x, 0), default=0x7802,
                    help="component of the UserSessions notification (CONFIRMED 0x7802)")
    ap.add_argument("--notify-cmd", type=lambda x: int(x, 0), default=5,
                    help="notification command (5=UserSessionExtendedDataUpdate)")
    ap.add_argument("--notify-probe", action="store_true",
                    help="after login, send notifications for commands 1..10 (diagnostics: "
                         "Frida shows which one triggers decoding)")
    ap.add_argument("--pad-preauth", type=int, default=0, metavar="N",
                    help="pad the preAuth reply to roughly N bytes with a plain string (no "
                         "maps) - tests whether SIZE or CONTENT breaks the client")
    ap.add_argument("--client-config", metavar="K=V,K=V",
                    help="custom set of client config keys instead of the default (for "
                         "bisection: checking key by key which one breaks the game)")
    ap.add_argument("--no-client-config", action="store_true",
                    help="send an EMPTY CONF in preAuth (old behaviour; the client then asks "
                         "for the config via FCCR{CFID='BlazeSDK'})")
    ap.add_argument("--no-qoss", action="store_true",
                    help="send an EMPTY QOSS in preAuth (old behaviour)")
    ap.add_argument("--qos-port", type=int, default=17502,
                    help="QoS ping-site port advertised in QOSS and listened on over UDP")
    ap.add_argument("--no-qos-responder", action="store_true",
                    help="do not start the QoS UDP responder")
    ap.add_argument("--qos-numprobes", type=int, default=10,
                    help="<numprobes> in the /qos/qos reply (how many UDP probes the client "
                         "sends; qtyp=2 requires >= 2)")
    ap.add_argument("--qos-probesize", type=int, default=64,
                    help="<probesize> in the /qos/qos reply = UDP probe packet length "
                         "(must be non-zero)")
    ap.add_argument("--qos-interfaces", type=int, default=2,
                    help="how many QoS endpoints we expose (ports qos-port, +1, ...). The NAT "
                         "test (/qos/firewall?nint=N) compares the external port seen from "
                         "different endpoints, so it needs >= 2")
    ap.add_argument("--qos-requestid", type=int, default=1234,
                    help="<requestid> in the /qos/qos reply. MUST be >= 2 - the same field "
                         "selects the probe receive path, and the bandwidth path only works "
                         "for >= 2")
    ap.add_argument("--session-bps", type=int, default=blaze.SESSION_BPS, metavar="BPS",
                    help="bandwidth (bit/s, both ways) the other players are told each player has, "
                         "in the session data and the game's NQOS. 100000 = up to 1.0.8 (A/B: "
                         "whether a 'slow' player is why name tags show only up close)")
    ap.add_argument("--qos-upstream-bps", type=int, default=100_000_000,
                    help="client upstream bandwidth reported in the reply to the first "
                         "bandwidth probe (bits/s, field +0x14)")
    ap.add_argument("--qos-firetype", type=int, default=1,
                    help="<firetype> in the /qos/firetype reply (NAT type). 5 = the 'unknown' "
                         "sentinel, and the game never calls the callback")
    ap.add_argument("--postauth-minimal", action="store_true",
                    help="in the postAuth reply, zero PORT and empty ADRS in PSS/TELE/TICK "
                         "(the structures stay). A/B for the question of whether the client "
                         "disconnects because it tries to reach subsystems at addresses where "
                         "nobody is listening")
    ap.add_argument("--bytevault-format", choices=("json", "heat"), default="json",
                    help="ByteVault reply format (REST over HTTPS on the Blaze port): json "
                         "(keys = field names without the 'm', unconfirmed) or heat (the same "
                         "TDF in binary)")
    ap.add_argument("--bytevault-pictures", choices=("raw", "json", "off"), default="raw",
                    help="how a player's launcher picture answers the game's GET "
                         ".../categories/Pictures/records/<uid>: raw JPEG bytes, a JSON guess "
                         "{info, payload{contentType, blob}} or off (the old empty reply). What "
                         "the game itself wrote to a record always wins. Research - see "
                         "_bytevault_record")
    ap.add_argument("--public-ip", default=None, metavar="IP",
                    help="this machine's address as seen from another machine (multiplayer). "
                         "Defaults to the detected LAN address. QoS reports it to the local "
                         "player as the external address so others can connect; 127.0.0.1 = "
                         "old behaviour")
    ap.add_argument("--local-id", type=int, default=0, metavar="UID",
                    help="uid of the player at the server. It must be the id of the career save "
                         "the game loads (Documents\\Ghost Games\\...\\settings\\<id>.sav), or "
                         "progress is written to a file the game never reads. By default found "
                         "through this machine's EA App (proto-lab/ea_identity.py)")
    ap.add_argument("--player-id", action="append", default=[], metavar="IP=UID",
                    help="EA save id of the player at an address (repeatable) - for a guest "
                         "without the launcher, whose launcher would otherwise report it. Checked "
                         "against the account suffix in the player's login token")
    ap.add_argument("--local-persona", default="", metavar="NAME",
                    help="name of the player at the server; stored in players.json, so it is "
                         "only needed once")
    ap.add_argument("--player", action="append", default=[], metavar="IP=NAME",
                    help="player name for an IP address (repeatable). The server cannot learn "
                         "EA names by itself - the login carries only an opaque Origin token")
    ap.add_argument("--mm-fail", action="store_true",
                    help="GameManager.startMatchmaking: send NotifyMatchmakingFailed "
                         "SESSION_TIMED_OUT instead of creating a public game (A/B)")
    ap.add_argument("--no-player-state-notify", dest="player_state_notify", action="store_false",
                    help="do NOT send NotifyGamePlayerStateChange (4/116) when a player moves "
                         "to ACTIVE_CONNECTED. Up to and including run-39 only notification 30 "
                         "was sent and the joining player lost the game ~7 s after the world "
                         "finished loading (A/B)")
    ap.add_argument("--no-host-migration", dest="host_migration", action="store_false",
                    help="when the host leaves, end the game for everyone (NotifyGameRemoved) "
                         "instead of handing it to another player - behaviour up to 17.09 (A/B)")
    ap.add_argument("--migration-skip-player-removed", dest="migration_player_removed",
                    action="store_false",
                    help="during a host migration, do NOT send the old host's NotifyPlayerRemoved "
                         "after NotifyHostMigrationStart (A/B, in case the client crashes on it)")
    ap.add_argument("--join-migrated-games", dest="join_migrated", action="store_true",
                    help="let matchmaking put players into a game that went through a host "
                         "migration. Off by default: in test 62 the migrated host's game never "
                         "sent game traffic to such a joiner, who left after ~50 s. With it off, "
                         "a returning player gets a fresh session and the players who stayed "
                         "regroup with 'Search session' (A/B)")
    ap.add_argument("--no-admin-tracking", dest="admin_tracking", action="store_false",
                    help="keep no server-side admin list: NotifyGameSetup carries ADMN = [host] "
                         "and nobody is told when an admin leaves - behaviour up to test 59, where "
                         "a player returning to the same game was never re-promoted to admin and "
                         "its game abandoned the join after ~8 s (A/B)")
    ap.add_argument("--migration-type", type=int, choices=(0, 1, 2), default=2,
                    help="HostMigrationType sent in NotifyHostMigrationStart: 0 topology host only, "
                         "1 platform host only, 2 both (default - the Rivals host is both). Test "
                         "53 used 0: the new host kept the mesh but stopped acting as the game's "
                         "owner, and a player joining the migrated game left after ~8 s")
    ap.add_argument("--no-platform-host-init", dest="platform_host_init", action="store_false",
                    help="do NOT send NotifyPlatformHostInitialized (4/71) after a migration that "
                         "moves the platform host (A/B)")
    ap.add_argument("--migration-timeout", type=float, default=10.0, metavar="SEC",
                    help="finish a host migration after this many seconds even if the new host "
                         "never reports updateGameHostMigrationStatus. 0 = never")
    ap.add_argument("--mm-delay", type=int, default=0, metavar="MS",
                    help="delay of the matchmaking decision (NotifyGameSetup) in ms; the client "
                         "gets its MSID immediately. Clamped to DUR from the request. 0 "
                         "(default) = synchronous decision. Run-39 showed the client only sends "
                         "removePlayer AFTER the matchmaking result, so waiting has nothing to "
                         "wait for; kept for a client that leaves its game before searching (A/B)")
    ap.add_argument("--no-speed-walls", action="store_true",
                    help="answer NFS.getInGameSpeedWalls (2050/20) with an empty acknowledgement "
                         "instead of saved results (A/B)")
    ap.add_argument("--no-autolog", action="store_true",
                    help="answer Autolog (NFS 2050/21 recommendations, 29 playlist, 31 rival score, "
                         "39 Special Guest info, 41 Special Guest speed wall) with an empty "
                         "acknowledgement, as before 1.0.12.2 (A/B)")
    ap.add_argument("--autolog-beat-type", type=int, default=blaze.RECOMMENDATION_BEAT_YOU,
                    metavar="N", help="RecommendationType of the \"X beat you\" entries: 0 = BEAT_YOU "
                                      "(default), 1 = HOT, 2 = POPULAR - values ASSUMED from the order "
                                      "of the names in the binary")
    ap.add_argument("--autolog-world-only", action="store_true",
                    help="\"X beat you\" entries only on cameras, zones and jumps, none on events "
                         "(races, pursuits ...) - the 1.0.12.4 behaviour, should an event entry crash "
                         "the game after a race")
    # 1.0.12.4's switch for the event entries, now the default; kept so a config.json that still
    # carries it starts the server
    ap.add_argument("--autolog-event-recommendations", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--autolog-empty-rivals", action="store_true",
                    help="list Autolog rivals with no \"X beat you\" entry too (empty RECM) - "
                         "CRASHES the game on the reply (confirmed 02.10, unmodded game); tests only")
    ap.add_argument("--autolog-unconfirmed-rivals", action="store_true",
                    help="show an online player whose identity is not confirmed (no launcher, a "
                         "guessed career save) in the others' Autolog - rival list and speed walls - "
                         "as up to 1.0.12.6. Clicking such a rival after he drove through one of his "
                         "cameras in your session CRASHED the game (02.10); tests only")
    ap.add_argument("--autolog-no-session-rivals", action="store_true",
                    help="leave everyone in your game off the Autolog rival list (they stay on the "
                         "walls) - should the 02.10 crash ever come back with a confirmed player")
    ap.add_argument("--autolog-vehicles", choices=("keep", "drop", "swap"), default="keep",
                    help="a rival's car (vehicleUsed) that none of the asker's own results was "
                         "driven in, in the Autolog reply: keep = as stored, drop = left out, swap = "
                         "the asker's most used car instead (A/B; ruled out as the 02.10 crash)")
    ap.add_argument("--autolog-rival", type=int, action="append", default=[], metavar="UID",
                    help="treat this stored player as if online: an Autolog rival with rows on "
                         "the speed walls - to reproduce a crash with a rival who is not around; "
                         "repeatable, tests only")
    ap.add_argument("--strict-avoid", action="store_true",
                    help="never put a player into a game its matchmaking asks to avoid (CRIT.AGAM.GIDL), "
                         "as before 1.0.12.1. By default such a game is still taken when it is the only "
                         "one - a game avoids the one it just dropped out of")
    ap.add_argument("--no-resume", action="store_true",
                    help="answer UserSessions.resumeSession (0x7802/0x23) with an empty "
                         "acknowledgement, as before 1.0.12, instead of taking the session back (A/B)")
    ap.add_argument("--speedwall-relation", type=int, default=blaze.RELATION_FRIEND, metavar="N",
                    help="UserRelationType given to the OTHER players' speed wall rows (the asker's "
                         "own row is LOCAL_PLAYER=1). 2 = FIRSTPARTY_FRIEND (default), 3 = "
                         "RECENTLY_PLAYED, 0 = NOT_SET as before 1.0.12. Values ASSUMED from the "
                         "order of the enum's names in the binary")
    ap.add_argument("--no-lookup-users", action="store_true",
                    help="answer UserSessions.lookupUsers (0x7802/13) with an empty acknowledgement, "
                         "as before 1.0.8, instead of the players behind the asked ids (A/B)")
    ap.add_argument("--entitlements", choices=("none", "online"), default="none",
                    help="Authentication.listUserEntitlements2 (1/29): none = empty list, "
                         "online = an ONLINE_ACCESS entry for the NFS14PC group")
    ap.add_argument("--no-store", action="store_true",
                    help="do NOT save progress from GameReporting (28) reports to disk")
    ap.add_argument("--data-dir", default=None,
                    help="progress directory (defaults to ~/TurboRivals/data)")
    ap.add_argument("--gm-player-state", type=int, default=4,
                    help="host player state in NotifyGameSetup: 4 = ACTIVE_CONNECTED, "
                         "2 = ACTIVE_CONNECTING (PlayerState enum from the binary)")
    ap.add_argument("--no-ack-unknown", dest="ack_unknown", action="store_false",
                    help="do NOT answer RPCs without a handler with an empty acknowledgement "
                         "(by default we reply err=0 with an empty payload so the game's "
                         "request completes)")
    ap.add_argument("--legacy-user-added", action="store_true",
                    help="in the UserAdded notification send USER with the old "
                         "UserSessionLoginInfo tags instead of UserIdentification (the game "
                         "then gets a user with ID=0) - for A/B")
    ap.add_argument("--empty-user-auth", action="store_true",
                    help="send the UserAuthenticated notification (0x7802/8) with an EMPTY "
                         "payload (old behaviour; the game gets BUID=0) - for A/B")
    ap.add_argument("--plain-session-data", action="store_true",
                    help="send EMPTY UserSessionExtendedData in the notifications after login "
                         "(old behaviour - for A/B)")
    ap.add_argument("--dump-tdf", action="store_true",
                    help="print the TDF tree of every client request (shows what the game "
                         "sends in login/postAuth)")
    ap.add_argument("--idle-timeout", type=int, default=300,
                    help="seconds of silence before we print a waiting notice (the connection "
                         "is NOT closed - the game keeps its Blaze session open)")
    ap.add_argument("--keepalive", type=float, default=3.0, metavar="SEC",
                    help="after login, send a server-side Fire2 PING after every N seconds of "
                         "silence so the game does not drop the Blaze connection on its idle "
                         "timeout (error 0x800e0000 -> teardown -> crash). 0 = off")
    ap.add_argument("--reply-msgtype", type=lambda x: int(x, 0), default=0x10,
                    help="msgType byte in the Fire2 reply header. 0x10 = REPLY (confirmed: the "
                         "game decodes ServerInstanceInfo)")
    args = ap.parse_args()

    if not args.cert.exists() or not args.key.exists():
        sys.stderr.write("no pki/ - run make_stub_cert.py first\n")
        return 1

    cert_der = args.cert.read_bytes()
    rsa = load_rsa_priv(args.key)
    print(f"RSA key loaded ({rsa[2] * 8} bit), cert {len(cert_der)} B")
    blaze.SESSION_BPS = args.session_bps
    print(f"players' bandwidth in the session data: {args.session_bps} bit/s (--session-bps)")

    bind_ips = [ip.strip() for ip in args.bind_ip.split(",") if ip.strip()]
    for ip in bind_ips:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            sys.stderr.write(f"--bind-ip: {ip!r} is not an IPv4 address\n")
            return 1
    if not bind_ips:
        sys.stderr.write("--bind-ip: no address given\n")
        return 1

    # Listening on the redirector port AND on the Blaze port - keeping them apart lets us
    # see whether the game actually connects after the getServerInstance reply.
    ports = [args.port]
    if args.blaze_port != args.port:
        ports.append(args.blaze_port)

    counter, lock = [0], threading.Lock()

    def serve(s: socket.socket, port: int) -> None:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle,
                             args=(conn, addr, args, args.out, counter, lock,
                                   rsa, cert_der),
                             daemon=True).start()

    def serve_qos(s: socket.socket, port: int) -> None:
        """QoS responder over UDP.

        After preAuth the Blaze client probes the ping sites from QOSS. We point them at
        ourselves, so we have to answer - without a reply the QoS test never
        finishes. The reply content is built by _qos_probe_reply (the client rejects a
        bare echo: the latency path needs >= 30 B and carries the external address).
        """
        n = 0
        while True:
            try:
                data, peer = s.recvfrom(4096)
            except OSError:
                return
            n += 1
            if n <= 8:                      # the first packets are shown in full
                print(f"\n  [QoS UDP #{n}] {len(data)} B from {peer[0]}:{peer[1]}")
                print(hexdump(data, 64))
            elif n % 25 == 0:
                print(f"  [QoS UDP :{port} #{n}] {len(data)} B from {peer[0]}:{peer[1]}")
            reply = _qos_probe_reply(data, peer, args)
            if n <= 8:
                kind = "latency" if len(data) == 0x14 else "bandwidth"
                print(f"    -> replying {len(reply)} B (probe: {kind})")
                print(hexdump(reply, 64))
            s.sendto(reply, peer)

    def serve_qos_http(s: socket.socket, port: int) -> None:
        """QoS probe over TCP/HTTP.

        DirtySDK also queries the ping site over HTTP - the binary has the URL patterns
        "%s://%s:%u/qos/qos?vers=%d", "/qos/firewall", "/qos/firetype". Until now
        we listened on the QoS port ONLY over UDP, so such a connection was refused.
        We log the whole request (that shows what the client wants) and answer with
        an empty 200, so as not to leave it with nothing.
        """
        while True:
            try:
                conn, peer = s.accept()
            except OSError:
                return
            try:
                conn.settimeout(5)
                req, req_body = _read_request(conn)
                reply = _launcher_request(req, req_body, args, peer)
                if reply is not None:                 # a launcher, not the game
                    status, ctype, body = reply
                    conn.sendall(b"HTTP/1.1 " + status + b"\r\n"
                                 b"Content-Type: " + ctype + b"\r\n"
                                 b"Connection: close\r\n"
                                 b"Content-Length: " + str(len(body)).encode() +
                                 b"\r\n\r\n" + body)
                    continue
                print(f"\n  [QoS HTTP] from {peer[0]}:{peer[1]}, {len(req)} B")
                try:
                    print("    " + req.decode("latin1").replace("\r\n", "\n    ").strip())
                except Exception:                     # noqa: BLE001
                    print(hexdump(req, 128))
                body = _qos_body(req, args, peer)
                print(f"    -> replying: {body.decode('latin1')}")
                conn.sendall(b"HTTP/1.1 200 OK\r\n"
                             b"Content-Type: text/xml\r\n"
                             b"Connection: close\r\n"
                             b"Content-Length: " + str(len(body)).encode() +
                             b"\r\n\r\n" + body)
            except OSError:
                pass
            except Exception as e:                    # noqa: BLE001
                # This one thread also answers the game's QoS - a bad launcher request must not
                # end it.
                print(f"  [http] {peer[0]}: request failed: {e!r}")
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    # Every socket is bound here, in the main thread, before anything is served: a port that is
    # taken stops the server with a message instead of silently killing one listener thread.
    listeners = []                                    # (serve function, socket, port)
    for ip in bind_ips:
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _bind_exclusive(s, ip, p, "redirector/Blaze")
            s.listen(16)
            print(f"listening on {ip}:{p} ({'redirector' if p == args.port else 'BLAZE'})")
            listeners.append((serve, s, p))
        if not args.no_qos_responder:
            for i in range(args.qos_interfaces):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                _bind_exclusive(s, ip, args.qos_port + i, "QoS UDP probes")
                print(f"listening on UDP {ip}:{args.qos_port + i} (QoS probes)")
                listeners.append((serve_qos, s, args.qos_port + i))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _bind_exclusive(s, ip, args.qos_port, "QoS HTTP")
            s.listen(8)
            print(f"listening on TCP {ip}:{args.qos_port} (QoS HTTP)")
            listeners.append((serve_qos_http, s, args.qos_port))
    for target, s, p in listeners[1:]:
        threading.Thread(target=target, args=(s, p), daemon=True).start()
    _lobby(args)                 # now, not on the first login: the local identity goes in the log up front
    print(f"handing the game this Blaze address: {args.redirect_ip}:{args.blaze_port}. "
          f"Ctrl+C to stop.")
    print("progress saving: " + ("OFF (--no-store)" if args.no_store
                               else str(args.data_dir or player_store.DATA_DIR)))
    lan = _public_ip(args)
    print(f"multiplayer: server address on this network is {lan}. On every other machine add a hosts "
          f"entry '{lan} {args.blaze_host}'. Windows firewall: Python TCP {args.port}, {args.blaze_port}, "
          f"{args.qos_port} and UDP {args.qos_port}-{args.qos_port + args.qos_interfaces - 1}; "
          f"game UDP 3659.\n")
    try:
        target, s, p = listeners[0]
        target(s, p)
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
