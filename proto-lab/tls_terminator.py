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
import hashlib
import hmac
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from tcp_proxy import hexdump, parse_records  # noqa: E402  (reuzycie raportowania)
import blaze  # noqa: E402  (Fire2 + TDF: dekodowanie zadania i budowa odpowiedzi)
import player_store  # noqa: E402  (zapis postepu z raportow GameReporting)
import lobby  # noqa: E402  (sesje graczy i gry - multiplayer)

# --- stale protokolu ---
VER_TLS11 = 0x0302
CIPHER_RC4_SHA = 0x0005
RT_CCS, RT_ALERT, RT_HANDSHAKE, RT_APPDATA = 20, 21, 22, 23
HS_CLIENT_HELLO, HS_SERVER_HELLO, HS_CERTIFICATE = 1, 2, 11
HS_SERVER_HELLO_DONE, HS_CLIENT_KEY_EXCHANGE, HS_FINISHED = 14, 16, 20
MAC_LEN = 20            # HMAC-SHA1
RC4_KEY_LEN = 16        # RC4_128


# ---------------------------------------------------------------- kryptografia
class RC4:
    """Strumieniowy RC4 - stan trwa przez cale zycie stanu szyfru (per kierunek)."""

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
    """PRF TLS 1.0/1.1: P_MD5(S1) XOR P_SHA1(S2), S1/S2 = polowki sekretu."""
    half = (len(secret) + 1) // 2
    s1, s2 = secret[:half], secret[-half:]
    md5 = p_hash(hashlib.md5, s1, label + seed, n)
    sha = p_hash(hashlib.sha1, s2, label + seed, n)
    return bytes(a ^ b for a, b in zip(md5, sha))


def load_rsa_priv(key_path: Path) -> tuple[int, int, int]:
    """Zwraca (n, d, k_bytes) z klucza prywatnego przez `openssl rsa -text`."""
    proc = subprocess.run(["openssl", "rsa", "-in", str(key_path), "-text",
                           "-noout"], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"nie moge odczytac klucza {key_path}:\n{proc.stderr}")
    txt = proc.stdout

    def grab(field: str) -> int:
        # Bloki hex postaci "field:\n    00:ab:cd:...\n    ..." az do nastepnego
        # pola (linia bez wciecia zaczynajaca sie od litery).
        m = re.search(rf"{field}:\s*\n((?:\s+[0-9a-f:]+\s*\n)+)", txt)
        if not m:
            raise SystemExit(f"could not find field '{field}' in openssl rsa -text")
        hexstr = re.sub(r"[^0-9a-f]", "", m.group(1))
        return int(hexstr, 16)

    n = grab("modulus")
    d = grab("privateExponent")
    k = (n.bit_length() + 7) // 8
    return n, d, k


def rsa_decrypt_pkcs1(ct: bytes, n: int, d: int, k: int) -> bytes:
    """RSA raw + zdjecie paddingu PKCS#1 v1.5 typu 2. Zwraca premaster."""
    m = pow(int.from_bytes(ct, "big"), d, n)
    em = m.to_bytes(k, "big")
    if em[0] != 0x00 or em[1] != 0x02:
        raise ValueError(f"zly padding PKCS#1: {em[:2].hex()}")
    sep = em.find(b"\x00", 2)
    if sep < 10:                       # PS musi miec >= 8 bajtow
        raise ValueError("could not find the padding separator")
    return em[sep + 1:]


# ---------------------------------------------------------------- warstwa rekordow
class Wire:
    """Bufor na strumieniu TCP: czyta i pisze rekordy TLS, liczy MAC/RC4."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""
        # Wersja warstwy rekordu dla naszych wysylek = TLS 1.1 (0x0302), DOKLADNIE
        # jak robil to zywy serwer EA. Capture (docs/recon/capture/120822-003-s2c.bin)
        # pokazuje, ze serwer slal WSZYSTKIE rekordy jako 0x0302 (ServerHello, Cert,
        # Done, CCS, Finished, AppData). Klient uzywa 0x0300 TYLKO dla ClientHello,
        # a od ClientKeyExchange wzwyz sam nadaje 0x0302. Nie odbijamy wiec 0x0300 z
        # ClientHello - wczesniejsza wersja tak robila i klient konczyl FIN-em tuz
        # po naszym Finished, bez wyslania pierwszego pakietu Blaze.
        self.record_version = VER_TLS11
        self.rx = None            # RC4 do odszyfrowania (klient->my), po CCS
        self.tx = None            # RC4 do szyfrowania (my->klient), po CCS
        self.rx_mac = b""
        self.tx_mac = b""
        self.rx_seq = 0
        self.tx_seq = 0

    def _recv_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("polaczenie zamkniete w trakcie rekordu")
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
            # Timeout w SRODKU rekordu: oddaj naglowek do bufora, zeby kolejne
            # recv_record wznowilo od tego samego miejsca, a nie od polowy.
            self.buf = head + self.buf
            raise
        if self.rx is not None:                       # stan szyfru aktywny
            frag = self._decrypt(rtype, ver, frag)
        return rtype, ver, frag

    def _decrypt(self, rtype: int, ver: int, frag: bytes) -> bytes:
        plain = self.rx.crypt(frag)
        if len(plain) < MAC_LEN:
            raise ValueError("rekord krotszy niz MAC")
        body, mac = plain[:-MAC_LEN], plain[-MAC_LEN:]
        want = self._mac(self.rx_mac, self.rx_seq, rtype, ver, body)
        if mac != want:
            print(f"    [!] bad record MAC (seq {self.rx_seq}) - "
                  f"continuing, this is diagnostics")
        self.rx_seq += 1
        return body

    def send_record(self, rtype: int, body: bytes) -> None:
        ver = self.record_version
        if self.tx is not None:
            mac = self._mac(self.tx_mac, self.tx_seq, rtype, ver, body)
            body = self.tx.crypt(body + mac)
            self.tx_seq += 1
        head = struct.pack(">BHH", rtype, ver, len(body))
        self.sock.sendall(head + body)

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
    """Zwraca (server_random 32B, wiadomosc ServerHello z naglowkiem handshake)."""
    rnd = struct.pack(">I", int(time.time())) + os.urandom(28)
    body = struct.pack(">H", VER_TLS11) + rnd
    body += b"\x00"                                   # brak session id
    body += struct.pack(">H", CIPHER_RC4_SHA)         # wybrany szyfr
    body += b"\x00"                                   # kompresja: null
    return rnd, hs_msg(HS_SERVER_HELLO, body)


def hs_msg(htype: int, body: bytes) -> bytes:
    return struct.pack(">B", htype) + len(body).to_bytes(3, "big") + body


def build_certificate(der: bytes) -> bytes:
    entry = len(der).to_bytes(3, "big") + der
    body = len(entry).to_bytes(3, "big") + entry      # lista certow (dlugosc)
    return hs_msg(HS_CERTIFICATE, body)


def parse_client_hello(msg: bytes) -> tuple[bytes, list[int]]:
    """Zwraca (client_random 32B, lista szyfrow). msg = cialo handshake (bez naglowka rekordu)."""
    body = msg[4:]                                    # pomijamy naglowek handshake
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


# ---------------------------------------------------------------- sesja
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

    w = Wire(conn)
    sess = None                                       # sesja Blaze (lobby.py) - po handshake
    transcript = b""                                  # wiadomosci handshake (z naglowkami)
    try:
        # 1. ClientHello
        rtype, ver, ch = w.recv_record()
        if rtype != RT_HANDSHAKE or not ch or ch[0] != HS_CLIENT_HELLO:
            print(f"  expected ClientHello, got type {rtype}")
            return
        transcript += ch
        # NIE odbijamy wersji rekordu klienta (0x0300 z ClientHello) - zywy serwer
        # odpowiadal 0x0302 na wszystkim (patrz komentarz w Wire). record_version
        # zostaje VER_TLS11.
        client_random, suites = parse_client_hello(ch)
        print(f"  ClientHello: record {hex(ver)}, {len(suites)} cipher suites"
              f"{' (RC4_SHA offered)' if CIPHER_RC4_SHA in suites else ' (!) no RC4_SHA'}")

        # 2-4. ServerHello + Certificate + ServerHelloDone (osobne rekordy)
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
        enc = cke[4:]                                 # cialo CKE
        enc = enc[2:] if len(enc) > (rsa[2]) else enc  # zdejmij 2B dlugosci (TLS)
        pre_master = rsa_decrypt_pkcs1(enc, *rsa)
        print(f"  ClientKeyExchange: premaster {len(pre_master)} B, "
              f"version inside premaster {pre_master[:2].hex()}")

        master, cmac, smac, ckey, skey = derive_keys(
            pre_master, client_random, server_random)

        # 6-7. ChangeCipherSpec + Finished klienta
        rtype, ver, ccs = w.recv_record()
        if rtype != RT_CCS:
            print(f"  expected ChangeCipherSpec, got type {rtype}")
            _drain_alert(rtype, ccs)
            return
        w.activate_read(RC4(ckey), cmac)              # od teraz klient szyfruje
        rtype, ver, fin = w.recv_record()
        if rtype != RT_HANDSHAKE or not fin or fin[0] != HS_FINISHED:
            print(f"  expected Finished, got type {rtype}")
            return
        want = finished_verify(master, b"client finished", transcript)
        got = fin[4:16]
        print(f"  client Finished: verify_data {'OK' if got == want else 'MISMATCH'}")
        transcript += fin                             # do Finished serwera

        # 8. ChangeCipherSpec + Finished serwera
        w.send_record(RT_CCS, b"\x01")
        w.activate_write(RC4(skey), smac)
        sfin = hs_msg(HS_FINISHED, finished_verify(master, b"server finished", transcript))
        w.send_record(RT_HANDSHAKE, sfin)
        print("  -> ChangeCipherSpec + server Finished")

        # 9. Pierwszy ApplicationData = pierwszy pakiet Blaze otwartym tekstem
        rtype, ver, app = w.recv_record()
        while rtype == RT_HANDSHAKE:                  # ignoruj ewentualne powtorki
            rtype, ver, app = w.recv_record()
        if rtype != RT_APPDATA:
            print(f"  after the handshake got type {rtype}, not ApplicationData")
            _drain_alert(rtype, app)
            return

        out_dir.mkdir(parents=True, exist_ok=True)

        # ByteVault laczy sie na TEN SAM port, ale mowi HTTP (REST), nie Fire2. W run-22
        # takie polaczenia wisialy na "ogon ... czekam na reszte ramki".
        if bytes(app[:7]).split(b" ")[0] in (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD"):
            print("  (this is HTTP, not Fire2 - ByteVault handling)")
            _serve_http(w, bytearray(app), args)
            return

        # 10. Petla serwera Blaze: dekoduj KAZDE zadanie Fire2 i odpowiadaj.
        #     UWAGA: granica rekordu TLS != granica ramki Fire2. Klient Blaze
        #     potrafi wyslac kilka RPC w jednym rekordzie (i rozbic jedno RPC na
        #     dwa rekordy). Dlatego sklejamy strumien w buforze i wycinamy z niego
        #     wszystkie KOMPLETNE ramki (12 B naglowka + size). Wczesniej brano
        #     tylko pierwsza ramke z rekordu, a ogon leciał do kosza -> RPC klienta
        #     nigdy sie nie konczylo (ekran "Laczenie").
        conn.settimeout(args.idle_timeout)
        buf = bytearray(app)
        frameno = 0
        # Wszystkie wysylki tego polaczenia ida przez sesje (blokada + wlasne msgId notyfikacji):
        # notyfikacje do tego gracza moze wysylac takze watek innego gracza (multiplayer).
        sess = lobby.Session(addr[0], lambda frame: w.send_record(RT_APPDATA, frame))
        logged_in = False                             # po 1/152; wlacza keepalive
        ping_seq = 0                                  # msgId serwerowych PINGow
        try:
            while True:
                # a) obsluz wszystko, co juz mamy w buforze
                while len(buf) >= blaze.FIRE2_HDR:
                    size = struct.unpack_from(">H", buf, 0)[0]
                    total = blaze.FIRE2_HDR + size
                    if len(buf) < total:              # ramka jeszcze niekompletna
                        break
                    pkt = bytes(buf[:total])
                    del buf[:total]
                    frameno += 1
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
                        # Po loginie wlaczamy krotki timeout, zeby budzic sie co
                        # keepalive sekund i podtrzymywac polaczenie Blaze (patrz
                        # nizej - inaczej gra zrywa je bledem 0x800e0000).
                        if fr.component == 1 and fr.command == 152 and args.keepalive:
                            logged_in = True
                            conn.settimeout(args.keepalive)
                        _deliver(sess, _after_reply(fr, args, sess))
                    else:
                        if name and "#" not in name:
                            # Komenda znana z binarki; surowa ramka i tak lezy w capture, a
                            # pola pokazuje --dump-tdf - hexdump tylko zasmiecal log.
                            print(f"  *** no handler: {name} ***")
                        else:
                            print("  *** no handler - hexdump (next piece to build) ***")
                            print(hexdump(pkt, 384))
                        # Domyslnie odpowiadamy pustym potwierdzeniem (err=0, pusty
                        # payload = odpowiedz z wartosciami domyslnymi). Bez tego RPC gry
                        # nigdy sie nie konczy i gra czeka w nieskonczonosc. run-20: po
                        # zalogowaniu przyszlo 7 takich zapytan naraz. --no-ack-unknown
                        # wylacza (zeby zobaczyc, na ktorym RPC gra naprawde stoi).
                        if getattr(args, "ack_unknown", True) and fr.msg_type == 0:
                            ack = blaze.build_empty_reply(fr.component, fr.command, fr.seq,
                                                          msg_type=args.reply_msgtype)
                            sess.send(ack)
                            print(f"  -> empty acknowledgement comp={fr.component} "
                                  f"cmd={fr.command} ({len(ack)} B)")
                if buf:
                    print(f"  ({len(buf)} B tail - waiting for the rest of the frame)")

                # b) dobierz kolejny rekord ze strumienia
                try:
                    rtype, ver, rec = w.recv_record()
                except socket.timeout:
                    # Cisza != koniec sesji. Gra trzyma polaczenie Blaze otwarte
                    # i moze dlugo nic nie wysylac - NIE zamykamy go.
                    if logged_in and args.keepalive:
                        # Keepalive: po loginie gra robi QoS na osobnych gniazdach,
                        # a Blaze TCP milczy. Aktualizacja polaczenia co klatke
                        # (0xf3a580) po przekroczeniu progu bezczynnosci [conn+0x2fc]
                        # zrywa polaczenie bledem 0x800e0000 -> teardown -> crash.
                        # Serwerowy PING resetuje licznik aktywnosci u klienta.
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

    except (ConnectionError, ValueError, struct.error) as e:
        print(f"  session error: {e}")
    finally:
        if sess is not None:
            _cancel_matchmaking(sess)
        if sess is not None and sess.uid:
            # Rozlaczenie = wyjscie ze wszystkich gier; pozostali gracze dostaja notyfikacje.
            _deliver(sess, _lobby(args).logout(sess))
        try:
            conn.close()
        except OSError:
            pass


def _deliver(sess, notes) -> None:
    """Wysyla notyfikacje (sesja, ramka) - do wlasnego polaczenia i do innych graczy. Polaczenie
    innego gracza moglo juz sie zamknac: taki blad tylko logujemy."""
    for target, note in notes:
        nfr = blaze.Fire2.decode(note)
        who = "" if target is sess else f" -> do {target!r}"
        try:
            seq = target.notify(note)
        except OSError as e:
            print(f"  -> NOTIFY comp={nfr.component} cmd={nfr.command}{who} NOT SENT ({e})")
            continue
        print(f"  -> async NOTIFY comp={nfr.component} cmd={nfr.command} seq={seq} "
              f"({len(note)} B){who}")


def _bind_exclusive(s: socket.socket, port: int, opis: str) -> None:
    """Bind, ktory GLOSNO pada, gdy port jest juz czyjs.

    Dlaczego nie SO_REUSEADDR (bylo tu wczesniej): na Windows ta opcja pozwala
    DRUGIEMU procesowi zajac ten sam adres:port, a polaczenia dostaje wtedy
    jeden z nich - w praktyce ten, ktory bindowal pierwszy. Nowy terminator
    wypisywal wiec komplet nasluchow i nie dostawal NICZEGO, bo gre obslugiwala
    stara instancja z poprzedniego kodu. Kosztowalo to caly przebieg A/B
    2026-09-11: logi nowych serwerow mialy sam baner, a Frida pokazywala, ze gra
    laczy sie i rozmawia. SO_EXCLUSIVEADDRUSE odwraca to: drugi bind konczy sie
    bledem od razu, zamiast cicho podszywac sie pod dzialajacy serwer."""
    excl = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
    if excl is not None:
        s.setsockopt(socket.SOL_SOCKET, excl, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError as e:
        sys.exit(f"\nPORT {port} ({opis}) IS ALREADY IN USE: {e}\n"
                 f"Most likely a terminator from an earlier run is still running "
                 f"(and the game then talks to THAT one, not to this process).\n"
                 f"Check:  netstat -ano | Select-String {port}\n"
                 f"and stop that process before starting this one.")


def _qos_body(req: bytes, args, peer=None) -> bytes:
    """Tresc odpowiedzi koordynatora QoS. Format: XML (DirtySDK xmlparse).

    Ustalone z dezasemblacji zrzutu pamieci (RVA, baza modulu 0x140000000):
    _QosApiParseResponse @0xfdb070 bierze bufor odpowiedzi HTTP
    (*(QosApiRef+0x128) + 0x112) i probuje po kolei XmlFind(buf, "firewall"),
    XmlFind(buf, "firetype"), XmlFind(buf, "qos"); gdy zadna nie trafi -> -2.

    XmlFind @0xfee910 skanuje do '<', pomija <?..?> i <!..>, konczy na '</',
    a terminator nazwy elementu to maska 0x40008001FFFFFFFF = {0x00-0x20, '/',
    '>'} - NIE ma tam '=', wiec nazwy z binarki (".numprobes", ".probesize",
    ".qosport", ".requestid", ".reqsecret") sa nazwami ELEMENTOW XML, a nie
    kluczy "klucz=wartosc" ani atrybutow. Wartosci czyta
    XmlContentGetInteger @0xfee6a0 (po '<' przeskakuje do '>', <tag/> = default),
    a po rodzenstwie (listy ips/ports) przechodzi XmlNext @0xfeeaf0.

    Dlatego poprzednia odpowiedz ("qos.numprobes=1 qos.probesize=64 ...",
    format TagField) nie zawierala ANI JEDNEGO '<' - parser wracal z -2 i gra
    milczala na UDP, mimo ze odpowiedz odczytala.

    Walidacja gry (0xfdb3f1-0xfdb424), return 0 tylko gdy przejdzie:
      * qosport  != 0  (zawsze)
      * requestid != 0 (zawsze)
      * dla qtyp == 2 (test pasma) dodatkowo probesize != 0 i numprobes >= 2
    probesize jest dlugoscia pakietu sondy, wiec musi byc sensowny takze dla
    qtyp == 1.

    qosport wskazujemy na siebie: klient wysle tam sondy UDP, ktore odbija
    responder echo. Sonda (builder @0xfdbc30) niesie big-endian requestid,
    reqsecret, licznik sondy i numprobes, a odbior @0xfdb9c9 porownuje te pola
    ze stanem - echo bajt w bajt spelnia wszystkie trzy warunki.
    """
    path = req.split(b" ", 2)[1] if b" " in req else b"/"
    port = args.qos_port
    if b"/qos/firewall" in path:
        # Klucze tej galezi to SCIEZKI ZAGNIEZDZONE, nie nazwy plaskie: w .rdata
        # stoi jeden string ".ips.ips" z NUL-em na koncu (@0x170ef18) i ".ports.ports"
        # (@0x170ef28) - po jednym NUL-u na koncu, kropka w srodku to zejscie do
        # dziecka. Czyli gra szuka elementu `ips` WEWNATRZ elementu `ips`:
        #     <ips><ips>A</ips><ips>B</ips></ips>
        # Plaskie <ips>A</ips> nie zostaje znalezione - potwierdzone zywym stanem
        # ze zrzutu pamieci: numinterfaces bylo zapisane (0xfdb0b6), a ips[0] i
        # ports[0] zostaly zerami, bo XmlFind(".ips.ips") zwrocil NULL i parser
        # wyszedl z -2 (0xfdb100 -> 0xfdb269).
        # Dla kontrastu galaz /qos/qos ma klucze plaskie (".numprobes" itd.).
        #
        # Kolejne pary to kolejne PORTY na tym samym IP - test NAT polega na
        # porownaniu portu zewnetrznego widzianego z dwoch roznych endpointow
        # serwera, wiec musza byc rozne. Nasluch UDP na tych portach podnosi
        # main() (--qos-interfaces).
        nint = 1
        for part in path.split(b"&"):
            if part.startswith(b"nint=") or part.startswith(b"?nint="):
                try:
                    nint = int(part.split(b"=", 1)[1])
                except ValueError:
                    pass
        nint = max(1, min(nint, args.qos_interfaces))      # tylko tyle, ile slucha
        # Klient z innego komputera musi dosiegnac sond UDP pod adresem serwera w sieci.
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
        # Wartosc trafia do [conn+0x1b0]; gdy == 5, gra nie wola callbacka
        # (5 = sentinel "nieznany"), wiec odsylamy cos innego. Semantyki enuma
        # nie znamy - stad flaga --qos-firetype do bisekcji.
        return (f"<firetype><firetype>{args.qos_firetype}</firetype>"
                f"</firetype>").encode()
    # /qos/qos?vers=1&qtyp=N&prpt=P  (prpt = port, z ktorego klient sonduje)
    return (f"<qos><numprobes>{args.qos_numprobes}</numprobes>"
            f"<probesize>{args.qos_probesize}</probesize>"
            f"<qosport>{port}</qosport>"
            f"<requestid>{args.qos_requestid}</requestid>"
            f"<reqsecret>1</reqsecret></qos>").encode()


def _qos_probe_reply(data: bytes, peer, args) -> bytes:
    """Odpowiedz na sonde UDP QoS. Gole echo NIE WYSTARCZA i dwa rodzaje sond
    wymagaja ROZNYCH odpowiedzi.

    Odbior @0xfdb6a0 wybiera sciezke po polu +0x04 NASZEJ odpowiedzi
    (0xfdb76d: `cmp r15d, 2; jae ...`), a nie po tym, co przyslal klient:
      ntohl(+0x04) <  2  -> sciezka latencji / adresu zewnetrznego
      ntohl(+0x04) >= 2  -> sciezka pasma, z porownaniem requestid i reqsecret
    Dlatego requestid w odpowiedzi HTTP MUSI byc >= 2 (inaczej sciezka pasma jest
    nieosiagalna), a w odpowiedzi na sonde latencji wpisujemy na sztywno 1.

    SONDA LATENCJI - 20 B, builder @0xfdbe80 (dlugosc na twardo 0x14), BE:
        +0x00 id ping-site'u  +0x04 requestid  +0x08 reqsecret
        +0x0c [QosApi+0x14]   +0x10 czas wyslania (NetTick)
    Odpowiedz MUSI miec >= 0x1e = 30 B (0xfdb777) i zawierac:
        +0x04 = 1             wybor sciezki latencji
        +0x10 = czas z sondy  RTT = czas_odbioru - ntohl(+0x10)   (0xfdb82e)
        +0x14 = IP klienta    zapis do stanu jako adres zewnetrzny (0xfdb7cb)
        +0x18 = port klienta  u16 (0xfdb804)
        +0x1a = 0             dlugosc ogona; memcpy z +0x1e tylko gdy
                              (dlugosc - 1) <= 0xff, czyli 0 = brak ogona
    Sens sondy: klient poznaje swoj adres zewnetrzny i mierzy RTT.

    SONDA PASMA - dlugosc probesize, builder @0xfdbc30, BE:
        +0x00 id  +0x04 requestid  +0x08 reqsecret
        +0x0c licznik wyslanych (0, 1, 2, ...)   +0x10 numprobes
    Odpowiedz ma INNY uklad niz sonda (kod czyta z niej inne offsety):
        +0x04 = requestid, +0x08 = reqsecret  - porownywane ze stanem (0xfdb9d0)
        +0x0c = ILE SOND JUZ ODEBRALISMY; gdy zrowna sie z numprobes (0xfdba7b),
                test pasma jest domkniety: 0xfdba94 ustawia bit0 "gotowe"
                (przy firetype != 5; gdy == 5, 0xfdbaa0 przechodzi do qtyp 5)
        +0x14 = pasmo WYSYLKI klienta zmierzone przez serwer, w bitach/s -
                czytane TYLKO z pierwszej odpowiedzi (0xfdba05)
    Pasmo ODBIORU klient liczy sam z czasow naszych odpowiedzi
    (0xfdba1f: odebrane * probesize * 8000 / czas), wiec wystarczy odpowiadac
    na kazda sonde.

    Licznik odebranych bierzemy z sondy (+0x0c) + 1 - sonda numeruje sie sama od
    zera, wiec nie trzymamy zadnego stanu, a przy ostatniej sondzie wychodzi
    dokladnie numprobes.
    """
    if len(data) < 0x10:
        return data                        # za krotkie, gra i tak odrzuci
    buf = bytearray(data)
    if len(data) == 0x14:                  # sonda latencji
        buf[0x04:0x08] = (1).to_bytes(4, "big")
        # Adres zewnetrzny, ktory klient potem melduje innym graczom (HNET/PNET). Gracz lokalny
        # sonduje z 127.0.0.1 - drugi komputer nie polaczy sie z takim adresem, wiec podajemy
        # adres tego komputera w sieci (--public-ip albo wykryty LAN). --public-ip 127.0.0.1
        # przywraca stare zachowanie.
        seen = _public_ip(args) if peer[0] in lobby.LOCAL_IPS else peer[0]
        ip = bytes(int(o) for o in seen.split("."))
        return bytes(buf) + ip + peer[1].to_bytes(2, "big") + bytes(4)
    got = int.from_bytes(data[0x0c:0x10], "big") + 1
    buf[0x0c:0x10] = got.to_bytes(4, "big")
    if len(buf) >= 0x18:
        buf[0x14:0x18] = args.qos_upstream_bps.to_bytes(4, "big")
    return bytes(buf)


def _dispatch_blaze(fr, args, sess):
    """Zwraca bajty odpowiedzi Fire2 dla znanego zadania, albo None (brak handlera).
    `sess` = lobby.Session tego polaczenia (tozsamosc gracza, adres, gry)."""
    if fr.component == 5 and fr.command == 1:          # Redirector.getServerInstance
        return blaze.build_getserverinstance_response(
            args.redirect_ip, args.blaze_port, seq=fr.seq,
            addr_index=args.addr_index, minimal=args.addr_only,
            msg_type=args.reply_msgtype, host=args.blaze_host)
    if fr.component == 9 and fr.command == 7:           # Util.preAuth
        if args.no_client_config:
            conf = {}                                   # puste CONF (stare zachowanie)
        elif args.client_config is not None:
            conf = dict(kv.split("=", 1) for kv in args.client_config.split(",") if kv)
        else:
            conf = dict(blaze.DEFAULT_CLIENT_CONFIG)
            if not args.no_bytevault:
                # ByteVault: tuz po zalogowaniu (stan online gry 9 -> 10 w 0xa1bb00) gra
                # czyta te klucze i inicjuje polaczenie ByteVault (0xf71b40). Bez nich
                # bierze domyslny host EA, ktory nie zyje. Formaty z kodu: port przez atoi
                # (getter +0x48), secure = porownanie z "true", host jako string.
                # Kierujemy na nasz Blaze - nieznane RPC wyjda w logu jako "brak handlera".
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
        # Tozsamosc per gracz z players.json (lobby.py): nadana raz przy pierwszym logowaniu.
        sess.outbox += _lobby(args).login(sess)
        print(f"  [player] {sess.ip} -> {sess.persona} (uid {sess.uid})")
        return blaze.build_login_response(fr.seq, sess.uid, sess.persona,
                                          msg_type=args.reply_msgtype)
    if fr.component == 9 and fr.command == 8:           # Util.postAuth
        return blaze.build_postauth_response(fr.seq, sess.uid, msg_type=args.reply_msgtype,
                                             subsystems=not args.postauth_minimal)
    # --- komendy Util wolane PO postAuth (numeracja z emulatora BF3, ten sam
    #     silnik; NFS uzywa component 9 dla Util). Brak odpowiedzi na ktoras z
    #     nich najpewniej trzymal gre na "Laczenie" (RPC klienta nie konczyl sie).
    if fr.component == 9 and fr.command == 1:           # Util.fetchClientConfig
        return blaze.build_fetch_client_config_response(fr.seq, msg_type=args.reply_msgtype)
    if fr.component == 9 and fr.command == 5:           # Util.getTelemetryServer
        return blaze.build_telemetry_response(fr.seq, msg_type=args.reply_msgtype,
                                              ip=args.redirect_ip)
    if fr.component == 9 and fr.command == 0xB:         # Util.userSettingsSave
        return blaze.build_empty_reply(9, 0xB, fr.seq, msg_type=args.reply_msgtype)
    if fr.component == 9 and fr.command == 0xC:         # Util.userSettingsLoadAll
        return blaze.build_user_settings_load_all_response(fr.seq, msg_type=args.reply_msgtype)
    # --- UserSessions (component 0x7802). Numery komend NIE sa zgadniete:
    #     getCommandName @0xf285b0 ma tablice skokow @0xf2867c (indeks = cmd - 3),
    #     z ktorej wprost wynika: 3=fetchExtendedData, 5=updateExtendedDataAttribute,
    #     8=updateHardwareFlags, 0xC=lookupUser, 0x14=updateNetworkInfo,
    #     0x19=updateUserSessionClientData, 0x1A=setUserInfoAttribute,
    #     0x20=lookupUserSessionId, 0x23=resumeSession.
    #     updateNetworkInfo przychodzi po domknieciu testu QoS (niesie
    #     NetworkInfo{ADDR,NLMP,NQOS}) i nie zwraca danych - wystarczy puste
    #     potwierdzenie, by RPC klienta sie zakonczylo.
    if fr.component == 0x7802 and fr.command in (0x14, 0x08, 0x1A):
        if fr.command == 0x14:
            # Adres gracza dla innych (UserAdded, roster gry). Pierwszy raport, jeszcze przed QoS,
            # ma EXIP 0 - takiego nie zapamietujemy.
            addr = _union_ip_pair(_req_fields(fr).get("ADDR"))
            if addr and addr[0]:
                sess.addr = addr
        return blaze.build_empty_reply(fr.component, fr.command, fr.seq,
                                       msg_type=args.reply_msgtype)
    # --- RPC po zalogowaniu (run-20/21b). Nazwy z emulacji getCommandName w binarce,
    #     uklady odpowiedzi z tablic pol TDF - patrz buildery w blaze.py.
    req = _req_fields(fr)
    mt = args.reply_msgtype
    if fr.component == 9 and fr.command == 10:          # Util.userSettingsLoad
        return blaze.build_user_settings_load_response(fr.seq, str(req.get("KEY", "")), msg_type=mt)
    if fr.component == 7 and fr.command == 15:          # Stats.getKeyScopesMap
        return blaze.build_key_scopes_response(fr.seq, msg_type=mt)
    if fr.component == 7 and fr.command == 4:           # Stats.getStatGroup
        return blaze.build_stat_group_response(fr.seq, str(req.get("NAME", "")), msg_type=mt)
    if fr.component == 7 and fr.command == 16:          # Stats.getStatsByGroupAsync
        return blaze.build_empty_reply(7, 16, fr.seq, msg_type=mt)   # dane idza notyfikacja 7/0x32
    if fr.component == 25 and fr.command == 6:          # AssociationLists.getLists
        return blaze.build_get_lists_response(fr.seq, msg_type=mt)
    if fr.component == 2050 and fr.command == 38:       # NFS.getGeolocationInfo
        return blaze.build_geolocation_info_response(fr.seq, int(req.get("BLID", 0) or 0), msg_type=mt)
    if fr.component == 1 and fr.command == 36:          # Authentication.getAuthToken
        return blaze.build_get_auth_token_response(fr.seq, f"TR_AUTH_{sess.uid}", msg_type=mt)
    if fr.component == 1 and fr.command == 29:          # Authentication.listUserEntitlements2
        # BUID = id persony EA tej gry (np. 1006431274704) - zapamietane w sesji. Licencje domyslnie
        # puste (Steam Complete Edition: DLC dziala lokalnie), wiec odpowiedz generyczna.
        if req.get("BUID"):
            sess.persona_id = int(req["BUID"])
        if getattr(args, "entitlements", "none") == "online":
            # A/B 15.09: dolaczajacy wychodzi z cudzej gry ~230 ms po tych zapytaniach (log-30..32).
            # Hipoteza: czeka na uprawnienie typu ONLINE_ACCESS w grupie gry. Tylko NFS14PC - grupa
            # NFS13PC (loyalty) moglaby odblokowac nagrody w zapisie kariery.
            groups = [str(g) for g in (req.get("GNLS") or []) if str(g) == "NFS14PC"]
            ents = [dict(id=1000 + i, group=g, type=blaze.ENTITLEMENT_TYPE["ONLINE_ACCESS"],
                         tag="ONLINE_ACCESS", persona_id=sess.persona_id,
                         product_id="Origin.OFR.50.0000676", grant_date="2013-11-19T00:00Z")
                    for i, g in enumerate(groups)]
            print(f"  [entitlements] {sess.persona}: {len(ents)} ONLINE_ACCESS entry/entries for {groups}")
            return blaze.build_list_entitlements_response(fr.seq, ents, msg_type=mt)
        return None
    # --- GameManager (run-22: "Wyszukiwanie gry" = createGame bez odpowiedzi).
    #     Gry i gracze w rejestrze lobby.py; notyfikacje (takze dla innych graczy) wysyla _after_reply.
    if fr.component == 4 and fr.command == 1:           # GameManager.createGame
        lb = _lobby(args)
        sess.addr = _raw_ip_pair(fr.payload)
        lb.learn_persona(sess, _raw_str(fr.payload, "GNAM", ""))
        g = lb.create_game(sess, _create_game_params(fr.payload), getattr(args, "gm_player_state", 4))
        sess.pending = ("created_game", 0, g)
        print(f"  [game] {sess!r} creates game {g.gid:#x} ({'public' if g.public else 'private'})")
        return blaze.build_create_game_response(fr.seq, g.gid, msg_type=mt)
    if fr.component == 4 and fr.command == 25:          # GameManager.resetDedicatedServer
        # run-36/37: gra z sesja PRYWATNA nie matchmakuje - zamiast startMatchmaking prosi o
        # zresetowanie serwera dedykowanego na wlasna gre (ATTR gameMembershipRequirements=
        # 'Private', GSET 276 zamiast 287 = bez bitow "otwarta na przegladanie/matchmaking").
        # Zadanie ma te same tagi co createGame (ATTR GNAM GSET NTOP PRES VOIP VSTR PCAP TIDS
        # HNET), wiec parametry czytamy tym samym kodem. Bez odpowiedzi gra stoi w nieskonczonosc
        # na "Wyszukiwanie gry" (log-36 i log-37: pusty ack i cisza az do zamkniecia gry).
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
        # run-26: "wyszukaj sesje" = leaveGameByGroup + startMatchmaking (MODE 3 = szukaj i utworz);
        # wynik matchmakingu przychodzi notyfikacja. Najpierw szukamy publicznej gry innego gracza
        # (dolaczenie, SUCCESS_JOINED_EXISTING_GAME), a gdy jej nie ma - nowa gra z graczem jako
        # hostem (SUCCESS_CREATED_GAME). --mm-fail: NotifyMatchmakingFailed SESSION_TIMED_OUT (A/B).
        # Adres i nick czytamy TU, w watku polaczenia: sess.addr trafia potem do rosteru, a nick
        # z GNAM ma byc znany, zanim ktokolwiek zobaczy tego gracza. Sama decyzja (ktora gra) idzie
        # na timer - patrz _resolve_matchmaking i --mm-delay.
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
        else:                                           # --mm-delay 0: jak do run-38 wlacznie
            sess.outbox.extend(_resolve_matchmaking(lb, args, sess, msid, req))
        return blaze.build_start_matchmaking_response(fr.seq, msid, msg_type=mt)
    if fr.component == 4 and fr.command == 14:          # GameManager.cancelMatchmaking
        # run-38: leci przy rezygnacji z wyszukiwania i wpadalo w "brak handlera". Przy odlozonej
        # decyzji trzeba ubic timer, inaczej gracz dostalby gre, z ktorej wlasnie zrezygnowal.
        _cancel_matchmaking(sess)
        print(f"  [matchmaking] {sess!r} cancels the search")
        return blaze.build_empty_reply(4, fr.command, fr.seq, msg_type=mt)
    if fr.component == 4 and fr.command in (2, 3, 11, 15, 22, 29, 106, 107):
        # destroyGame, advanceGameState, removePlayer, finalizeGameCreation, leaveGameByGroup,
        # updateMeshConnection, addAdminPlayer, removeAdminPlayer - samo potwierdzenie; skutki
        # (notyfikacje) wysyla _after_reply
        return blaze.build_empty_reply(4, fr.command, fr.seq, msg_type=mt)
    if fr.component == 2050 and fr.command == 20 and not getattr(args, "no_speed_walls", False):
        # NFS.getInGameSpeedWalls: gra pyta o speed wall, gdy podjezdza do fotoradaru, strefy albo
        # eventu (run-25: 46 zapytan o 35 id). Id to ENTI z raportow GameReporting, wiec wiersze
        # bierzemy z zapisanego stanu. --no-speed-walls wraca do pustego potwierdzenia (A/B).
        store = _player_store(args)
        walls = []
        for swid in req.get("SWIS") or []:
            rows = store.rows_for_entity(swid) if store else []
            for r in rows:
                r["persona"] = _lobby(args).persona_of(r["blaze_id"])
            walls.append((int(swid), rows))
            print(f"  [speed wall] {swid}: {len(rows)} row(s)"
                  + (f" {rows[0]['float'] or rows[0]['int']}" if rows else ""))
        return blaze.build_in_game_speed_walls_response(fr.seq, walls, msg_type=mt)
    if fr.component == 9 and fr.command == 20:          # Util.filterForProfanity
        # run-23: TLST [{DIRT 2, UTXT ''}] - puste potwierdzenie oddawalo PUSTA liste, czyli
        # gra dostawala zero wynikow na jeden tekst. Odsylamy kazdy tekst bez zmian.
        texts = []
        for item in req.get("TLST") or []:
            vals = {t.strip(): v for t, _w, v in item} if isinstance(item, list) else {}
            texts.append(str(vals.get("UTXT", "")))
        return blaze.build_filter_profanity_response(fr.seq, texts, msg_type=mt)
    return None


GAME_REPORTING = 28
_REPORTS = {"n": 0}


def _ack_game_report(sess, fr, args) -> None:
    """GameReporting (komponent 28): raporty stanu gry. W run-23 przyszlo ich 429 w ok. 2 min
    jazdy (Collectables, DistanceDriven*, CarCustomization, LicensesPart1/2 ...) i zajmowaly
    95% logu. Klasa zadania @0x141a32ad0 {FNSH mFinishedStatus, PRVT mPrivateReport,
    RPRT mGameReport}; raport siedzi w polu typu variable, ktorego nasz dekoder nie rozklada.
    Odpowiadamy pustym potwierdzeniem, tak jak w run-23 (gra je przyjmuje). Pelna ramka jest w
    capture (blaze-<tag>-NN.bin), wiec w logu zostaje jedna linia z nazwami z raportu."""
    import re
    _REPORTS["n"] += 1
    sess.send(blaze.build_empty_reply(fr.component, fr.command, fr.seq,
                                      msg_type=args.reply_msgtype))
    # Zapis postepu (player_store.py). Blad parsowania/zapisu nie moze zatrzymac gry - ack
    # poszedl wyzej, tu tylko log.
    store = _player_store(args)
    try:
        rep = player_store.parse_game_report(fr.payload)
        stats = sum(len(p[k]) for p in rep["players"].values() for k in ("int", "float", "str"))
        entity = next(iter(rep["players"].values()))["entity"] if rep["players"] else "-"
        desc = f"{rep['category']} ENTI={entity} ({stats} stat.)"
        saved = ""
        if store is not None:
            store.record(rep)
            saved = " [zapis]"
    except Exception as e:                              # noqa: BLE001
        words = [m.decode() for m in re.findall(rb"[A-Za-z][A-Za-z0-9_]{5,}", fr.payload)]
        desc, saved = " ".join(words[:4]), f" [NIE ZAPISANE: {e!r}]"
    print(f"  <- GameReporting 28/{fr.command} #{_REPORTS['n']} seq={fr.seq} "
          f"({len(fr.payload)} B): {desc} -> ack{saved}")


_STORE_LOCK = threading.Lock()
_STORE: dict = {}


def _player_store(args):
    """Wspolny PlayerStore dla wszystkich polaczen; None przy --no-store."""
    if getattr(args, "no_store", False):
        return None
    root = getattr(args, "data_dir", None) or player_store.DATA_DIR
    with _STORE_LOCK:
        if root not in _STORE:
            _STORE[root] = player_store.PlayerStore(root)
        return _STORE[root]


DEFAULT_GAME_NAME = "Gracz"          # gdy zadanie nie niesie GNAM (nazwa gry = nick zalozyciela)
_LOBBY: dict = {}


def _lobby(args) -> lobby.Lobby:
    """Wspolny rejestr graczy i gier (jeden na proces). players.json lezy obok zapisu postepu."""
    with _STORE_LOCK:
        if "lobby" not in _LOBBY:
            root = Path(getattr(args, "data_dir", None) or player_store.DATA_DIR)
            forced = dict(p.split("=", 1) for p in (getattr(args, "player", None) or []) if "=" in p)
            _LOBBY["lobby"] = lobby.Lobby(
                root / "players.json", forced,
                player_state_notify=getattr(args, "player_state_notify", True),
                local_id=getattr(args, "local_id", 0),
                local_persona=getattr(args, "local_persona", ""))
        return _LOBBY["lobby"]


def _public_ip(args) -> str:
    """Adres tego komputera widziany z innego komputera w sieci: --public-ip albo wykryty LAN."""
    ip = getattr(args, "public_ip", None)
    if not ip:
        ip = _detect_lan_ip()
        args.public_ip = ip
    return ip


def _detect_lan_ip() -> str:
    """Glowny adres IPv4 w sieci lokalnej. connect() gniazda UDP nie wysyla pakietu - system tylko
    wybiera interfejs z trasa domyslna i jego adres."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _client_facing_ip(sess, args) -> str:
    """Adres serwera dla tego klienta: gracz lokalny 127.0.0.1, inny komputer - adres w sieci."""
    if sess is None or sess.is_local:
        return args.redirect_ip
    return _public_ip(args)


def _req_fields(fr) -> dict:
    """Pola najwyzszego poziomu zadania klienta: tag (bez spacji) -> wartosc."""
    if not fr.payload:
        return {}
    try:
        return {tag.strip(): val for tag, _wtype, val in blaze.decode_tdf(fr.payload)}
    except Exception:                                   # noqa: BLE001
        return {}


# --- Odczyt pojedynczych pol z SUROWEGO zadania. Nasz dekoder nie rozklada calego
#     createGame (lista unii HNET, typy variable), a potrzebujemy tylko kilku wartosci.
#     Szukamy bajtow "tag + typ" - dla tych pol w createGame trafienia sa jednoznaczne.
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
    """(exip, export, inip, inport, maci) ze zdekodowanej unii NetworkAddress wariant 2 (IpPair
    {EXIP{IP MACI PORT} INIP{..} MACI}): PNET w startMatchmaking, ADDR w updateNetworkInfo.
    None, gdy uklad jest inny."""
    try:
        _union, _variant, (_tag, _wtype, fields) = u
        f = {t.strip(): v for t, _w, v in fields}
        ex = {t.strip(): v for t, _w, v in f["EXIP"]}
        inn = {t.strip(): v for t, _w, v in f["INIP"]}
        return ex["IP"], ex["PORT"], inn["IP"], inn["PORT"], f.get("MACI", 0)
    except (KeyError, TypeError, ValueError):
        return None


def _objid_uid(v) -> int:
    """uid z ObjectId (0x7802, 2, uid) - SCG/TCG w updateMeshConnection."""
    return int(v[2]) if isinstance(v, tuple) and len(v) == 3 else 0


def _create_game_params(p: bytes) -> dict:
    """Parametry gry z SUROWEGO zadania createGame (nasz dekoder nie rozklada HNET)."""
    cap = _raw_list_int(p, "PCAP", [6, 0, 0, 0])
    # resetDedicatedServer przysyla PMAX=0, a pojemnosc wylacznie w PCAP ([6,0,0,0]) - gdy PMAX
    # jest zerowy, bierzemy sume miejsc, inaczej gra dostaje MCAP=0 i nie ma gdzie wejsc.
    return dict(game_name=_raw_str(p, "GNAM", DEFAULT_GAME_NAME), game_settings=_raw_int(p, "GSET", 0),
                network_topology=_raw_int(p, "NTOP", 0), presence_mode=_raw_int(p, "PRES", 1),
                voip=_raw_int(p, "VOIP", 0), version_string=_raw_str(p, "VSTR", ""),
                max_players=_raw_int(p, "PMAX", 0) or sum(cap) or 6,
                slot_capacities=cap,
                team_ids=_raw_list_int(p, "TIDS", [65535]), attributes=_raw_map_str(p, "ATTR"))


def _mm_game_params(req: dict) -> dict:
    """Parametry gry tworzonej przez matchmaking - ze zdekodowanego zadania startMatchmaking."""
    pmax = int(req.get("PMAX", 6))
    attrs = {str(k): str(v) for k, v in (req.get("ATTR") or {}).items()}
    # Regula czlonkostwa z kryteriow (RLST: gameMembershipRule = ['Public']) zapisana jako atrybut
    # gry pod nazwa z createGame (gameMembershipRequirements) - po nim drugi gracz szukajacy gry
    # publicznej ja znajduje (Lobby.find_public_game). Nazwa atrybutu przyjeta z createGame.
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
    """NotifyGameSetup gry z rejestru: roster wszystkich graczy, adres hosta, biezacy stan gry."""
    roster = lb.roster(g)
    host_addr = next((p["addr"] for p in roster if p["uid"] == g.host_uid), lobby.DEFAULT_ADDR)
    return blaze.build_notify_game_setup(g.gid, g.host_uid, roster, host_addr=host_addr,
                                         game_state=g.state, setup_context=setup_context, **g.params)


def _resolve_matchmaking(lb, args, sess, msid, req) -> list:
    """Decyzja matchmakingu wraz z notyfikacjami, jako lista (sesja, ramka).

    Najpierw szukamy publicznej gry innego gracza (SUCCESS_JOINED_EXISTING_GAME), a gdy jej nie ma -
    nowa gra z graczem jako hostem (SUCCESS_CREATED_GAME). --mm-fail: NotifyMatchmakingFailed.

    Do run-38 decyzja zapadala synchronicznie, w chwili zadania - i to ja wywracalo. Gdy gracz
    wychodzi z garazu do swiata, klient wysyla startMatchmaking, a removePlayer dla starej gry
    dopiero KLATKE pozniej (log-38: seq=95 i seq=96). Gracz byl wiec nadal czlonkiem tamtej gry,
    find_public_game pomijalo ja przez `sess.uid not in g.players` i serwer tworzyl nowa zamiast
    wpuscic go z powrotem. Prawdziwy Blaze oddaje wynik notyfikacja po DUR z zadania, wiec widzi
    juz wykonane wyjscie - stad odroczenie (--mm-delay)."""
    if getattr(args, "mm_fail", False):
        print(f"  [matchmaking] session {msid} -> NotifyMatchmakingFailed SESSION_TIMED_OUT (--mm-fail)")
        return [(sess, blaze.build_notify_matchmaking_failed(
            msid, sess.uid, blaze.MATCHMAKING_RESULT["SESSION_TIMED_OUT"]))]
    crit = {t.strip(): v for t, _w, v in (req.get("CRIT") or [])}
    agam = {t.strip(): v for t, _w, v in (crit.get("AGAM") or [])}
    g = lb.find_public_game(sess, {int(x) for x in (agam.get("GIDL") or [])})
    if g is None:
        g = lb.create_game(sess, _mm_game_params(req), getattr(args, "gm_player_state", 4))
        print(f"  [matchmaking] session {msid}, MODE={req.get('MODE')} DUR={req.get('DUR')} ms -> "
              f"new game {g.gid:#x} (SUCCESS_CREATED_GAME)")
        return [(sess, _game_setup(lb, g, (msid, blaze.MATCHMAKING_RESULT["SUCCESS_CREATED_GAME"],
                                           sess.uid)))]
    lb.join(sess, g)
    print(f"  [matchmaking] session {msid}: {sess!r} JOINS game {g.gid:#x} hosted by "
          f"{lb.persona_of(g.host_uid)} (players: {len(g.players)})")
    # Dolaczajacy musi znac pozostalych graczy (UserAdded z ich adresami), zanim dostanie gre
    # z rosterem; gracze juz w grze dostaja UserAdded dolaczajacego i NotifyPlayerJoining.
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
    """Ubija odlozona decyzje, jesli jakas czeka (cancelMatchmaking, kolejne szukanie, rozlaczenie)."""
    t = sess.mm_timer
    if t is not None:
        t.cancel()
        sess.mm_timer = None


def _arm_matchmaking(lb, args, sess, msid, req, delay_ms: int) -> None:
    """Uzbraja timer decyzji matchmakingu. Wysylka z watku-timera jest bezpieczna: Session.notify ma
    wlasna blokade i sekwencje, a _deliver przelyka OSError z zamknietego polaczenia."""
    _cancel_matchmaking(sess)

    def fire():
        if not sess.alive:
            print(f"  [matchmaking] session {msid}: connection closed, not sending the decision")
            return
        try:
            _deliver(sess, _resolve_matchmaking(lb, args, sess, msid, req))
        except Exception as e:      # watek-timer: nieobsluzony wyjatek zginalby po cichu
            print(f"  [matchmaking] session {msid}: decision failed: {e!r}")

    sess.mm_timer = threading.Timer(delay_ms / 1000.0, fire)
    sess.mm_timer.daemon = True
    sess.mm_timer.start()


def _raw_ip_pair(payload: bytes) -> tuple[int, int, int, int, int]:
    """(exip, export, inip, inport, maci) z HNET zadania createGame; domyslnie lokalnie."""
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
    # MACI wewnatrz INIP to 0, wlasciwy MACI pary jest za struktura INIP - bierz ostatnie trafienie
    k = payload.rfind(_enc_tag("MACI") + b"\x00")
    if k >= 0:
        maci = _dec_varint(payload, k + 4)[0]
    return exip, export, inip, inport, maci


def _bytevault_reply(method: str, path: str, body: bytes, args) -> tuple[str, str, bytes]:
    """Odpowiedz ByteVault (REST). Uklad listy rekordow: kandydat {LIST mRecords, TOTL
    mTotalCount} (@0x1416b6748). Klucze JSON NIE sa zapisane w binarce - przyjmujemy nazwy
    pol bez przedrostka m; --bytevault-format heat wysyla ten sam TDF binarnie."""
    fmt = getattr(args, "bytevault_format", "json")
    listing = "/recordinfo" in path or path.split("?")[0].rstrip("/").endswith("/records")
    if fmt == "heat":
        payload = blaze.encode_tdf([blaze.f_list_struct("LIST", []), blaze.f_int("TOTL", 0)]) \
            if listing else b""
        return "200 OK", "application/heat", payload
    return "200 OK", "application/json", (b'{"records":[],"totalCount":0}' if listing else b"{}")


def _serve_http(w, buf: bytearray, args) -> None:
    """Sesja HTTP po TLS na porcie Blaze - tak laczy sie ByteVault (run-22: GET
    /1.0/contexts/nfs-rivals-common/categories/Unlocks/recordinfo?...). Obsluguje kolejne
    zapytania na tym samym polaczeniu (keep-alive) az klient je zamknie."""
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
            print(f"      {ln}")
        if body:
            print(f"      BODY ({len(body)} B): {body[:300]!r}")
        status, ctype, payload = _bytevault_reply(method, path, body, args)
        resp = (f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n"
                f"Content-Length: {len(payload)}\r\n\r\n").encode() + payload
        w.send_record(RT_APPDATA, resp)
        print(f"  -> HTTP {status} {ctype} ({len(payload)} B) {payload[:120]!r}")
        if headers.get("connection", "").lower() == "close":
            # ByteVault wysyla "Connection: Close" i zamyka gniazdo po odpowiedzi; dalsze
            # czekanie na rekord konczylo sie falszywym "blad sesji" w logu (run-23).
            return


def _after_reply(fr, args, sess):
    """Async notyfikacje wysylane PO odpowiedzi: lista (sesja, ramka). Zwykle do tego samego
    gracza, a w multiplayerze takze do innych graczy gry (dolaczenie, wyjscie, mesh). msgId nadaje
    Session.notify - kazda sesja ma wlasna rosnaca sekwencje."""
    lb = _lobby(args)
    out = list(sess.outbox)
    sess.outbox.clear()

    def me(frame):
        out.append((sess, frame))

    if fr.component == 1 and fr.command == 152:         # po loginie
        if args.notify_probe:
            for cmd in range(1, 11):
                me(blaze.build_usersession_update(sess.uid, component=args.notify_comp, command=cmd))
        else:
            # Kolejnosc jak w Blaze po loginie: UserAdded (cmd 2, tworzy usera),
            # ExtendedDataUpdate (cmd 1, dane sesji), UserAuthenticated (cmd 8,
            # sygnal "zalogowany" -> trigger postAuth).
            rich = not args.plain_session_data
            # USER w UserAdded = UserIdentification (ID = BlazeId). Stary uklad z tagami
            # UserSessionLoginInfo dawal usera z ID=0 -> gra nie dostawala onAuthenticated.
            me(blaze.build_useradded_notify(sess.uid, sess.persona, component=args.notify_comp,
                                            command=2, rich_data=rich,
                                            legacy_user=getattr(args, "legacy_user_added", False)))
            me(blaze.build_usersession_update(sess.uid, component=args.notify_comp, command=1,
                                              rich_data=rich))
            # UserAuthenticated z pelnym UserSessionLoginInfo (klasa z binarki
            # @0x141a2f160). Pusty payload dawal BUID=0 i stan online gry nie dochodzil
            # do 9 ("Logowanie"). --empty-user-auth przywraca stary pusty wariant (A/B).
            if args.empty_user_auth:
                me(blaze.build_notification(args.notify_comp, 8, b""))
            else:
                me(blaze.build_user_authenticated_notify(sess.uid, sess.persona,
                                                         component=args.notify_comp, command=8))
    if fr.component == 7 and fr.command == 16:          # Stats.getStatsByGroupAsync
        # Wynik zapytania asynchronicznego przychodzi notyfikacja 7/0x32 z tym samym VID;
        # LAST=1 zamyka widok. Bez niej gra czeka na statystyki bez konca.
        req = _req_fields(fr)
        eids = req.get("EID") or []
        if not isinstance(eids, list):
            eids = [eids]
        me(blaze.build_stats_async_notification(
            int(req.get("VID", 0) or 0), str(req.get("NAME", "")),
            [int(e) for e in eids if isinstance(e, int)]))
    if fr.component == 4 and fr.command in (1, 25) and sess.pending:
        # createGame / resetDedicatedServer: gre utworzyl dispatch. Matchmaking (cmd 13) tu nie
        # trafia - jego decyzja idzie przez _resolve_matchmaking (od razu do outbox przy
        # --mm-delay 0, inaczej z watku-timera).
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
        # Zmiane listy adminow Blaze rozglasza wszystkim graczom gry. log-30: host dodal goscia jako
        # admina 13 ms po polaczeniu mesh (4/106 {GID, PID}), a my odsylalismy samo potwierdzenie.
        req = _req_fields(fr)
        g = lb.game(int(req.get("GID", 0) or 0))
        pid = int(req.get("PID", 0) or 0)
        if g is not None and pid:
            added = fr.command == 106
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
    ap.add_argument("--public-ip", default=None, metavar="IP",
                    help="this machine's address as seen from another machine (multiplayer). "
                         "Defaults to the detected LAN address. QoS reports it to the local "
                         "player as the external address so others can connect; 127.0.0.1 = "
                         "old behaviour")
    ap.add_argument("--local-id", type=int, default=0, metavar="UID",
                    help="uid of the player at the server; by default assigned once at first "
                         "login and stored in players.json. Pass it to adopt progress saved "
                         "earlier under a specific id (stats/<uid>.json)")
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
    ap.add_argument("--mm-delay", type=int, default=0, metavar="MS",
                    help="delay of the matchmaking decision (NotifyGameSetup) in ms; the client "
                         "gets its MSID immediately. Clamped to DUR from the request. 0 "
                         "(default) = synchronous decision. Run-39 showed the client only sends "
                         "removePlayer AFTER the matchmaking result, so waiting has nothing to "
                         "wait for; kept for a client that leaves its game before searching (A/B)")
    ap.add_argument("--no-speed-walls", action="store_true",
                    help="answer NFS.getInGameSpeedWalls (2050/20) with an empty acknowledgement "
                         "instead of saved results (A/B)")
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

    # Nasluch na porcie redirectora ORAZ na porcie Blaze - rozdzielenie pozwala
    # zobaczyc, czy gra faktycznie laczy sie po odpowiedzi getServerInstance.
    ports = [args.port]
    if args.blaze_port != args.port:
        ports.append(args.blaze_port)

    counter, lock = [0], threading.Lock()

    def serve(port: int) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _bind_exclusive(s, port, "redirector/Blaze")
        s.listen(16)
        role = "redirector" if port == args.port else "BLAZE"
        print(f"listening on 0.0.0.0:{port} ({role})")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle,
                             args=(conn, addr, args, args.out, counter, lock,
                                   rsa, cert_der),
                             daemon=True).start()

    def serve_qos(port: int) -> None:
        """Responder QoS po UDP.

        Klient Blaze po preAuth sonduje ping-site'y z QOSS. Wskazujemy je na
        siebie, wiec musimy odpowiadac - bez odpowiedzi test QoS nigdy sie nie
        konczy. Tresc odpowiedzi sklada _qos_probe_reply (gole echo klient
        odrzuca: sciezka latencji wymaga >= 30 B i niesie adres zewnetrzny).
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _bind_exclusive(s, port, "sondy QoS UDP")
        print(f"listening on UDP 0.0.0.0:{port} (QoS probes)")
        n = 0
        while True:
            try:
                data, peer = s.recvfrom(4096)
            except OSError:
                return
            n += 1
            if n <= 8:                      # pierwsze pakiety pokazujemy w calosci
                print(f"\n  [QoS UDP #{n}] {len(data)} B from {peer[0]}:{peer[1]}")
                print(hexdump(data, 64))
            elif n % 25 == 0:
                print(f"  [QoS UDP :{port} #{n}] {len(data)} B from {peer[0]}:{peer[1]}")
            reply = _qos_probe_reply(data, peer, args)
            if n <= 8:
                kind = "latencja" if len(data) == 0x14 else "pasmo"
                print(f"    -> replying {len(reply)} B (probe: {kind})")
                print(hexdump(reply, 64))
            s.sendto(reply, peer)

    def serve_qos_http(port: int) -> None:
        """Sonda QoS po TCP/HTTP.

        DirtySDK odpytuje ping-site takze po HTTP - w binarce sa wzorce URL
        "%s://%s:%u/qos/qos?vers=%d", "/qos/firewall", "/qos/firetype". Dotad
        na porcie QoS sluchalismy WYLACZNIE po UDP, wiec takie polaczenie
        dostawalo odmowe. Logujemy cale zadanie (to pokaze, czego klient chce)
        i odpowiadamy pustym 200, zeby nie zostawiac go z niczym.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _bind_exclusive(s, port, "QoS HTTP")
        s.listen(8)
        print(f"listening on TCP 0.0.0.0:{port} (QoS HTTP)")
        while True:
            try:
                conn, peer = s.accept()
            except OSError:
                return
            try:
                conn.settimeout(5)
                req = conn.recv(4096)
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
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    for p in ports[1:]:
        threading.Thread(target=serve, args=(p,), daemon=True).start()
    if not args.no_qos_responder:
        for i in range(args.qos_interfaces):
            threading.Thread(target=serve_qos, args=(args.qos_port + i,),
                             daemon=True).start()
        threading.Thread(target=serve_qos_http, args=(args.qos_port,), daemon=True).start()
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
        serve(ports[0])
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
