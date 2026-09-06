#!/usr/bin/env python3
"""Serwer zastepczy terminujacy TLS - pierwszy odszyfrowany pakiet Blaze.

Tor A pokazal, ze zywy klient NFS Rivals laczy sie z redirectorem przez `hosts`
i po handshake od razu wysyla zaszyfrowany ApplicationData (pierwszy pakiet
Blaze), ktorego pasywne proxy nie odczyta. Ten serwer prowadzi wlasny handshake,
przedstawia cert zastepczy (patchowany bugiem ProtoSSL - patrz make_stub_cert.py),
odszyfrowuje premaster wlasnym kluczem prywatnym i wypisuje ladunek OTWARTYM
TEKSTEM. To most do pierwszego czytelnego naglowka Fire/Fire2 + TDF.

Parametry handshake (z docs/protocol.md, Tor A i sondy):
  - wersja negocjowana: TLS 1.1 (0x0302),
  - wymiana kluczy: RSA (klient szyfruje premaster naszym kluczem publicznym),
  - szyfr: TLS_RSA_WITH_RC4_128_SHA (0x0005) - jest na liscie klienta; wybieramy
    RC4, bo bez IV/paddingu ochrona rekordow jest trywialna (prosciej niz AES-CBC).
  - kryptografia TLS 1.0/1.1: PRF = P_MD5 XOR P_SHA1, MAC = HMAC-SHA1.

Bez zaleznosci zewnetrznych: RSA-decrypt i RC4 sa czysto w Pythonie (spojnie z
reszta proto-lab, ktora recznie sklada TLS). Klucz (n, d) wyciagamy raz na
starcie przez `openssl rsa -text`. `cryptography` nie jest wymagane.

Uzycie (hosts kieruje gosredirector.online.ea.com -> 127.0.0.1):
    python proto-lab/make_stub_cert.py          # raz, generuje pki/
    python proto-lab/tls_terminator.py           # potem uruchom i wystartuj gre
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
            raise SystemExit(f"nie znalazlem pola '{field}' w openssl rsa -text")
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
        raise ValueError("nie znalazlem separatora paddingu")
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
        frag = self._recv_exact(rlen)
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
            print(f"    [!] zly MAC rekordu (seq {self.rx_seq}) - "
                  f"kontynuuje, to diagnostyka")
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
    print(f"\n=== [{tag}] klient {addr[0]}:{addr[1]} ===")

    w = Wire(conn)
    transcript = b""                                  # wiadomosci handshake (z naglowkami)
    try:
        # 1. ClientHello
        rtype, ver, ch = w.recv_record()
        if rtype != RT_HANDSHAKE or not ch or ch[0] != HS_CLIENT_HELLO:
            print(f"  spodziewalem sie ClientHello, dostalem typ {rtype}")
            return
        transcript += ch
        # NIE odbijamy wersji rekordu klienta (0x0300 z ClientHello) - zywy serwer
        # odpowiadal 0x0302 na wszystkim (patrz komentarz w Wire). record_version
        # zostaje VER_TLS11.
        client_random, suites = parse_client_hello(ch)
        print(f"  ClientHello: rekord {hex(ver)}, {len(suites)} szyfrow"
              f"{' (RC4_SHA obecny)' if CIPHER_RC4_SHA in suites else ' (!) brak RC4_SHA'}")

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
            print("  [!] klient zerwal polaczenie tuz po Certificate (RST, bez "
                  "Alertu) - najpewniej ODRZUCIL cert. Sprawdz issuer leafa: "
                  "musi byc DN OTG3 (make_stub_cert.py).")
            raise
        if rtype != RT_HANDSHAKE or not cke or cke[0] != HS_CLIENT_KEY_EXCHANGE:
            print(f"  spodziewalem sie ClientKeyExchange, dostalem typ {rtype}")
            _drain_alert(rtype, cke)
            return
        transcript += cke
        enc = cke[4:]                                 # cialo CKE
        enc = enc[2:] if len(enc) > (rsa[2]) else enc  # zdejmij 2B dlugosci (TLS)
        pre_master = rsa_decrypt_pkcs1(enc, *rsa)
        print(f"  ClientKeyExchange: premaster {len(pre_master)} B, "
              f"wersja w premaster {pre_master[:2].hex()}")

        master, cmac, smac, ckey, skey = derive_keys(
            pre_master, client_random, server_random)

        # 6-7. ChangeCipherSpec + Finished klienta
        rtype, ver, ccs = w.recv_record()
        if rtype != RT_CCS:
            print(f"  spodziewalem sie ChangeCipherSpec, dostalem typ {rtype}")
            _drain_alert(rtype, ccs)
            return
        w.activate_read(RC4(ckey), cmac)              # od teraz klient szyfruje
        rtype, ver, fin = w.recv_record()
        if rtype != RT_HANDSHAKE or not fin or fin[0] != HS_FINISHED:
            print(f"  spodziewalem sie Finished, dostalem typ {rtype}")
            return
        want = finished_verify(master, b"client finished", transcript)
        got = fin[4:16]
        print(f"  Finished klienta: verify_data {'OK' if got == want else 'ROZNI SIE'}")
        transcript += fin                             # do Finished serwera

        # 8. ChangeCipherSpec + Finished serwera
        w.send_record(RT_CCS, b"\x01")
        w.activate_write(RC4(skey), smac)
        sfin = hs_msg(HS_FINISHED, finished_verify(master, b"server finished", transcript))
        w.send_record(RT_HANDSHAKE, sfin)
        print("  -> ChangeCipherSpec + Finished serwera")

        # 9. Pierwszy ApplicationData = pierwszy pakiet Blaze otwartym tekstem
        rtype, ver, app = w.recv_record()
        while rtype == RT_HANDSHAKE:                  # ignoruj ewentualne powtorki
            rtype, ver, app = w.recv_record()
        if rtype != RT_APPDATA:
            print(f"  po handshake dostalem typ {rtype}, nie ApplicationData")
            _drain_alert(rtype, app)
            return

        out_dir.mkdir(parents=True, exist_ok=True)
        blob = out_dir / f"blaze-first-{tag}.bin"
        blob.write_bytes(app)
        print(f"\n  *** PIERWSZY PAKIET BLAZE (cleartext): {len(app)} B -> {blob.name}")
        print(hexdump(app, 512))

        # 10. Odpowiedz na Redirector.getServerInstance (comp 5, cmd 1) - kieruj
        #     gre z powrotem na nas, zeby wyslala kolejny pakiet (preAuth/auth).
        #     DRAFT schematu odpowiedzi - patrz blaze.build_getserverinstance_response.
        try:
            fr = blaze.Fire2.decode(app)
            print(f"  Fire2: component={fr.component} command={fr.command} "
                  f"error={fr.error} seq={fr.seq} payload={len(fr.payload)}B")
            if fr.component == 5 and fr.command == 1:
                resp = blaze.build_getserverinstance_response(
                    args.redirect_ip, args.redirect_port, seq=fr.seq)
                w.send_record(RT_APPDATA, resp)
                print(f"  -> odpowiedz getServerInstance ({len(resp)} B) -> "
                      f"{args.redirect_ip}:{args.redirect_port} [DRAFT]")
            else:
                print(f"  (nieoczekiwany component/command - nie odpowiadam)")
        except Exception as e:                        # noqa: BLE001 - diagnostyka
            print(f"  [!] nie zbudowalem/nie wyslalem odpowiedzi: {e}")

        # zbierz reakcje klienta (kolejne pakiety albo Alert/rozlaczenie)
        extra = []
        conn.settimeout(5)
        try:
            while True:
                rtype, ver, more = w.recv_record()
                if rtype == RT_APPDATA:
                    extra.append(more)
                    print(f"  + reakcja klienta: ApplicationData {len(more)} B")
                    print(hexdump(more, 256))
                elif rtype == RT_ALERT:
                    _drain_alert(rtype, more)
                    break
        except socket.timeout:
            print("  (brak dalszych pakietow w tej sesji - koniec 5 s okna)")
        except ConnectionError:
            print("  (klient zamknal to polaczenie)")
        if extra:
            (out_dir / f"blaze-first-{tag}-rest.bin").write_bytes(b"".join(extra))

    except (ConnectionError, ValueError, struct.error) as e:
        print(f"  blad sesji: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


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
                    help="cert DER (patchowany OID); domyslnie pki/server.der")
    ap.add_argument("--key", type=Path, default=pki / "server.key")
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon/capture"))
    ap.add_argument("--redirect-ip", default="127.0.0.1",
                    help="adres, ktory oddajemy w odpowiedzi getServerInstance "
                         "(domyslnie my sami, by klient wrocil po kolejny pakiet)")
    ap.add_argument("--redirect-port", type=int, default=None,
                    help="port w odpowiedzi getServerInstance (domyslnie = --port)")
    args = ap.parse_args()

    if args.redirect_port is None:
        args.redirect_port = args.port

    if not args.cert.exists() or not args.key.exists():
        sys.stderr.write("brak pki/ - uruchom najpierw make_stub_cert.py\n")
        return 1

    cert_der = args.cert.read_bytes()
    rsa = load_rsa_priv(args.key)
    print(f"klucz RSA zaladowany ({rsa[2] * 8} bit), cert {len(cert_der)} B")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", args.port))
    s.listen(16)
    print(f"terminator 0.0.0.0:{args.port} - czekam na klienta. Ctrl+C konczy.\n")

    counter, lock = [0], threading.Lock()
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle,
                             args=(conn, addr, args, args.out, counter, lock,
                                   rsa, cert_der),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\nkoniec")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
