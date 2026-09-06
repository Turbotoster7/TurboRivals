#!/usr/bin/env python3
"""Pasywny nasluch na portach backendu EA - pierwszy kontakt z klientem.

Serwery EA sa martwe od 2025-10-07, wiec nie da sie nagrac ruchu
serwer->klient. Zaczynamy wiec od drugiej strony: przekierowujemy
hostname na siebie i patrzymy, co gra wysyla.

Ten skrypt niczego nie udaje - tylko przyjmuje polaczenie, zrzuca bajty
na dysk i rozbiera pierwszy rekord SSL/TLS. Odpowiedz na kluczowe
pytanie fazy 1: czy klient mowi SSLv3 i jakie oferuje szyfry (od tego
zalezy, czy zadziala minimalna implementacja SSLv3 z RC4).

Uzycie:
    python proto-lab/tcp_tap.py                 # port 42127
    python proto-lab/tcp_tap.py -p 42127 443 44125
"""

from __future__ import annotations

import argparse
import datetime as dt
import socket
import struct
import threading
from pathlib import Path

# Szyfry istotne dla ProtoSSL. EA w tej epoce korzystalo praktycznie
# wylacznie z RC4-SHA, co jest dobra wiadomoscia - to najprostszy
# do zaimplementowania zestaw.
CIPHERS = {
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
}

VERSIONS = {
    0x0002: "SSLv2",
    0x0300: "SSLv3",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def hexdump(data: bytes, limit: int = 512) -> str:
    out = []
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        out.append(f"  {i:08x}  {hexs:<47}  {text}")
    if len(data) > limit:
        out.append(f"  ... (+{len(data) - limit} bajtow)")
    return "\n".join(out)


def parse_client_hello(data: bytes) -> list[str]:
    """Rozbiera ClientHello. Obsluguje tez stary format SSLv2."""
    info: list[str] = []
    if len(data) < 5:
        return ["(za malo danych na rekord SSL)"]

    if data[0] & 0x80:
        info.append("format rekordu: SSLv2 (przestarzaly ClientHello)")
        return info

    if data[0] != 0x16:
        info.append(f"pierwszy bajt = {data[0]:#04x} - to nie jest handshake SSL/TLS")
        return info

    rec_ver = struct.unpack_from(">H", data, 1)[0]
    info.append(f"wersja rekordu:  {VERSIONS.get(rec_ver, hex(rec_ver))}")

    if len(data) < 11 or data[5] != 0x01:
        info.append("(brak pelnego ClientHello)")
        return info

    hello_ver = struct.unpack_from(">H", data, 9)[0]
    info.append(f"wersja klienta:  {VERSIONS.get(hello_ver, hex(hello_ver))}")

    pos = 11 + 32                       # po random
    if pos >= len(data):
        return info
    sid_len = data[pos]
    pos += 1 + sid_len
    if pos + 2 > len(data):
        return info
    cs_len = struct.unpack_from(">H", data, pos)[0]
    pos += 2
    suites = []
    for i in range(0, min(cs_len, len(data) - pos), 2):
        cs = struct.unpack_from(">H", data, pos + i)[0]
        suites.append(CIPHERS.get(cs, f"0x{cs:04x}"))
    info.append(f"szyfrow:         {len(suites)}")
    for s in suites:
        info.append(f"  - {s}")
    return info


def handle(conn: socket.socket, addr, port: int, out_dir: Path, counter: list[int],
           lock: threading.Lock) -> None:
    with lock:
        counter[0] += 1
        n = counter[0]
    stamp = dt.datetime.now().strftime("%H%M%S")
    tag = f"{stamp}-p{port}-{n:03d}"
    print(f"\n=== [{tag}] polaczenie z {addr[0]}:{addr[1]} na porcie {port} ===")

    conn.settimeout(10.0)
    chunks: list[bytes] = []
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            chunks.append(data)
            # Klient czeka na odpowiedz, wiec po pierwszym bloku i tak nic
            # wiecej nie przyjdzie. Nie zamykamy od razu - dajemy szanse
            # na doslanie reszty rekordu.
            if len(b"".join(chunks)) > 8192:
                break
    except socket.timeout:
        pass
    except OSError:
        pass
    finally:
        conn.close()

    blob = b"".join(chunks)
    if not blob:
        print("  klient nic nie wyslal (samo nawiazanie TCP)")
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{tag}.bin").write_bytes(blob)

    lines = [f"# capture {tag}", f"peer: {addr[0]}:{addr[1]}  port: {port}",
             f"bajtow: {len(blob)}", "", "## ClientHello"]
    lines += parse_client_hello(blob)
    lines += ["", "## hexdump", hexdump(blob, limit=2048)]
    (out_dir / f"{tag}.txt").write_text("\n".join(lines), encoding="utf-8")

    print(f"  odebrano {len(blob)} bajtow -> {out_dir / (tag + '.bin')}")
    for line in parse_client_hello(blob):
        print(f"  {line}")
    print(hexdump(blob, limit=128))


def serve(port: int, out_dir: Path, counter: list[int], lock: threading.Lock) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError as e:
        print(f"nie moge nasluchiwac na {port}: {e}")
        return
    s.listen(16)
    print(f"nasluch na 0.0.0.0:{port}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle,
                         args=(conn, addr, port, out_dir, counter, lock),
                         daemon=True).start()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-p", "--ports", type=int, nargs="+", default=[42127],
                    help="porty do nasluchu (domyslnie 42127 - redirector Blaze)")
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon/capture"))
    args = ap.parse_args()

    counter, lock = [0], threading.Lock()
    for port in args.ports:
        threading.Thread(target=serve, args=(port, args.out, counter, lock),
                         daemon=True).start()

    print("czekam na polaczenia. Ctrl+C konczy.\n")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nkoniec")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
