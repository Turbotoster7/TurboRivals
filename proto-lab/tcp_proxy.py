#!/usr/bin/env python3
"""Logujacy proxy TCP miedzy gra a prawdziwym backendem EA.

Odkrycie: redirector EA nadal zyje i odpowiada, mimo ze gra online zostala
wylaczona 2025-10-07 (gra dostaje szybka odmowe, nie timeout). To znaczy,
ze mozemy podejrzec PRAWDZIWA rozmowe klient<->serwer, a nie tylko to,
co wysyla klient.

Handshake SSL leci otwartym tekstem, wiec bez lamania czegokolwiek
dostajemy:
  - wersje SSL i liste szyfrow oferowanych przez gre,
  - szyfr wybrany przez EA,
  - oryginalny certyfikat serwera EA (do sklonowania).

Uzycie (hosts musi kierowac hosta na 127.0.0.1):
    python proto-lab/tcp_proxy.py --upstream 159.153.51.18 --port 42127

Uwaga: upstream podajemy ADRESEM IP, nie nazwa - nazwa wrocilaby przez
hosts na nas samych i zrobilaby petle.
"""

from __future__ import annotations

import argparse
import datetime as dt
import socket
import struct
import threading
from pathlib import Path

VERSIONS = {
    0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}

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

RECORD_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake",
                23: "ApplicationData"}
HANDSHAKE_TYPES = {0: "HelloRequest", 1: "ClientHello", 2: "ServerHello",
                   11: "Certificate", 12: "ServerKeyExchange",
                   13: "CertificateRequest", 14: "ServerHelloDone",
                   15: "CertificateVerify", 16: "ClientKeyExchange",
                   20: "Finished"}

ALERT_DESC = {0: "close_notify", 10: "unexpected_message",
              20: "bad_record_mac", 40: "handshake_failure",
              42: "bad_certificate", 46: "certificate_unknown",
              47: "illegal_parameter", 48: "unknown_ca",
              49: "access_denied", 50: "decode_error", 51: "decrypt_error",
              70: "protocol_version", 71: "insufficient_security",
              80: "internal_error", 90: "user_canceled"}


def hexdump(data: bytes, limit: int = 256) -> str:
    out = []
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        out.append(f"  {i:08x}  {hexs:<47}  {text}")
    if len(data) > limit:
        out.append(f"  ... (+{len(data) - limit} bajtow)")
    return "\n".join(out)


def parse_records(stream: bytes, out_dir: Path, tag: str, side: str) -> list[str]:
    """Rozbiera strumien na rekordy SSL. Zapisuje napotkane certyfikaty."""
    info: list[str] = []
    pos = 0
    cert_no = 0
    while pos + 5 <= len(stream):
        rtype = stream[pos]
        ver = struct.unpack_from(">H", stream, pos + 1)[0]
        rlen = struct.unpack_from(">H", stream, pos + 3)[0]
        body = stream[pos + 5:pos + 5 + rlen]
        if len(body) < rlen:
            info.append(f"  [rekord uciety: typ {rtype}, deklarowane {rlen} B]")
            break
        name = RECORD_TYPES.get(rtype, f"typ {rtype}")
        info.append(f"  rekord {name}, {VERSIONS.get(ver, hex(ver))}, {rlen} B")

        if rtype == 21 and len(body) >= 2:
            level = "fatal" if body[0] == 2 else "warning"
            info.append(f"    ALERT {level}: "
                        f"{ALERT_DESC.get(body[1], body[1])}")

        if rtype == 22:
            info += parse_handshake(body, out_dir, tag, side, cert_no)
            cert_no += 1

        pos += 5 + rlen
    if pos < len(stream):
        info.append(f"  [pozostalo {len(stream) - pos} B poza rekordami]")
    return info


def parse_handshake(body: bytes, out_dir: Path, tag: str, side: str,
                    cert_no: int) -> list[str]:
    info: list[str] = []
    pos = 0
    while pos + 4 <= len(body):
        htype = body[pos]
        hlen = int.from_bytes(body[pos + 1:pos + 4], "big")
        msg = body[pos + 4:pos + 4 + hlen]
        hname = HANDSHAKE_TYPES.get(htype, f"typ {htype}")
        info.append(f"    handshake: {hname} ({hlen} B)")

        if htype == 1 and len(msg) >= 34:          # ClientHello
            cver = struct.unpack_from(">H", msg, 0)[0]
            info.append(f"      wersja klienta: {VERSIONS.get(cver, hex(cver))}")
            p = 2 + 32
            sid_len = msg[p]; p += 1 + sid_len
            if p + 2 <= len(msg):
                cs_len = struct.unpack_from(">H", msg, p)[0]; p += 2
                suites = [struct.unpack_from(">H", msg, p + i)[0]
                          for i in range(0, min(cs_len, len(msg) - p), 2)]
                info.append(f"      oferowane szyfry ({len(suites)}):")
                for cs in suites:
                    info.append(f"        - {CIPHERS.get(cs, f'0x{cs:04x}')}")

        elif htype == 2 and len(msg) >= 35:        # ServerHello
            sver = struct.unpack_from(">H", msg, 0)[0]
            p = 2 + 32
            sid_len = msg[p]; p += 1 + sid_len
            if p + 2 <= len(msg):
                cs = struct.unpack_from(">H", msg, p)[0]
                info.append(f"      wersja serwera: {VERSIONS.get(sver, hex(sver))}")
                info.append(f"      WYBRANY SZYFR: {CIPHERS.get(cs, f'0x{cs:04x}')}")

        elif htype == 11:                          # Certificate
            p = 3                                   # dlugosc calego lancucha
            n = 0
            while p + 3 <= len(msg):
                clen = int.from_bytes(msg[p:p + 3], "big")
                der = msg[p + 3:p + 3 + clen]
                if not der:
                    break
                path = out_dir / f"{tag}-{side}-cert{n}.der"
                path.write_bytes(der)
                info.append(f"      certyfikat #{n}: {clen} B -> {path.name}")
                p += 3 + clen
                n += 1

        pos += 4 + hlen
    return info


def pump(src: socket.socket, dst: socket.socket, sink: list[bytes],
        label: str, quiet: bool) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            sink.append(data)
            if not quiet:
                print(f"  {label} {len(data)} B")
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(conn: socket.socket, addr, args, out_dir: Path,
           counter: list[int], lock: threading.Lock) -> None:
    with lock:
        counter[0] += 1
        n = counter[0]
    tag = f"{dt.datetime.now():%H%M%S}-{n:03d}"
    print(f"\n=== [{tag}] {addr[0]}:{addr[1]} -> {args.upstream}:{args.upstream_port} ===")

    try:
        up = socket.create_connection((args.upstream, args.upstream_port), timeout=10)
    except OSError as e:
        print(f"  nie moge polaczyc sie z upstreamem: {e}")
        conn.close()
        return

    c2s: list[bytes] = []
    s2c: list[bytes] = []
    t1 = threading.Thread(target=pump, args=(conn, up, c2s, "gra   ->", args.quiet))
    t2 = threading.Thread(target=pump, args=(up, conn, s2c, "EA    ->", args.quiet))
    t1.start(); t2.start()
    t1.join(); t2.join()
    conn.close(); up.close()

    out_dir.mkdir(parents=True, exist_ok=True)
    cs, sc = b"".join(c2s), b"".join(s2c)
    (out_dir / f"{tag}-c2s.bin").write_bytes(cs)
    (out_dir / f"{tag}-s2c.bin").write_bytes(sc)

    lines = [f"# sesja {tag}",
             f"gra -> EA: {len(cs)} B    EA -> gra: {len(sc)} B", ""]
    lines.append("## gra -> EA")
    lines += parse_records(cs, out_dir, tag, "client")
    lines += ["", "## EA -> gra"]
    lines += parse_records(sc, out_dir, tag, "server")
    lines += ["", "## hexdump gra -> EA", hexdump(cs, 512),
              "", "## hexdump EA -> gra", hexdump(sc, 512)]
    report = "\n".join(lines)
    (out_dir / f"{tag}.txt").write_text(report, encoding="utf-8")

    print(f"  gra -> EA: {len(cs)} B, EA -> gra: {len(sc)} B")
    for line in lines[2:]:
        if line.startswith("## hexdump"):
            break
        print(line)
    print(f"  -> {out_dir / (tag + '.txt')}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--upstream", required=True,
                    help="IP prawdziwego serwera EA (nie nazwa!)")
    ap.add_argument("--upstream-port", type=int, default=None,
                    help="port docelowy (domyslnie taki jak --port)")
    ap.add_argument("-p", "--port", type=int, default=42127,
                    help="port lokalnego nasluchu")
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon/capture"))
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()
    if args.upstream_port is None:
        args.upstream_port = args.port

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", args.port))
    s.listen(16)
    print(f"proxy 0.0.0.0:{args.port} -> {args.upstream}:{args.upstream_port}")
    print("czekam na gre. Ctrl+C konczy.\n")

    counter, lock = [0], threading.Lock()
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle,
                             args=(conn, addr, args, args.out, counter, lock),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\nkoniec")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
