#!/usr/bin/env python3
"""Sonda SSL redirectora EA - jaka wersja i jakie szyfry.

Redirector EA nadal odpowiada mimo wylaczenia gry online, wiec nie musimy
czekac na klienta, zeby poznac parametry SSL. Wysylamy wlasnorecznie
sklecony ClientHello (biblioteka `ssl` nie zrobi juz SSLv3) i patrzymy,
co odpowie serwer.

Odpowiada na pytania otwarte nr 2 i 3 z docs/protocol.md:
  - czy to SSLv3, czy nowszy TLS,
  - jaki szyfr wybiera serwer,
  - jak wyglada oryginalny certyfikat (do sklonowania).

Uzycie:
    python proto-lab/ssl_probe.py --host 159.153.51.18 --port 42127
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from tcp_proxy import parse_records  # noqa: E402

VERSION_IDS = {"sslv3": 0x0300, "tls1.0": 0x0301, "tls1.1": 0x0302,
               "tls1.2": 0x0303}

# RC4 na poczatku - to szyfr, ktorego uzywalo ProtoSSL w tej epoce.
OFFERED = [0x0005, 0x0004, 0x000A, 0x002F, 0x0035, 0x003C, 0x009C,
           0xC013, 0xC014, 0xC02F]


def build_client_hello(version: int, sni: str | None) -> bytes:
    body = struct.pack(">H", version)
    body += struct.pack(">I", int(time.time())) + os.urandom(28)
    body += b"\x00"                                     # brak session id
    body += struct.pack(">H", len(OFFERED) * 2)
    body += b"".join(struct.pack(">H", c) for c in OFFERED)
    body += b"\x01\x00"                                 # kompresja: brak

    # SSLv3 nie zna rozszerzen; dla TLS dodajemy SNI, bo EA moze
    # hostowac kilka uslug pod jednym adresem.
    if version >= 0x0301 and sni:
        host = sni.encode("ascii")
        server_name = b"\x00" + struct.pack(">H", len(host)) + host
        sni_ext = struct.pack(">H", len(server_name)) + server_name
        ext = struct.pack(">HH", 0x0000, len(sni_ext)) + sni_ext
        body += struct.pack(">H", len(ext)) + ext

    msg = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack(">H", version) + struct.pack(">H", len(msg)) + msg


def probe(host: str, port: int, version_name: str, sni: str | None,
          out_dir: Path) -> None:
    version = VERSION_IDS[version_name]
    print(f"\n=== {version_name.upper()} -> {host}:{port} ===")
    hello = build_client_hello(version, sni)

    try:
        s = socket.create_connection((host, port), timeout=8)
    except OSError as e:
        print(f"  nie moge sie polaczyc: {e}")
        return

    s.settimeout(8)
    chunks: list[bytes] = []
    try:
        s.sendall(hello)
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
            if len(b"".join(chunks)) > 32768:
                break
    except socket.timeout:
        pass
    except OSError as e:
        print(f"  blad transmisji: {e}")
    finally:
        s.close()

    resp = b"".join(chunks)
    if not resp:
        print("  serwer nic nie odpowiedzial (polaczenie przyjete i zamkniete)")
        return

    print(f"  odpowiedz: {len(resp)} B")
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = f"probe-{version_name.replace('.', '')}"
    (out_dir / f"{tag}.bin").write_bytes(resp)
    for line in parse_records(resp, out_dir, tag, "server"):
        print(line)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="159.153.51.18")
    ap.add_argument("--port", type=int, default=42127)
    ap.add_argument("--sni", default="gosredirector.ea.com")
    ap.add_argument("--versions", nargs="+", default=["sslv3", "tls1.0", "tls1.2"],
                    choices=list(VERSION_IDS))
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon/capture"))
    args = ap.parse_args()

    for v in args.versions:
        probe(args.host, args.port, v, args.sni, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
