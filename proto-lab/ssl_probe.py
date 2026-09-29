#!/usr/bin/env python3
"""SSL probe of the EA redirector - which version and which ciphers.

The EA redirector still answers even though the game's online is shut down,
so we do not have to wait for the client to learn the SSL parameters. We send
a hand-built ClientHello (the `ssl` module can no longer do SSLv3) and look at
what the server answers.

Answers open questions no. 2 and 3 from docs/protocol.md:
  - is it SSLv3 or a newer TLS,
  - which cipher the server picks,
  - what the original certificate looks like (to clone it).

Usage:
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

# RC4 first - that is the cipher ProtoSSL used in this era.
OFFERED = [0x0005, 0x0004, 0x000A, 0x002F, 0x0035, 0x003C, 0x009C,
           0xC013, 0xC014, 0xC02F]


def build_client_hello(version: int, sni: str | None) -> bytes:
    body = struct.pack(">H", version)
    body += struct.pack(">I", int(time.time())) + os.urandom(28)
    body += b"\x00"                                     # no session id
    body += struct.pack(">H", len(OFFERED) * 2)
    body += b"".join(struct.pack(">H", c) for c in OFFERED)
    body += b"\x01\x00"                                 # compression: none

    # SSLv3 has no extensions; for TLS we add SNI, because EA may
    # host several services behind one address.
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
        print(f"  cannot connect: {e}")
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
        print(f"  transmission error: {e}")
    finally:
        s.close()

    resp = b"".join(chunks)
    if not resp:
        print("  the server sent nothing back (connection accepted and closed)")
        return

    print(f"  response: {len(resp)} B")
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
