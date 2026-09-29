#!/usr/bin/env python3
"""Passive listener on the EA backend ports - first contact with the client.

The EA servers have been dead since 2025-10-07, so server->client traffic
cannot be recorded. So we start from the other side: we redirect the
hostname to ourselves and look at what the game sends.

This script does not pretend to be anything - it just accepts the connection,
dumps the bytes to disk and parses the first SSL/TLS record. It answers the key
question of phase 1: does the client speak SSLv3 and which ciphers does it offer
(that decides whether a minimal SSLv3 implementation with RC4 will work).

Usage:
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

# Ciphers relevant to ProtoSSL. In this era EA used practically nothing
# but RC4-SHA, which is good news - it is the simplest suite
# to implement.
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
        out.append(f"  ... (+{len(data) - limit} bytes)")
    return "\n".join(out)


def parse_client_hello(data: bytes) -> list[str]:
    """Parses a ClientHello. Also handles the old SSLv2 format."""
    info: list[str] = []
    if len(data) < 5:
        return ["(not enough data for an SSL record)"]

    if data[0] & 0x80:
        info.append("record format: SSLv2 (obsolete ClientHello)")
        return info

    if data[0] != 0x16:
        info.append(f"first byte = {data[0]:#04x} - this is not an SSL/TLS handshake")
        return info

    rec_ver = struct.unpack_from(">H", data, 1)[0]
    info.append(f"record version:  {VERSIONS.get(rec_ver, hex(rec_ver))}")

    if len(data) < 11 or data[5] != 0x01:
        info.append("(no complete ClientHello)")
        return info

    hello_ver = struct.unpack_from(">H", data, 9)[0]
    info.append(f"client version:  {VERSIONS.get(hello_ver, hex(hello_ver))}")

    pos = 11 + 32                       # after random
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
    info.append(f"ciphers:         {len(suites)}")
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
    print(f"\n=== [{tag}] connection from {addr[0]}:{addr[1]} on port {port} ===")

    conn.settimeout(10.0)
    chunks: list[bytes] = []
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            chunks.append(data)
            # The client waits for a response, so nothing more will arrive
            # after the first block anyway. We do not close right away - we
            # give the rest of the record a chance to arrive.
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
        print("  the client sent nothing (bare TCP connect)")
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{tag}.bin").write_bytes(blob)

    lines = [f"# capture {tag}", f"peer: {addr[0]}:{addr[1]}  port: {port}",
             f"bytes: {len(blob)}", "", "## ClientHello"]
    lines += parse_client_hello(blob)
    lines += ["", "## hexdump", hexdump(blob, limit=2048)]
    (out_dir / f"{tag}.txt").write_text("\n".join(lines), encoding="utf-8")

    print(f"  received {len(blob)} bytes -> {out_dir / (tag + '.bin')}")
    for line in parse_client_hello(blob):
        print(f"  {line}")
    print(hexdump(blob, limit=128))


def serve(port: int, out_dir: Path, counter: list[int], lock: threading.Lock) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError as e:
        print(f"cannot listen on {port}: {e}")
        return
    s.listen(16)
    print(f"listening on 0.0.0.0:{port}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle,
                         args=(conn, addr, port, out_dir, counter, lock),
                         daemon=True).start()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-p", "--ports", type=int, nargs="+", default=[42127],
                    help="ports to listen on (default 42127 - the Blaze redirector)")
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon/capture"))
    args = ap.parse_args()

    counter, lock = [0], threading.Lock()
    for port in args.ports:
        threading.Thread(target=serve, args=(port, args.out, counter, lock),
                         daemon=True).start()

    print("waiting for connections. Ctrl+C quits.\n")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\ndone")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
