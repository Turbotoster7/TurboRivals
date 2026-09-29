#!/usr/bin/env python3
"""Searching for structures on the HEAP in a memory dump - by a value signature.

Why: tools/dump_image.py only reconstructs the MODULE IMAGE (code + global
variables). Structures allocated at runtime - like the QoS state under
`*(QosApiRef+0x128)` - live on the heap, which is not there. This script reads
the dump as a RAW FILE and searches it for a byte pattern.

Technique (worth remembering, works on any protocol):
  1. Take values that YOU put into the protocol - the weirder, the better
     (that is why the QoS response has requestid=1234 and not 1: such a number
     rarely occurs in memory, so the signature is unambiguous).
  2. Read from the disassembly at which OFFSETS of the structure those fields sit.
  3. Build a pattern: known fields as bytes, unknown ones as holes.
  4. The hit found minus the field offset = start of the structure (the anchor).
  5. Read the remaining fields by offset - you have the live process state.

Usage:
    python tools/dump_search.py NFS14.dmp --qos
    python tools/dump_search.py NFS14.dmp --qos --requestid 1234 --numprobes 10
    python tools/dump_search.py NFS14.dmp --u32 1234              # where this number is
    python tools/dump_search.py NFS14.dmp --hex "40000000????????0a000000" --at 0x111c
"""

from __future__ import annotations

import argparse
import mmap
import re
import struct
from pathlib import Path

# Layout of the QoS state (*(QosApiRef+0x128)) read from the game code - the RVAs
# in the comments are the places that write or read the given field.
QOS_FIELDS = [
    # (offset, type, name, how we know - RVA of the instruction that writes the field)
    (0x1118, "I",  "qtyp",         "phase: 0/1 latency, 2 bandwidth, 5/6/7 later"),
    (0x111C, "I",  "probesize",    "bandwidth probe length, from our XML (0xfdb370)"),
    (0x1120, "I",  "sent",         "counter of sent probes (0xfdbd0e)"),
    (0x1124, "I",  "numprobes",    "how many probes there should be, from our XML (0xfdb345)"),
    (0x1128, "I",  "received",     "counter of server responses (0xfdb9ee)"),
    (0x112C, "I",  "t_first_resp", "NetTick of the first response (0xfdb9ff)"),
    (0x1130, "I",  "requestid",    "from our XML (0xfdb3c0)"),
    (0x1134, "I",  "reqsecret",    "from our XML (0xfdb3eb)"),
    (0x1138, "I",  "numinterf",    ".numinterfaces of the firewall branch (0xfdb0e0)"),
    (0x113C, "ip", "ips[0]",       "first NAT test endpoint (0xfdb139)"),
    (0x1140, "ip", "ips[1]",       "second endpoint, XmlNext loop (0xfdb1ae)"),
    (0x1144, "H",  "ports[0]",     "port of the first endpoint (0xfdb154)"),
    (0x1146, "H",  "ports[1]",     "port of the second endpoint (0xfdb1c7)"),
    (0x1148, "I",  "firetype",     "NAT type; 5 = unknown (0xfdb2b3)"),
    (0x114C, "I",  "fw_requestid", "requestid of the firewall branch (0xfdb204)"),
    (0x1150, "I",  "fw_reqsecret", "reqsecret of the firewall branch (0xfdb22f)"),
]


def build_pattern(hex_or_none: str | None, args) -> tuple[bytes, int]:
    """Returns (regex pattern, anchor offset). '??' in the hex = any byte."""
    if hex_or_none:
        txt = hex_or_none.replace(" ", "").lower()
        if len(txt) % 2:
            raise SystemExit("hex pattern must have an even number of characters")
        out = b""
        for i in range(0, len(txt), 2):
            pair = txt[i:i + 2]
            out += b"." if pair == "??" else re.escape(bytes([int(pair, 16)]))
        return out, args.at

    # --qos preset: probesize @+0x111c, numprobes @+0x1124 (+8),
    #               requestid @+0x1130 (+0x14), reqsecret @+0x1134 (+0x18)
    u = lambda v: re.escape(struct.pack("<I", v))
    pat = (u(args.probesize) + b".{4}" + u(args.numprobes) + b".{8}"
           + u(args.requestid) + u(args.reqsecret))
    return pat, 0x111C


def show_qos(buf, base: int) -> None:
    for off, kind, name, why in QOS_FIELDS:
        fmt = "<H" if kind == "H" else "<I"
        val = struct.unpack_from(fmt, buf, base + off)[0]
        txt = (".".join(str(b) for b in struct.pack(">I", val))
               if kind == "ip" else str(val))
        print(f"    +0x{off:04x}  {name:<13} = {txt:<12}  {why}")


def hexdump(data: bytes, base_off: int) -> None:
    for i in range(0, len(data), 16):
        row = data[i:i + 16]
        txt = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in row)
        print(f"    {base_off + i:#012x}  {row.hex(' '):<47}  {txt}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", type=Path, help="full .dmp minidump")
    ap.add_argument("--qos", action="store_true",
                    help="ready-made QoS state signature + description of all fields")
    ap.add_argument("--u32", type=lambda x: int(x, 0),
                    help="find a 32-bit little-endian number")
    ap.add_argument("--hex", help="custom pattern, '??' = any byte")
    ap.add_argument("--at", type=lambda x: int(x, 0), default=0,
                    help="field offset from the structure start (anchor for --hex)")
    ap.add_argument("--size", type=int, default=64,
                    help="how many bytes to show around a hit (--u32/--hex mode)")
    ap.add_argument("--limit", type=int, default=6, help="how many hits to show")
    ap.add_argument("--probesize", type=int, default=64)
    ap.add_argument("--numprobes", type=int, default=10)
    ap.add_argument("--requestid", type=int, default=1234)
    ap.add_argument("--reqsecret", type=int, default=1)
    args = ap.parse_args()

    if not (args.qos or args.u32 is not None or args.hex):
        ap.error("pick --qos, --u32 or --hex")

    with open(args.dump, "rb") as fh:
        buf = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        print(f"dump: {args.dump}  ({len(buf):,} B)")

        if args.u32 is not None:
            needle = struct.pack("<I", args.u32)
            hits, off = [], 0
            while len(hits) < args.limit * 4:
                i = buf.find(needle, off)
                if i < 0:
                    break
                hits.append(i)
                off = i + 4
            print(f"number {args.u32} (0x{args.u32:x}) as u32 LE: "
                  f"{len(hits)}{'+' if len(hits) == args.limit * 4 else ''} hits\n")
            for i in hits[:args.limit]:
                print(f"  @ 0x{i:x}")
                hexdump(buf[i - args.size // 2: i + args.size // 2], i - args.size // 2)
                print()
            return 0

        pat, anchor = build_pattern(args.hex, args)
        hits = [m.start() for m in re.compile(pat, re.DOTALL).finditer(buf)]
        print(f"signature hits: {len(hits)}  (anchor: hit - 0x{anchor:x})\n")
        for i, start in enumerate(hits[:args.limit], 1):
            base = start - anchor
            print(f"  #{i} structure @ file offset 0x{base:x}")
            if args.qos:
                show_qos(buf, base)
            else:
                hexdump(buf[start: start + args.size], start)
            print()
        if not hits:
            print("  No hits. Most common causes:\n"
                  "   - dump taken BEFORE the game filled in the structure\n"
                  "   - different values in the XML than the defaults (set --requestid etc.)\n"
                  "   - a mini dump without memory (check tools/dump_image.py)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
