#!/usr/bin/env python3
"""From a string in the binary to the code that uses it - on a memory dump.

Why: strings and .rdata can be read from the .exe (they are not encrypted), but
the CODE (.text) is encrypted on disk. So we read code from a memory dump, where
it is decrypted. This tool runs the whole loop:

  1. finds the string (or takes the given address)
  2. looks for REFERENCES FROM CODE: on x64 a string reference is
     `lea reg,[rip+disp32]` (7 bytes: 48 8d /r disp32), where
     target = instruction_address + 7 + disp
  3. finds the function start - MSVC pads the gaps between functions with
     0xCC (int3), so the last run of CC before the xref is the function start
  4. disassembles the function and resolves rip-relative string references

Usage:
    python xref.py <dump.dmp> --str ".qosport"
    python xref.py <dump.dmp> --va 0x14170ef98 --len 400
    python xref.py <dump.dmp> --func 0xfdb070 --len 200   (disassemble from an RVA)
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, "tools")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", type=Path,
                    help="NFS14.exe (enough for strings) OR a full .dmp dump "
                         "(required for CODE - .text on disk is encrypted)")
    ap.add_argument("--str", dest="text", help="string whose uses we are looking for")
    ap.add_argument("--va", type=lambda x: int(x, 0), help="or a ready address (VA)")
    ap.add_argument("--func", type=lambda x: int(x, 0),
                    help="disassemble the function containing this RVA (no search)")
    ap.add_argument("--len", type=int, default=260, help="how many bytes to disassemble")
    ap.add_argument("--module", default="NFS14")
    ap.add_argument("--strings", type=lambda x: int(x, 0), metavar="VA",
                    help="print the strings starting at this address (no code search)")
    args = ap.parse_args()

    import capstone

    if args.dump.suffix.lower() == ".exe":
        from pe_probe import PE
        mi = PE(args.dump.read_bytes())
        print(f"reading {args.dump.name} from disk (strings and .rdata - OK; "
              f"CODE will be encrypted)")
    else:
        from dump_image import load_dump
        mi = load_dump(args.dump, args.module)
    d, base = mi.data, mi.image_base
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    text = next(s for s in mi.sections if s.name == ".text")

    def func_start(rva: int) -> int:
        """Function start = end of the last run of int3 (0xCC) before rva."""
        i = rva
        while i > text.va:
            if d[i - 1] == 0xCC and d[i - 2] == 0xCC:
                return i
            i -= 1
        return rva

    def disasm(rva: int, n: int) -> None:
        for ins in md.disasm(d[rva:rva + n], base + rva):
            line = f"  0x{ins.address - base:08x}  {ins.mnemonic:<7} {ins.op_str}"
            if "rip" in ins.op_str:
                for op in ins.operands:
                    if (op.type == capstone.x86.X86_OP_MEM
                            and op.mem.base == capstone.x86.X86_REG_RIP):
                        t = ins.address + ins.size + op.mem.disp
                        s = mi.cstring_at(t, 64)
                        line += "   ; " + (f'"{s}"' if s else f"0x{t:x}")
            print(line)

    if args.strings is not None:
        off = mi.va_to_off(args.strings)
        if off is None:
            raise SystemExit(f"address 0x{args.strings:x} is outside the image")
        blob = mi.data[off: off + args.len]
        print(f"strings from 0x{args.strings:x} (next {args.len} B):")
        print("")
        i = 0
        while i < len(blob):
            if 0x20 <= blob[i] <= 0x7E:
                j = i
                while j < len(blob) and 0x20 <= blob[j] <= 0x7E:
                    j += 1
                if j - i >= 3:
                    print(f"  0x{args.strings + i:x}  {blob[i:j].decode()!r}")
                i = j
            else:
                i += 1
        return 0

    if args.func is not None:
        st = func_start(args.func)
        print(f"=== function containing 0x{args.func:x} starts @ 0x{st:x} ===")
        disasm(st, args.len)
        return 0

    # 1) string address
    targets: dict[int, str] = {}
    if args.va is not None:
        targets[args.va] = mi.cstring_at(args.va, 64) or f"0x{args.va:x}"
    else:
        if not args.text:
            ap.error("pass --str, --va or --func")
        needle = args.text.encode()
        off = 0
        while True:
            i = d.find(needle, off)
            if i < 0:
                break
            targets[base + i] = mi.cstring_at(base + i, 64) or args.text
            off = i + 1
            if len(targets) >= 12:
                break
        if not targets:
            print(f"{args.text!r} not found in the dump")
            return 1
    for va, s in targets.items():
        sec = mi.section_of_va(va)
        print(f"  string @ 0x{va:x} [{sec.name if sec else '?'}]  {s!r}")

    # 2) references from code: lea reg,[rip+disp32]
    print("\n  searching for `lea reg,[rip+...]` in .text ...")
    blob = d[text.va:text.va + text.vsize]
    hits: list[tuple[int, int]] = []
    for p in range(len(blob) - 7):
        if blob[p] != 0x48 or blob[p + 1] != 0x8D:
            continue
        if (blob[p + 2] & 0xC7) != 0x05:          # mod=00, rm=101 = rip-relative
            continue
        disp = struct.unpack_from("<i", blob, p + 3)[0]
        t = base + text.va + p + 7 + disp
        if t in targets:
            hits.append((text.va + p, t))
    if not hits:
        print("  no references from code (the string may be used through a pointer in data"
              " - then try tools/pe_probe.py refs --va ...)")
        return 0

    # 3) + 4) function boundary and disassembly
    seen: set[int] = set()
    for rva, t in hits:
        print(f"\n  xref @ 0x{rva:x}  ->  {targets[t]!r}")
        st = func_start(rva)
        if st in seen:
            print(f"    (same function as above, start 0x{st:x})")
            continue
        seen.add(st)
        print(f"    function starts @ 0x{st:x}, disassembling {args.len} B:")
        disasm(st, args.len)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
