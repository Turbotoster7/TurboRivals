#!/usr/bin/env python3
"""Od stringu w binarce do kodu, ktory go uzywa - na zrzucie pamieci.

Po co: stringi i .rdata mozna czytac z .exe (nie sa zaszyfrowane), ale KOD
(.text) jest na dysku zaszyfrowany. Kod czytamy wiec ze zrzutu pamieci, gdzie
jest odszyfrowany. To narzedzie robi cala petle:

  1. znajduje string (albo bierze podany adres)
  2. szuka ODWOLAN Z KODU: na x64 odwolanie do stringu to `lea reg,[rip+disp32]`
     (7 bajtow: 48 8d /r disp32), gdzie target = adres_instrukcji + 7 + disp
  3. ustala poczatek funkcji - MSVC wypelnia przerwy miedzy funkcjami bajtem
     0xCC (int3), wiec ostatni ciag CC przed xrefem to poczatek funkcji
  4. dezasembluje funkcje i rozwija odwolania rip-relative do stringow

Uzycie:
    python xref.py <zrzut.dmp> --str ".qosport"
    python xref.py <zrzut.dmp> --va 0x14170ef98 --len 400
    python xref.py <zrzut.dmp> --func 0xfdb070 --len 200   (dezasembluj od RVA)
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
                    help="NFS14.exe (wystarczy do stringow) LUB pelny zrzut .dmp "
                         "(konieczny do KODU - .text na dysku jest zaszyfrowana)")
    ap.add_argument("--str", dest="text", help="string, ktorego uzycia szukamy")
    ap.add_argument("--va", type=lambda x: int(x, 0), help="albo gotowy adres (VA)")
    ap.add_argument("--func", type=lambda x: int(x, 0),
                    help="dezasembluj funkcje zawierajaca ten RVA (bez szukania)")
    ap.add_argument("--len", type=int, default=260, help="ile bajtow dezasemblowac")
    ap.add_argument("--module", default="NFS14")
    ap.add_argument("--strings", type=lambda x: int(x, 0), metavar="VA",
                    help="wypisz stringi lezace od tego adresu (nie szuka kodu)")
    args = ap.parse_args()

    import capstone

    if args.dump.suffix.lower() == ".exe":
        from pe_probe import PE
        mi = PE(args.dump.read_bytes())
        print(f"czytam {args.dump.name} z dysku (stringi i .rdata - OK; "
              f"KOD bedzie zaszyfrowany)")
    else:
        from dump_image import load_dump
        mi = load_dump(args.dump, args.module)
    d, base = mi.data, mi.image_base
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    text = next(s for s in mi.sections if s.name == ".text")

    def func_start(rva: int) -> int:
        """Poczatek funkcji = koniec ostatniego ciagu int3 (0xCC) przed rva."""
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
            raise SystemExit(f"adres 0x{args.strings:x} jest poza obrazem")
        blob = mi.data[off: off + args.len]
        print(f"stringi od 0x{args.strings:x} (nastepne {args.len} B):")
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
        print(f"=== funkcja zawierajaca 0x{args.func:x} zaczyna sie @ 0x{st:x} ===")
        disasm(st, args.len)
        return 0

    # 1) adres stringu
    targets: dict[int, str] = {}
    if args.va is not None:
        targets[args.va] = mi.cstring_at(args.va, 64) or f"0x{args.va:x}"
    else:
        if not args.text:
            ap.error("podaj --str, --va albo --func")
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
            print(f"nie znalazlem {args.text!r} w zrzucie")
            return 1
    for va, s in targets.items():
        sec = mi.section_of_va(va)
        print(f"  string @ 0x{va:x} [{sec.name if sec else '?'}]  {s!r}")

    # 2) odwolania z kodu: lea reg,[rip+disp32]
    print("\n  szukam `lea reg,[rip+...]` w .text ...")
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
        print("  brak odwolan z kodu (string moze byc uzywany przez wskaznik w danych"
              " - wtedy sprobuj tools/pe_probe.py refs --va ...)")
        return 0

    # 3) + 4) granica funkcji i dezasemblacja
    seen: set[int] = set()
    for rva, t in hits:
        print(f"\n  xref @ 0x{rva:x}  ->  {targets[t]!r}")
        st = func_start(rva)
        if st in seen:
            print(f"    (ta sama funkcja co wyzej, start 0x{st:x})")
            continue
        seen.add(st)
        print(f"    funkcja zaczyna sie @ 0x{st:x}, dezasembluje {args.len} B:")
        disasm(st, args.len)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
