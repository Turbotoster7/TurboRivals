#!/usr/bin/env python3
"""Sonda PE - szukanie tablic metadanych TDF w binarce gry.

Hipoteza: BlazeSDK generuje dla kazdej klasy TDF statyczna tablice
TdfMemberInfo, ktora wiaze tag (4 znaki spakowane w 3 bajty) z nazwa pola
i offsetem w strukturze. Nazwy pol ("mBlazeId") sa w binarce - jesli obok
nich leza tagi, mozemy odtworzyc caly schemat protokolu bez zgadywania.

Podkomendy:
    info                          naglowki PE i sekcje
    find <tekst>                  znajdz stringi i pokaz ich VA
    xref <tekst>                  znajdz wskazniki na string i zrzut otoczenia
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Section:
    name: str
    va: int          # RVA
    vsize: int
    raw_ptr: int
    raw_size: int


class PE:
    def __init__(self, data: bytes):
        self.data = data
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("to nie jest plik PE")
        coff = e_lfanew + 4
        self.machine, nsections = struct.unpack_from("<HH", data, coff)
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        self.pe32plus = magic == 0x20B
        self.image_base = struct.unpack_from(
            "<Q" if self.pe32plus else "<I", data, opt + 24)[0]
        self.ptr_size = 8 if self.pe32plus else 4
        self.ptr_fmt = "<Q" if self.pe32plus else "<I"

        sec_off = opt + opt_size
        self.sections: list[Section] = []
        for i in range(nsections):
            o = sec_off + i * 40
            name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, o + 8)
            self.sections.append(Section(name, va, vsize, raw_ptr, raw_size))

    def off_to_va(self, off: int) -> int | None:
        for s in self.sections:
            if s.raw_ptr <= off < s.raw_ptr + s.raw_size:
                return self.image_base + s.va + (off - s.raw_ptr)
        return None

    def va_to_off(self, va: int) -> int | None:
        rva = va - self.image_base
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                off = s.raw_ptr + (rva - s.va)
                if off < s.raw_ptr + s.raw_size:
                    return off
        return None

    def section_of_va(self, va: int) -> Section | None:
        rva = va - self.image_base
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return s
        return None

    def cstring_at(self, va: int, limit: int = 128) -> str | None:
        off = self.va_to_off(va)
        if off is None:
            return None
        end = self.data.find(b"\0", off, off + limit)
        if end < 0:
            return None
        raw = self.data[off:end]
        if not raw or not all(0x20 <= b <= 0x7E for b in raw):
            return None
        return raw.decode("ascii")


def cmd_info(pe: PE, _args) -> int:
    print(f"machine        0x{pe.machine:04x}  ({'x64' if pe.pe32plus else 'x86'})")
    print(f"image base     0x{pe.image_base:x}")
    print(f"pointer size   {pe.ptr_size}")
    print()
    print(f"{'section':10} {'RVA':>12} {'vsize':>12} {'raw ptr':>12} {'raw size':>12}")
    for s in pe.sections:
        print(f"{s.name:10} {s.va:#12x} {s.vsize:#12x} {s.raw_ptr:#12x} {s.raw_size:#12x}")
    return 0


def find_strings(pe: PE, text: str, exact: bool) -> list[tuple[int, int, str]]:
    """Zwraca (offset, va, tekst) dla stringow zawierajacych/rownych `text`."""
    needle = text.encode("ascii")
    out: list[tuple[int, int, str]] = []
    start = 0
    while True:
        i = pe.data.find(needle, start)
        if i < 0:
            break
        start = i + 1
        # cofnij sie do poczatku C-stringa
        begin = i
        while begin > 0 and 0x20 <= pe.data[begin - 1] <= 0x7E:
            begin -= 1
        end = pe.data.find(b"\0", i)
        if end < 0 or end - begin > 256:
            continue
        s = pe.data[begin:end].decode("ascii", "replace")
        if exact and s != text:
            continue
        va = pe.off_to_va(begin)
        if va is None:
            continue
        out.append((begin, va, s))
    return out


def cmd_find(pe: PE, args) -> int:
    hits = find_strings(pe, args.text, args.exact)
    print(f"{len(hits)} trafien dla {args.text!r} (exact={args.exact})")
    for off, va, s in hits[:args.limit]:
        sec = pe.section_of_va(va)
        print(f"  off={off:#010x}  va={va:#014x}  [{sec.name if sec else '?':8}]  {s}")
    return 0


def hexdump(pe: PE, va: int, before: int, after: int) -> None:
    off = pe.va_to_off(va)
    if off is None:
        return
    lo = max(0, off - before)
    hi = min(len(pe.data), off + after)
    for line_off in range(lo, hi, 16):
        chunk = pe.data[line_off:line_off + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        mark = " <<<" if line_off <= off < line_off + 16 else ""
        cur_va = pe.off_to_va(line_off)
        print(f"    {cur_va:#014x} {hexs:<47}  {text}{mark}")


def cmd_xref(pe: PE, args) -> int:
    """Znajduje 8-bajtowe wskazniki na string i pokazuje sasiedztwo.

    Jesli tablica TdfMemberInfo istnieje, wokol wskaznika na nazwe pola
    powinny lezec: tag, offset pola i typ.
    """
    hits = find_strings(pe, args.text, exact=True)
    if not hits:
        print(f"nie znaleziono stringa {args.text!r}")
        return 1
    print(f"string {args.text!r}: {len(hits)} wystapien")

    for off, va, _ in hits[:args.limit]:
        ptr = struct.pack(pe.ptr_fmt, va)
        refs = [m.start() for m in re.finditer(re.escape(ptr), pe.data)]
        print(f"\n  va={va:#014x} (off={off:#010x}) -> {len(refs)} wskaznikow")
        for r in refs[:args.refs]:
            rva = pe.off_to_va(r)
            sec = pe.section_of_va(rva) if rva else None
            print(f"\n  ref @ off={r:#010x} va={rva:#014x} [{sec.name if sec else '?'}]")
            hexdump(pe, rva, args.before, args.after)
    return 0


def decode_tdf_tag(raw: int) -> str:
    """Rozpakowuje 24-bitowy tag TDF na 4 znaki (6 bitow na znak).

    BlazeSDK pakuje 4-znakowy tag do 3 bajtow: kazdy znak to 6 bitow,
    a wartosc 0 oznacza spacje. Uzywane do weryfikacji, czy dany
    fragment metadanych to faktycznie tag.
    """
    chars = []
    for shift in (18, 12, 6, 0):
        c = (raw >> shift) & 0x3F
        chars.append(" " if c == 0 else chr(c + 0x20))
    return "".join(chars)


def cmd_table(pe: PE, args) -> int:
    """Zrzuca region jako tablice rekordow, rozwiazujac wskazniki na stringi.

    Nie zakladamy z gory ukladu rekordu - wypisujemy kazde pole i to, czy
    da sie je zinterpretowac jako wskaznik na tekst. Semantyka powinna
    wyjsc z samego zestawienia.
    """
    va = args.va
    for i in range(args.count):
        base = va + i * args.stride
        off = pe.va_to_off(base)
        if off is None:
            print(f"{base:#014x}  <poza obrazem>")
            break
        raw = pe.data[off:off + args.stride]
        parts = []
        for j in range(0, args.stride, 8):
            if j + 8 > len(raw):
                break
            q = struct.unpack_from("<Q", raw, j)[0]
            s = pe.cstring_at(q) if 0x140000000 <= q < 0x150000000 else None
            if s is not None:
                parts.append(f"[{j:2}] -> {s!r}")
            else:
                tag = decode_tdf_tag((q >> 8) & 0xFFFFFF)
                hint = f" tag?={tag!r}" if tag.strip().isalnum() else ""
                parts.append(f"[{j:2}] = {q:#018x}{hint}")
        print(f"{base:#014x}  " + "  ".join(parts))
    return 0


def cmd_refs(pe: PE, args) -> int:
    """Szuka referencji do adresu: jako 8-bajtowy VA i jako 4-bajtowy RVA.

    Deskryptor klasy TDF powinien wskazywac na poczatek tablicy pol,
    wiec referencja do pierwszego rekordu bloku prowadzi nas do klasy.
    """
    va = args.va
    rva = va - pe.image_base

    for label, needle in (("VA  (8B)", struct.pack("<Q", va)),
                          ("RVA (4B)", struct.pack("<I", rva))):
        refs = [m.start() for m in re.finditer(re.escape(needle), pe.data)]
        print(f"\n=== {label} = {needle.hex()} -> {len(refs)} trafien ===")
        for r in refs[:args.limit]:
            r_va = pe.off_to_va(r)
            sec = pe.section_of_va(r_va) if r_va else None
            print(f"\n  @ off={r:#010x} va={r_va:#014x} [{sec.name if sec else '?'}]")
            if r_va is not None:
                hexdump(pe, r_va, args.before, args.after)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", type=Path)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("info").set_defaults(func=cmd_info)

    p = sub.add_parser("find")
    p.add_argument("text")
    p.add_argument("--exact", action="store_true")
    p.add_argument("--limit", type=int, default=40)
    p.set_defaults(func=cmd_find)

    p = sub.add_parser("xref")
    p.add_argument("text")
    p.add_argument("--limit", type=int, default=2, help="ile wystapien stringa")
    p.add_argument("--refs", type=int, default=3, help="ile wskaznikow na wystapienie")
    p.add_argument("--before", type=int, default=48)
    p.add_argument("--after", type=int, default=80)
    p.set_defaults(func=cmd_xref)

    p = sub.add_parser("refs")
    p.add_argument("--va", type=lambda x: int(x, 0), required=True)
    p.add_argument("--limit", type=int, default=4)
    p.add_argument("--before", type=int, default=32)
    p.add_argument("--after", type=int, default=48)
    p.set_defaults(func=cmd_refs)

    p = sub.add_parser("table")
    p.add_argument("--va", type=lambda x: int(x, 0), required=True)
    p.add_argument("--count", type=int, default=20)
    p.add_argument("--stride", type=int, default=24)
    p.set_defaults(func=cmd_table)

    args = ap.parse_args()
    if not args.exe.is_file():
        print(f"nie ma takiego pliku: {args.exe}", file=sys.stderr)
        return 1
    return args.func(PE(args.exe.read_bytes()), args)


if __name__ == "__main__":
    raise SystemExit(main())
