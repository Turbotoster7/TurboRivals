#!/usr/bin/env python3
"""Loader obrazu modulu z minidumpa (.dmp) - odszyfrowana .text z RAM.

Po co: sekcja .text binarki NFS14.exe ze Steama jest zaszyfrowana na dysku
(entropia 1.000), wiec map_tdf_classes.py nie znajdzie instrukcji `lea`
wiazacych tablice pol TDF z nazwami klas. W RUNTIME kod jest odszyfrowany w
pamieci procesu. Ten modul czyta pelny minidump (Task Manager -> "Utworz plik
zrzutu", albo `procdump -ma NFS14.exe`), rekonstruuje obraz modulu NFS14.exe
INDEKSOWANY PO RVA (offset == RVA) i wystawia interfejs zgodny z klasa PE
(pe_probe.PE), zeby istniejace narzedzia dzialaly bez zmian.

Rebasing: adresy w docs/recon/tdf_members.json policzono wzgledem PREFEROWANEJ
bazy z naglowka PE. RVA sa niezalezne od bazy zaladowania (ASLR), wiec obraz
budujemy po RVA, a image_base bierzemy z naglowka PE modulu - dzieki temu
off_to_va() daje te same VA co json.

Uzycie (samodzielnie, do sprawdzenia):
    python tools/dump_image.py NFS14.dmp
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pe_probe import Section  # noqa: E402  (reuzycie dataclass sekcji)

# typy strumieni minidump
_STREAM_MODULE_LIST = 4
_STREAM_MEMORY_LIST = 5
_STREAM_MEMORY64_LIST = 9

_MDMP = 0x504D444D          # 'MDMP' little-endian


class MemImage:
    """Obraz modulu z pamieci, zgodny (duck-typing) z pe_probe.PE.

    data jest indeksowane po RVA: data[rva] to bajt spod image_base+rva.
    Sekcje ustawione tak, ze raw_ptr == va (RVA), wiec kod korzystajacy z
    text.raw_ptr/raw_size dostaje bajty pamieci danej sekcji.
    """

    def __init__(self, data: bytes, image_base: int, sections: list[Section],
                 pe32plus: bool, machine: int):
        self.data = data
        self.image_base = image_base
        self.sections = sections
        self.pe32plus = pe32plus
        self.machine = machine
        self.ptr_size = 8 if pe32plus else 4
        self.ptr_fmt = "<Q" if pe32plus else "<I"

    def off_to_va(self, off: int) -> int | None:
        if 0 <= off < len(self.data):
            return self.image_base + off
        return None

    def va_to_off(self, va: int) -> int | None:
        off = va - self.image_base
        return off if 0 <= off < len(self.data) else None

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


def _read_minidump_string(buf: bytes, rva: int) -> str:
    ln = struct.unpack_from("<I", buf, rva)[0]
    raw = buf[rva + 4: rva + 4 + ln]
    return raw.decode("utf-16-le", "replace")


def _find_module(buf: bytes, streams: dict[int, tuple[int, int]],
                 want: str) -> tuple[int, int]:
    """Zwraca (base_of_image, size_of_image) modulu, ktorego nazwa zawiera `want`."""
    if _STREAM_MODULE_LIST not in streams:
        raise SystemExit("brak ModuleListStream w zrzucie")
    rva, _ = streams[_STREAM_MODULE_LIST]
    n = struct.unpack_from("<I", buf, rva)[0]
    p = rva + 4
    want_l = want.lower()
    for _ in range(n):
        base, size = struct.unpack_from("<QI", buf, p)
        name_rva = struct.unpack_from("<I", buf, p + 20)[0]
        name = _read_minidump_string(buf, name_rva)
        if want_l in name.lower():
            print(f"  modul: {name}  base=0x{base:x}  size=0x{size:x}")
            return base, size
        p += 108        # sizeof(MINIDUMP_MODULE)
    raise SystemExit(f"nie znalazlem modulu zawierajacego {want!r} w zrzucie")


def _build_from_memory64(buf: bytes, stream_rva: int, base: int, size: int,
                         img: bytearray) -> int:
    n, data_rva = struct.unpack_from("<QQ", buf, stream_rva)
    p = stream_rva + 16
    cur = data_rva
    copied = 0
    for _ in range(n):
        start, dsize = struct.unpack_from("<QQ", buf, p)
        p += 16
        if base <= start < base + size:
            off = start - base
            chunk = buf[cur:cur + dsize]
            end = min(off + len(chunk), size)
            img[off:end] = chunk[:end - off]
            copied += end - off
        cur += dsize
    return copied


def _build_from_memory(buf: bytes, stream_rva: int, base: int, size: int,
                       img: bytearray) -> int:
    n = struct.unpack_from("<I", buf, stream_rva)[0]
    p = stream_rva + 4
    copied = 0
    for _ in range(n):
        start, dsize, rva = struct.unpack_from("<QII", buf, p)
        p += 16
        if base <= start < base + size:
            off = start - base
            chunk = buf[rva:rva + dsize]
            end = min(off + len(chunk), size)
            img[off:end] = chunk[:end - off]
            copied += end - off
    return copied


def load_dump(path: Path, module: str = "NFS14") -> MemImage:
    import mmap
    fh = open(path, "rb")                 # mmap - zrzut pelny to czesto kilka GB
    buf = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
    if struct.unpack_from("<I", buf, 0)[0] != _MDMP:
        raise SystemExit(f"{path} to nie minidump (brak sygnatury MDMP)")
    nstreams, dir_rva = struct.unpack_from("<II", buf, 8)
    streams: dict[int, tuple[int, int]] = {}
    for i in range(nstreams):
        o = dir_rva + i * 12
        stype, dsize, srva = struct.unpack_from("<III", buf, o)
        streams[stype] = (srva, dsize)

    base, size = _find_module(buf, streams, module)
    img = bytearray(size)
    if _STREAM_MEMORY64_LIST in streams:
        copied = _build_from_memory64(buf, streams[_STREAM_MEMORY64_LIST][0],
                                      base, size, img)
    elif _STREAM_MEMORY_LIST in streams:
        copied = _build_from_memory(buf, streams[_STREAM_MEMORY_LIST][0],
                                    base, size, img)
    else:
        raise SystemExit("zrzut nie zawiera pamieci (brak Memory64List/MemoryList) "
                         "- zrob PELNY zrzut (Task Manager 'Utworz plik zrzutu' "
                         "albo 'procdump -ma')")
    print(f"  skopiowano {copied:,} B pamieci modulu do obrazu ({size:,} B)")

    # naglowek PE modulu z pamieci: preferowana baza, maszyna, sekcje
    e_lfanew = struct.unpack_from("<I", img, 0x3C)[0]
    if img[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("naglowek PE modulu nie jest w zrzucie - zrzut niepelny?")
    coff = e_lfanew + 4
    machine, nsec = struct.unpack_from("<HH", img, coff)
    opt_size = struct.unpack_from("<H", img, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", img, opt)[0]
    pe32plus = magic == 0x20B
    image_base = struct.unpack_from("<Q" if pe32plus else "<I", img, opt + 24)[0]

    sec_off = opt + opt_size
    sections: list[Section] = []
    for i in range(nsec):
        so = sec_off + i * 40
        name = bytes(img[so:so + 8]).rstrip(b"\0").decode("ascii", "replace")
        vsize, va = struct.unpack_from("<II", img, so + 8)[0:2]
        # W obrazie pamieci offset == RVA: raw_ptr = va, raw_size = vsize.
        sections.append(Section(name, va, vsize, va, vsize))

    print(f"  image_base=0x{image_base:x}  sekcji={nsec}  "
          f"{'x64' if pe32plus else 'x86'}")
    return MemImage(bytes(img), image_base, sections, pe32plus, machine)


def main() -> int:
    if len(sys.argv) < 2:
        print("uzycie: python tools/dump_image.py NFS14.dmp [nazwa_modulu]")
        return 1
    mod = sys.argv[2] if len(sys.argv) > 2 else "NFS14"
    mi = load_dump(Path(sys.argv[1]), mod)
    text = next((s for s in mi.sections if s.name == ".text"), None)
    if text:
        blob = mi.data[text.raw_ptr:text.raw_ptr + text.raw_size]
        nz = sum(1 for b in blob[:65536] if b)
        print(f"  .text @ RVA 0x{text.va:x} ({text.vsize:,} B); "
              f"niezerowych w pierwszych 64 KiB: {nz}/65536 "
              f"({'wyglada na ODSZYFROWANA' if nz > 30000 else 'podejrzanie pusta/zaszyfrowana'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
