#!/usr/bin/env python3
"""Szukanie struktur na STERCIE w zrzucie pamieci - po sygnaturze wartosci.

Po co: tools/dump_image.py rekonstruuje tylko OBRAZ MODULU (kod + zmienne
globalne). Struktury alokowane w czasie dzialania - jak stan QoS pod
`*(QosApiRef+0x128)` - leza na stercie, ktorej tam nie ma. Ten skrypt czyta
zrzut jako SUROWY PLIK i szuka w nim wzorca bajtow.

Technika (warto zapamietac, dziala na kazdym protokole):
  1. Wez wartosci, ktore SAM wstawiles do protokolu - im dziwniejsze, tym lepiej
     (dlatego w odpowiedzi QoS mamy requestid=1234, a nie 1: taka liczba wystepuje
     w pamieci rzadko, wiec sygnatura jest jednoznaczna).
  2. Z dezasemblacji odczytaj, na jakich OFFSETACH struktury te pola leza.
  3. Zloz wzorzec: znane pola jako bajty, nieznane jako dziury.
  4. Znalezione trafienie minus offset pola = poczatek struktury (kotwica).
  5. Odczytaj reszte pol po offsetach - masz zywy stan procesu.

Uzycie:
    python tools/dump_search.py NFS14.dmp --qos
    python tools/dump_search.py NFS14.dmp --qos --requestid 1234 --numprobes 10
    python tools/dump_search.py NFS14.dmp --u32 1234              # gdzie jest ta liczba
    python tools/dump_search.py NFS14.dmp --hex "40000000????????0a000000" --at 0x111c
"""

from __future__ import annotations

import argparse
import mmap
import re
import struct
from pathlib import Path

# Uklad stanu QoS (*(QosApiRef+0x128)) odczytany z kodu gry - RVA w komentarzach
# sa miejscami, ktore dane pole zapisuja albo czytaja.
QOS_FIELDS = [
    # (offset, typ, nazwa, skad wiemy - RVA instrukcji, ktora pole zapisuje)
    (0x1118, "I",  "qtyp",         "faza: 0/1 latencja, 2 pasmo, 5/6/7 dalej"),
    (0x111C, "I",  "probesize",    "dlugosc sondy pasma, z naszego XML (0xfdb370)"),
    (0x1120, "I",  "wyslanych",    "licznik wyslanych sond (0xfdbd0e)"),
    (0x1124, "I",  "numprobes",    "ile sond ma byc, z naszego XML (0xfdb345)"),
    (0x1128, "I",  "odebranych",   "licznik odpowiedzi serwera (0xfdb9ee)"),
    (0x112C, "I",  "czas_1_odp",   "NetTick pierwszej odpowiedzi (0xfdb9ff)"),
    (0x1130, "I",  "requestid",    "z naszego XML (0xfdb3c0)"),
    (0x1134, "I",  "reqsecret",    "z naszego XML (0xfdb3eb)"),
    (0x1138, "I",  "numinterf",    ".numinterfaces galezi firewall (0xfdb0e0)"),
    (0x113C, "ip", "ips[0]",       "pierwszy endpoint testu NAT (0xfdb139)"),
    (0x1140, "ip", "ips[1]",       "drugi endpoint, petla XmlNext (0xfdb1ae)"),
    (0x1144, "H",  "ports[0]",     "port pierwszego endpointu (0xfdb154)"),
    (0x1146, "H",  "ports[1]",     "port drugiego endpointu (0xfdb1c7)"),
    (0x1148, "I",  "firetype",     "typ NAT; 5 = nieznany (0xfdb2b3)"),
    (0x114C, "I",  "fw_requestid", "requestid galezi firewall (0xfdb204)"),
    (0x1150, "I",  "fw_reqsecret", "reqsecret galezi firewall (0xfdb22f)"),
]


def build_pattern(hex_or_none: str | None, args) -> tuple[bytes, int]:
    """Zwraca (wzorzec regex, offset kotwicy). '??' w hexie = dowolny bajt."""
    if hex_or_none:
        txt = hex_or_none.replace(" ", "").lower()
        if len(txt) % 2:
            raise SystemExit("wzorzec hex musi miec parzysta liczbe znakow")
        out = b""
        for i in range(0, len(txt), 2):
            pair = txt[i:i + 2]
            out += b"." if pair == "??" else re.escape(bytes([int(pair, 16)]))
        return out, args.at

    # preset --qos: probesize @+0x111c, numprobes @+0x1124 (+8),
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
    ap.add_argument("dump", type=Path, help="pelny minidump .dmp")
    ap.add_argument("--qos", action="store_true",
                    help="gotowa sygnatura stanu QoS + opis wszystkich pol")
    ap.add_argument("--u32", type=lambda x: int(x, 0),
                    help="znajdz 32-bitowa liczbe little-endian")
    ap.add_argument("--hex", help="wlasny wzorzec, '??' = dowolny bajt")
    ap.add_argument("--at", type=lambda x: int(x, 0), default=0,
                    help="offset pola od poczatku struktury (kotwica dla --hex)")
    ap.add_argument("--size", type=int, default=64,
                    help="ile bajtow pokazac wokol trafienia (tryb --u32/--hex)")
    ap.add_argument("--limit", type=int, default=6, help="ile trafien pokazac")
    ap.add_argument("--probesize", type=int, default=64)
    ap.add_argument("--numprobes", type=int, default=10)
    ap.add_argument("--requestid", type=int, default=1234)
    ap.add_argument("--reqsecret", type=int, default=1)
    args = ap.parse_args()

    if not (args.qos or args.u32 is not None or args.hex):
        ap.error("wybierz --qos, --u32 albo --hex")

    with open(args.dump, "rb") as fh:
        buf = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        print(f"zrzut: {args.dump}  ({len(buf):,} B)")

        if args.u32 is not None:
            needle = struct.pack("<I", args.u32)
            hits, off = [], 0
            while len(hits) < args.limit * 4:
                i = buf.find(needle, off)
                if i < 0:
                    break
                hits.append(i)
                off = i + 4
            print(f"liczba {args.u32} (0x{args.u32:x}) jako u32 LE: "
                  f"{len(hits)}{'+' if len(hits) == args.limit * 4 else ''} trafien\n")
            for i in hits[:args.limit]:
                print(f"  @ 0x{i:x}")
                hexdump(buf[i - args.size // 2: i + args.size // 2], i - args.size // 2)
                print()
            return 0

        pat, anchor = build_pattern(args.hex, args)
        hits = [m.start() for m in re.compile(pat, re.DOTALL).finditer(buf)]
        print(f"trafien sygnatury: {len(hits)}  (kotwica: trafienie - 0x{anchor:x})\n")
        for i, start in enumerate(hits[:args.limit], 1):
            base = start - anchor
            print(f"  #{i} struktura @ offset w pliku 0x{base:x}")
            if args.qos:
                show_qos(buf, base)
            else:
                hexdump(buf[start: start + args.size], start)
            print()
        if not hits:
            print("  Brak trafien. Najczestsze przyczyny:\n"
                  "   - zrzut zrobiony PRZED tym, jak gra wypelnila strukture\n"
                  "   - inne wartosci w XML niz domyslne (ustaw --requestid itd.)\n"
                  "   - zrzut mini, bez pamieci (sprawdz tools/dump_image.py)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
