#!/usr/bin/env python3
"""Koder/dekoder protokolu Blaze: ramka Fire2 + TDF (heat2).

Po przebiciu TLS (tls_terminator.py) czytamy ruch Blaze otwartym tekstem.
Pierwszy pakiet klienta to Redirector.getServerInstance (component 5, cmd 1).
Zeby gra poszla dalej, musimy ODPOWIEDZIEC - a do tego potrzebny jest enkoder
TDF. Ten modul jest lustrem dekodera zweryfikowanego na przechwyconym pakiecie
(docs/recon/capture, blaze-first-*.bin): tag 24-bit (6 bitow/znak), typ 1 bajt,
potem wartosc. Format ustalony empirycznie i round-tripem na realnym pakiecie.

UWAGA co do schematu odpowiedzi: sekcja .text binarki Steam jest zaszyfrowana
(entropia 1.000), wiec map_tdf_classes.py nie zrzuci ukladu klas. Dokladny
zestaw pol odpowiedzi (ServerInstanceInfo) ustalamy empirycznie - wysylamy
i czytamy reakcje klienta (jak przy certcie i wersji rekordu).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# --- typy TDF na drucie (heat2) ---
T_INT = 0x00
T_STRING = 0x01
T_BLOB = 0x02
T_STRUCT = 0x03
T_LIST = 0x04
T_MAP = 0x05
T_UNION = 0x06
T_VARIABLE = 0x07
T_OBJTYPE = 0x08
T_OBJID = 0x09
T_FLOAT = 0x0A

UNION_UNSET = 0x7F         # brak aktywnego skladnika unii


# ---------------------------------------------------------------- tagi
def enc_tag(label: str) -> bytes:
    """4-znakowy tag -> 3 bajty (6 bitow/znak; spacja = 0). Lustro decode_tag."""
    label = (label + "    ")[:4]
    raw = 0
    for c in label:
        v = 0 if c == " " else (ord(c) - 0x20) & 0x3F
        raw = (raw << 6) | v
    return bytes(((raw >> 16) & 0xFF, (raw >> 8) & 0xFF, raw & 0xFF))


def dec_tag(b3: bytes) -> str:
    raw = (b3[0] << 16) | (b3[1] << 8) | b3[2]
    return "".join(" " if ((raw >> s) & 0x3F) == 0 else chr(((raw >> s) & 0x3F) + 0x20)
                   for s in (18, 12, 6, 0))


# ---------------------------------------------------------------- liczby (varint heat2)
def enc_int(v: int) -> bytes:
    """Varint heat2: 1. bajt bity0-5 = wartosc, bit6 = 'sa dalsze', kolejne
    bajty bity0-6 z bit7 = kontynuacja. (Kodujemy wartosci nieujemne.)"""
    if v < 0:
        raise ValueError("enc_int obsluguje tylko wartosci nieujemne")
    out = bytearray()
    if v < 0x40:
        out.append(v & 0x3F)
        return bytes(out)
    out.append(0x40 | (v & 0x3F))
    v >>= 6
    while True:
        if v < 0x80:
            out.append(v & 0x7F)
            break
        out.append(0x80 | (v & 0x7F))
        v >>= 7
    return bytes(out)


def dec_int(buf: bytes, p: int) -> tuple[int, int]:
    first = buf[p]; p += 1
    val = first & 0x3F
    if first & 0x40:
        shift = 6
        while True:
            bb = buf[p]; p += 1
            val |= (bb & 0x7F) << shift
            shift += 7
            if not bb & 0x80:
                break
    return val, p


# ---------------------------------------------------------------- wartosci
def enc_str(s: str | bytes) -> bytes:
    data = (s.encode("latin1") if isinstance(s, str) else s) + b"\x00"
    return enc_int(len(data)) + data


def dec_str(buf: bytes, p: int) -> tuple[str, int]:
    ln, p = dec_int(buf, p)
    s = buf[p:p + ln]; p += ln
    return s.rstrip(b"\x00").decode("latin1"), p


# ---------------------------------------------------------------- pola i struktury
@dataclass
class Field:
    """Jedno pole TDF: (tag, typ na drucie, wartosc juz zakodowana w bajtach)."""
    tag: str
    wtype: int
    value: bytes

    def encode(self) -> bytes:
        return enc_tag(self.tag) + bytes((self.wtype,)) + self.value


def f_int(tag: str, v: int) -> Field:
    return Field(tag, T_INT, enc_int(v))


def f_str(tag: str, s: str | bytes) -> Field:
    return Field(tag, T_STRING, enc_str(s))


def f_struct(tag: str, fields: list[Field]) -> Field:
    """Struktura zagniezdzona: pola + terminator 0x00 (konwencja heat2)."""
    return Field(tag, T_STRUCT, b"".join(f.encode() for f in fields) + b"\x00")


def f_union(tag: str, active: int, member: Field | None) -> Field:
    """Unia: indeks aktywnego skladnika + skladnik (tagowany), albo UNSET."""
    if member is None:
        return Field(tag, T_UNION, bytes((UNION_UNSET,)))
    return Field(tag, T_UNION, bytes((active,)) + member.encode())


def f_blob(tag: str, data: bytes) -> Field:
    return Field(tag, T_BLOB, enc_int(len(data)) + data)


def encode_tdf(fields: list[Field]) -> bytes:
    """Koduje liste pol jako cialo TDF najwyzszego poziomu (bez terminatora -
    dlugosc wyznacza ramka Fire2)."""
    return b"".join(f.encode() for f in fields)


# ---------------------------------------------------------------- ramka Fire2
FIRE2_HDR = 12


@dataclass
class Fire2:
    component: int
    command: int
    payload: bytes
    error: int = 0
    seq: int = 0
    msg_type: int = 0            # 0=REQUEST; odpowiedz zwykle tez 0 z error=0

    def encode(self) -> bytes:
        # Uklad naglowka jak w przechwyconym pakiecie: size(2) comp(2) cmd(2)
        # error(2) rez(2) seq... Ostatni bajt to numer sekwencyjny (u klienta
        # rosl 0,1,2...). Odpowiedz echo-uje seq zadania.
        hdr = struct.pack(">HHHH", len(self.payload), self.component,
                          self.command, self.error)
        hdr += bytes((0, 0, 0, self.seq & 0xFF))
        return hdr + self.payload

    @staticmethod
    def decode(b: bytes) -> "Fire2":
        size, comp, cmd, err = struct.unpack_from(">HHHH", b, 0)
        seq = b[11]
        return Fire2(component=comp, command=cmd, payload=b[FIRE2_HDR:FIRE2_HDR + size],
                     error=err, seq=seq)


# ---------------------------------------------------------------- dekoder TDF (pomocniczy)
def build_getserverinstance_response(ip: str, port: int, *, secure: bool = True,
                                     service: str = "nfs-rivals-pc",
                                     seq: int = 0) -> bytes:
    """DRAFT odpowiedzi Redirector.getServerInstance (comp 5, cmd 1, error 0).

    Kieruje gre pod podany adres (IP:port) - domyslnie na NAS, zeby po redirekcie
    klient polaczyl sie ponownie i wyslal kolejny pakiet (preAuth/auth), ktory
    znow odczytamy. Schemat ServerInstanceInfo ustalany EMPIRYCZNIE - to pierwsza
    proba oparta na tagach z docs/recon/tdf_members.json (MSTR/INST/ADDR/IP/PORT/
    SECU). Jesli klient odrzuci - log reakcji wskaze, co poprawic.

    Adres kodujemy jako union ServerAddressInfo, wariant IP (struct IP+PORT).
    Indeks aktywnego skladnika unii (ADDR_MEMBER_IP) to najbardziej niepewny
    element - latwy do zmiany w razie odrzucenia.
    """
    ADDR_MEMBER_IP = 0                     # <- do skorygowania empirycznie
    ip_int = int.from_bytes(bytes(int(o) for o in ip.split(".")), "big")

    # ServerAddressInfo (union) -> wariant IP: struct { IP int, PORT int }
    ip_struct = f_struct("VALU", [f_int("IP", ip_int), f_int("PORT", port)])
    addr = f_union("ADDR", ADDR_MEMBER_IP, ip_struct)

    # pojedyncza instancja serwera
    instance = f_struct("VALU", [addr, f_str("NAME", service)])

    server_instance_info = [
        f_int("SECU", 1 if secure else 0),
        addr,                              # adres na najwyzszym poziomie (redundancja pomaga)
        instance,                          # master/instancja
        f_str("SNAM", service),
    ]
    payload = encode_tdf(server_instance_info)
    return Fire2(component=5, command=1, payload=payload, error=0, seq=seq).encode()


def decode_tdf(buf: bytes, p: int = 0, end: int | None = None) -> list[tuple]:
    """Dekoduje pola do konca bufora/struktury. Zwraca liste (tag, typ, wartosc).
    Obsluguje typy, ktore realnie widzimy; nieznane konczy z surowym ogonem."""
    if end is None:
        end = len(buf)
    out = []
    while p < end:
        if buf[p] == 0x00:        # terminator struktury
            p += 1
            break
        tag = dec_tag(buf[p:p + 3]); wtype = buf[p + 3]; p += 4
        if wtype == T_STRING:
            v, p = dec_str(buf, p); out.append((tag, "str", v))
        elif wtype == T_INT:
            v, p = dec_int(buf, p); out.append((tag, "int", v))
        elif wtype == T_STRUCT:
            sub = []
            while p < end and buf[p] != 0x00:
                one = decode_tdf(buf, p, end)
                # decode_tdf zjada do terminatora; tu upraszczamy - patrz nizej
                break
            out.append((tag, "struct", "<...>"))
            # dla diagnostyki nie schodzimy glebiej; wystarcza nam pola plaskie
            return out
        else:
            out.append((tag, f"typ0x{wtype:02x}", buf[p:p + 8].hex()))
            return out
    return out
