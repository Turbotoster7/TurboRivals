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
    """Varint heat2 (zweryfikowany na polu LOC z zywego zadania):
    1. bajt: bity 0-5 = wartosc, bit6 = ZNAK (ujemna), bit7 = KONTYNUACJA;
    kolejne bajty: bity 0-6 = wartosc, bit7 = kontynuacja.
    UWAGA: kontynuacja to ZAWSZE bit7 - wczesniejsza wersja mylila go z bit6
    (znakiem), przez co IP/PORT >= 0x40 wychodzily zle i klient odrzucal cert."""
    neg = v < 0
    if neg:
        v = -v
    out = bytearray()
    b = v & 0x3F
    v >>= 6
    if neg:
        b |= 0x40
    if v:
        b |= 0x80
    out.append(b)
    while v:
        b = v & 0x7F
        v >>= 7
        if v:
            b |= 0x80
        out.append(b)
    return bytes(out)


def dec_int(buf: bytes, p: int) -> tuple[int, int]:
    b = buf[p]; p += 1
    neg = b & 0x40
    val = b & 0x3F
    shift = 6
    while b & 0x80:
        b = buf[p]; p += 1
        val |= (b & 0x7F) << shift
        shift += 7
    return (-val if neg else val), p


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

# messageType (pole uint16 na offsecie 8 naglowka). Wartosci wg Blaze Fire2.
MSG_MESSAGE = 0        # zadanie (tak wysyla klient)
MSG_REPLY = 1          # odpowiedz na zadanie (tak MUSIMY odpowiedziec)
MSG_NOTIFICATION = 2
MSG_ERROR_REPLY = 3
MSG_PING = 4
MSG_PING_REPLY = 5


@dataclass
class Fire2:
    """Ramka Fire2. Naglowek 12 B = 6x uint16 BE:
    size, component, command, errorCode, messageType, messageId.
    W zadaniu klienta messageType=MESSAGE(0), messageId rosnie 0,1,2...
    Odpowiedz MUSI miec messageType=REPLY(1) i ten sam messageId (echo)."""
    component: int
    command: int
    payload: bytes
    error: int = 0
    seq: int = 0                 # messageId
    msg_type: int = MSG_MESSAGE

    def encode(self) -> bytes:
        # Naglowek 12 B: size(2) comp(2) cmd(2) err(2) msgType(1) reserved(1) msgId(2)
        # UWAGA: messageType to POJEDYNCZY BAJT na offsecie 8 (nie uint16 na [8-9]).
        # Wczesniej kodowany jako uint16 -> REPLY(1) ladowal 0x00 w bajcie 8 =>
        # gra czytala nasza odpowiedz jako MESSAGE (kolejne zadanie), nie REPLY.
        return struct.pack(">HHHHBBH", len(self.payload), self.component,
                           self.command, self.error, self.msg_type & 0xFF, 0,
                           self.seq & 0xFFFF) + self.payload

    @staticmethod
    def decode(b: bytes) -> "Fire2":
        size, comp, cmd, err = struct.unpack_from(">HHHH", b, 0)
        mtype = b[8]
        mid = struct.unpack_from(">H", b, 10)[0]
        return Fire2(component=comp, command=cmd,
                     payload=b[FIRE2_HDR:FIRE2_HDR + size],
                     error=err, seq=mid, msg_type=mtype)


# ---------------------------------------------------------------- dekoder TDF (pomocniczy)
def f_list_empty(tag: str, elem_wtype: int) -> Field:
    """Pusta lista heat2: typ elementu + licznik 0."""
    return Field(tag, T_LIST, bytes((elem_wtype,)) + enc_int(0))


def build_getserverinstance_response(ip: str, port: int, *, secure: bool = True,
                                     service: str = "nfs-rivals-pc",
                                     seq: int = 0, addr_index: int = 0,
                                     minimal: bool = False,
                                     msg_type: int = MSG_REPLY,
                                     host: str | None = None) -> bytes:
    """Odpowiedz Redirector.getServerInstance (comp 5, cmd 1, error 0).

    Schemat WYCIAGNIETY z odszyfrowanej binarki (zrzut pamieci + map_tdf_classes):
    klasa ServerInstanceInfo (@0x1416f6890) ma pola w kolejnosci tagow:
        ADDR (union, mAddress) | AMAP (list) | CERT (list, mCertificateList) |
        MSGS (list) | NMAP (list) | SECU (bool, mSecure) | XDNS (int, mDefaultDnsAddress)
    Struktura adresu (@0x1416f8580): HOST (mHostname) | IP (mIp) | PORT (mPort).

    WAZNE: heat2 wymaga pol w ROSNACEJ kolejnosci tagow (tak wygladal request:
    BSDK<BTIM<...<NAME). Emitujemy dokladnie w tej kolejnosci, inaczej dekoder
    pomija pola (to pogrzebalo pierwszy draft - ADDR szedl po SECU, malejaco).

    Kieruje gre pod podany adres - domyslnie na NAS, by klient wrocil z kolejnym
    pakietem (preAuth/auth). Podajemy i HOST, i IP, zeby klient mogl uzyc dowolnego.

    Nadal empiryczne (log reakcji potwierdzi): indeks/tag skladnika unii ADDR.
    """
    ADDR_MEMBER_INDEX = addr_index         # 0=ServerAddressInfo.mIpAddress; do prob
    ADDR_MEMBER_TAG = "VALU"
    ip_int = int.from_bytes(bytes(int(o) for o in ip.split(".")), "big")

    # union ADDR -> skladnik = struct adresu {HOST, IP, PORT} (rosnaco po tagu).
    # HOST = nazwa hosta, ktora (a) jest w pliku hosts -> wskazuje na nas oraz
    # (b) pasuje do CN certu (gosredirector.ea.com) - inaczej gra odrzuca cert na
    # polaczeniu Blaze. Gra WOLI HOST (rozwiazuje go) nad polem IP.
    addr_struct = f_struct(ADDR_MEMBER_TAG, [
        f_str("HOST", host if host is not None else ip),
        f_int("IP", ip_int),
        f_int("PORT", port),
    ])
    if minimal:
        # tylko ADDR - izolacja unii (bez list/bool, ktore moga psuc dekodowanie)
        fields = [f_union("ADDR", ADDR_MEMBER_INDEX, addr_struct)]
    else:
        fields = [
            f_union("ADDR", ADDR_MEMBER_INDEX, addr_struct),
            f_list_empty("AMAP", T_STRUCT),
            f_list_empty("CERT", T_STRUCT),
            f_list_empty("MSGS", T_STRING),
            f_list_empty("NMAP", T_STRUCT),
            f_int("SECU", 1 if secure else 0),
            f_int("XDNS", ip_int),
        ]
    payload = encode_tdf(fields)
    return Fire2(component=5, command=1, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def f_list_int(tag: str, values: list[int]) -> Field:
    """Lista heat2 int: typ elementu(int=0) + licznik + wartosci."""
    body = bytes((T_INT,)) + enc_int(len(values))
    for v in values:
        body += enc_int(v)
    return Field(tag, T_LIST, body)


# Komponenty Blaze, ktore zwykle sa hostowane (CIDS). Klient dowiaduje sie z tego,
# jakie komponenty ma serwer. Zestaw orientacyjny - do korekty wg reakcji gry.
DEFAULT_COMPONENT_IDS = [1, 4, 5, 7, 9, 11, 15, 21, 25, 30, 63, 2000]


def build_preauth_response(seq: int, *, msg_type: int = MSG_REPLY,
                           service: str = "nfs-rivals-pc",
                           component_ids: list[int] | None = None) -> bytes:
    """Odpowiedz Util.preAuth (component 9, command 7).

    Schemat PreAuthResponse (z binarki, kolejnosc tagow rosnaca):
      ASRC(str) CIDS(list int) CONF(struct) ESRC(str) INST(str) MINR(?) NASP(str)
      PILD(str) PLAT(str) QOSS(struct) RSRC(str) SVER(str).
    Pierwsza proba: wypelniamy stringi + CIDS + puste CONF/QOSS. Reszta opcjonalna.
    """
    if component_ids is None:
        component_ids = DEFAULT_COMPONENT_IDS
    fields = [
        f_str("ASRC", "205604"),                    # authentication source (id)
        f_list_int("CIDS", component_ids),
        f_struct("CONF", []),                        # config map - pusto na start
        f_str("ESRC", "205604"),                    # entitlement source
        f_str("INST", service),
        f_str("NASP", "cem_ea_id"),                  # persona namespace EA
        f_str("PILD", ""),
        f_str("PLAT", "pc"),
        f_struct("QOSS", []),                        # QoS settings - pusto na start
        f_str("RSRC", "205604"),
        f_str("SVER", "Blaze 3.15.08.0 (CL# 1058939)"),
    ]
    payload = encode_tdf(fields)
    return Fire2(component=9, command=7, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_login_response(seq: int, *, msg_type: int = MSG_REPLY,
                         user_id: int = REDACTED_EA_USER_ID, persona: str = "PayTonkaaa",
                         email: str = "player@nfsrivals.local") -> bytes:
    """Odpowiedz Authentication.login (component 1, command 152) = FullLoginResponse.

    Struktura z binarki:
      FullLoginResponse{ AGUP ANON NTOS PCTK SESS SPAM UNDR }
        SESS=SessionInfo{ BUID FRST KEY LLOG MAIL PDTL UID }
          PDTL=PersonaDetails{ DSNM LAST PID PLAT STAS XREF }
    """
    import time
    now = int(time.time())
    pdtl = f_struct("PDTL", [
        f_str("DSNM", persona),
        f_int("LAST", now),
        f_int("PID", user_id),
        f_int("PLAT", 4),                 # pc
        f_int("STAS", 2),                 # ACTIVE
        f_int("XREF", 0),
    ])
    sess = f_struct("SESS", [
        f_int("BUID", user_id),
        f_int("FRST", 0),
        f_str("KEY", f"1_{user_id}_sess"),
        f_int("LLOG", now),
        f_str("MAIL", email),
        pdtl,
        f_int("UID", user_id),
    ])
    fields = [
        f_int("AGUP", 0),
        f_int("ANON", 0),
        f_int("NTOS", 0),
        f_str("PCTK", ""),
        sess,
        f_int("SPAM", 1),
        f_int("UNDR", 0),
    ]
    payload = encode_tdf(fields)
    return Fire2(component=1, command=152, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_ping_response(seq: int, *, msg_type: int = MSG_REPLY) -> bytes:
    """Odpowiedz Util.ping (component 9, command 2) = { STIM mServerTime }."""
    import time
    payload = encode_tdf([f_int("STIM", int(time.time()))])
    return Fire2(component=9, command=2, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_postauth_response(seq: int, *, msg_type: int = MSG_REPLY) -> bytes:
    """Odpowiedz Util.postAuth (component 9, command 8) = PostAuthResponse.
    Struktura (@0x1416c3b50): { PSS TELE TICK UROP (struct) ... }. Na start puste."""
    payload = encode_tdf([
        f_struct("PSS", []),
        f_struct("TELE", []),
        f_struct("TICK", []),
        f_struct("UROP", []),
    ])
    return Fire2(component=9, command=8, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


MSG_NOTIFY_BYTE = 0x20        # bajt msgType dla notyfikacji (typ 2 w gornym nibble)


def build_notification(component: int, command: int, payload: bytes, *,
                       seq: int = 0, msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """Serwerowa notyfikacja Fire2 (async, nie odpowiedz)."""
    return Fire2(component=component, command=command, payload=payload,
                 error=0, seq=seq, msg_type=msg_type).encode()


def build_usersession_update(user_id: int = REDACTED_EA_USER_ID, *, component: int = 30,
                             command: int = 5, seq: int = 0,
                             msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """UserSessions notyfikacja UserSessionExtendedDataUpdate.
    Struktura (@0x1416d81c0): { DATA(UserSessionExtendedData) SUBS(bool) USID(int64) }.
    DATA na start puste. component/command UserSessions do potwierdzenia empirycznie
    (standard Blaze: UserSessions=30; command notyfikacji 1/5 do proby)."""
    payload = encode_tdf([
        f_struct("DATA", []),
        f_int("SUBS", 1),
        f_int("USID", user_id),
    ])
    return build_notification(component, command, payload, seq=seq, msg_type=msg_type)


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
