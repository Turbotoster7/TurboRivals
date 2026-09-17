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


def f_map_struct(tag: str, items: dict[str, list[Field]]) -> Field:
    """Mapa heat2 string -> struktura: typ klucza, typ wartosci, licznik, potem
    pary (klucz, pola struktury + terminator) BEZ tagow (tak jak f_map_str)."""
    body = bytes((T_STRING, T_STRUCT)) + enc_int(len(items))
    for k, fields in items.items():
        body += enc_str(k) + b"".join(f.encode() for f in fields) + b"\x00"
    return Field(tag, T_MAP, body)


def f_map_empty(tag: str, key_wtype: int, val_wtype: int) -> Field:
    """Pusta mapa heat2: typ klucza + typ wartosci + licznik 0. Klient dostaje
    poprawnie otagowane, ale puste pole zamiast braku pola."""
    return Field(tag, T_MAP, bytes((key_wtype, val_wtype)) + enc_int(0))


# --- adresy sieciowe -------------------------------------------------------
# NetworkAddress to UNIA; warianty (potwierdzone wczesniej z binarki):
#   0=XboxClientAddress 1=XboxServerAddress 2=IpPairAddress 3=IpAddress 4=HostNameAddress
# Klient PC opisuje siebie jako IpPairAddress (@0x141706320): EXIP INIP MACI,
# gdzie EXIP/INIP to struktury adresu (@0x1416f8580): HOST IP PORT.
NETADDR_IPPAIR = 2
NETADDR_IPADDR = 3


def _ip_to_int(ip: str) -> int:
    return int.from_bytes(bytes(int(o) for o in ip.split(".")), "big")


def f_ip_pair(tag: str, ip: str = "127.0.0.1", port: int = 3659, *,
              machine_id: int = 0) -> Field:
    """Unia NetworkAddress z aktywnym IpPairAddress (adres wewn. == zewn.)."""
    inner = [f_int("IP", _ip_to_int(ip)), f_int("PORT", port)]
    pair = f_struct("VALU", [                    # tagi rosnaco: EXIP < INIP < MACI
        f_struct("EXIP", inner),
        f_struct("INIP", inner),
        f_int("MACI", machine_id),
    ])
    return f_union(tag, NETADDR_IPPAIR, pair)


def f_extended_data(tag: str = "DATA", *, ip: str = "127.0.0.1", port: int = 3659,
                    ping_site: str = "ams", country: str = "PL",
                    latencies: list[int] | None = None,
                    addr: tuple[int, int, int, int, int] | None = None) -> Field:
    """UserSessionExtendedData (@0x1416d7ac0) - stan sesji uzytkownika.

    Pola w kolejnosci tagow (heat2 czyta sekwencyjnie, wiec ROSNACO):
        ADDR(union NetworkAddress) BPS(str, alias najlepszego ping-site)
        CTY(str) DMAP(map) HWFG(int) PSLM(list latencji) QDAT(struct QosData)
        UATT(int) ULST(list ObjectId)

    Wczesniej wysylalismy tu PUSTA strukture. Klient po loginie trzyma w tym
    swoj wlasny stan sesji; bez adresu i wyniku QoS nie uznaje sie za gotowego
    online i nie wysyla updateNetworkInfo - stad ekran "Laczenie".
    """
    if latencies is None:
        latencies = [10]                          # jeden ping-site, 10 ms
    return f_struct(tag, [
        # addr = pelna para adresow gracza (exip, export, inip, inport, maci) - multiplayer: inni
        # gracze dostaja w UserAdded prawdziwy adres, nie 127.0.0.1
        f_union_ip_pair("ADDR", *addr) if addr else f_ip_pair("ADDR", ip, port),
        f_str("BPS", ping_site),
        f_str("CTY", country),
        f_map_empty("DMAP", T_INT, T_INT),        # mDataMap - brak danych wlasnych
        f_int("HWFG", 0),                         # mHardwareFlags
        f_list_int("PSLM", latencies),            # mLatencyList
        f_struct("QDAT", [                        # mQosData - wynik testu QoS
            f_int("DBPS", 100000),                # downstream bit/s
            f_int("NATT", 0),                     # NAT type: OPEN
            f_int("UBPS", 100000),                # upstream bit/s
        ]),
        f_int("UATT", 0),                         # mUserInfoAttribute
        f_list_empty("ULST", T_OBJID),            # mBlazeObjectIdList
    ])


def f_map_str(tag: str, items: dict[str, str]) -> Field:
    """Mapa heat2 string->string: typ klucza(1) + typ wartosci(1) + licznik +
    pary (klucz, wartosc) BEZ naglowkow tagow. Format wg TdfEncoder BlazeSDK
    (potwierdzony na emulatorze BF3 - ten sam silnik): keyType, valType, count,
    potem dla kazdej pary enc_str(key)+enc_str(val)."""
    # Klucze POSORTOWANE: klient trzyma mape jako posortowany wektor i szuka w nim
    # binarnie (lookup configu 0xf39cb0). W run-20 klucze bytevault* dopisane na koncu
    # (za voipHeadsetUpdateRate) byly przez to "nieznalezione" i ByteVault poszedl na
    # domyslny host EA. Serwery Blaze wysylaja mapy posortowane.
    body = bytes((T_STRING, T_STRING)) + enc_int(len(items))
    for k, v in sorted(items.items()):
        body += enc_str(k) + enc_str(v)
    return Field(tag, T_MAP, body)


# Komponenty Blaze, ktore zwykle sa hostowane (CIDS). Klient dowiaduje sie z tego,
# jakie komponenty ma serwer. Zestaw orientacyjny - do korekty wg reakcji gry.
DEFAULT_COMPONENT_IDS = [1, 4, 5, 7, 9, 11, 15, 21, 25, 30, 63, 2000]


# Klucze client configu obecne w binarce (@0x016d2d80 i okolice: pingPeriod,
# defaultRequestTimeout, connIdleTimeout; @0x016ea7c8 associationListSkipInitialSet;
# @0x016eaac8 voipHeadsetUpdateRate). Wartosci sa nasze - klient parsuje je jako
# tekst, wiec liczby ida stringami.
#
# CZASY MUSZA MIEC JEDNOSTKE. Trzy klucze czasu czyta tylko 0xf419b0, przez getter
# polaczenia 0xf39dc0 -> parser TimeValue 0xf79d60: segmenty <liczba><d|h|m|s|ms>
# (mozna laczyc, opcjonalnie przez ':'), wynik w mikrosekundach. Gola liczba ("90")
# konczy sie NUL-em zamiast jednostki -> parser zwraca false i nic nie zapisuje, a
# getter IGNORUJE ten wynik i melduje "znaleziony" -> czytnik bierze zmienna = 0.
# Tak bylo do 2026-09-13: connIdleTimeout="90" dawalo [conn+0x2fc]=0 ms i klient
# zrywal Blaze (0x800e0000) zaraz po preAuth. Domyslne klienta, gdy klucza brak
# (konstruktor 0xf2e7d0): idle 40 s, ping 15 s. Szczegoly: docs/protocol.md sekcja 11.
DEFAULT_CLIENT_CONFIG = {
    "associationListSkipInitialSet": "1",
    "connIdleTimeout": "90s",
    "defaultRequestTimeout": "30s",
    "pingPeriod": "15s",
    "voipHeadsetUpdateRate": "500",
}


def f_qos_ping_site(alias: str, host: str, port: int) -> list[Field]:
    """Pola QosPingSiteInfo (@0x1417065c0, odczytane z binarki):
    PSA(mAddress) PSP(mPort) SNA(mSiteName) - tagi rosnaco."""
    return [f_str("PSA", host), f_int("PSP", port), f_str("SNA", alias)]


def f_qos_settings(tag: str = "QOSS", *, alias: str = "ams",
                   host: str = "127.0.0.1", port: int = 17502,
                   service_id: int = 0, timeout_us: int = 5000000) -> Field:
    """QosConfigInfo (@0x141a32d80) - ustawienia testu QoS.

    Uklad ODCZYTANY Z BINARKI (nie zgadniety z BF3):
        BWPS(struct) mBandwidthPingSiteInfo
        LNP (uint16) mNumLatencyProbes
        LTPS(map)    mPingSiteInfoByAliasMap
        SVID(int32)  mServiceId
        TIME(czas)   mTimeout            <- tego pola NIE MA w ukladzie BF3

    Tablica pol tej klasy lezy w sekcji .data, nie .rdata - dlatego wczesniejszy
    skan jej nie widzial i uklad braliśmy przez analogie do BF3, bez TIME.
    Ping-site wskazuje na nas; inaczej klient sonduje martwe serwery EA.
    """
    site = f_qos_ping_site(alias, host, port)
    return f_struct(tag, [
        f_struct("BWPS", site),                      # mBandwidthPingSiteInfo
        f_int("LNP", 1),                             # mNumLatencyProbes
        f_map_struct("LTPS", {alias: site}),         # mPingSiteInfoByAliasMap
        f_int("SVID", service_id),                   # mServiceId
        f_int("TIME", timeout_us),                   # mTimeout (TimeValue, us)
    ])


def build_preauth_response(seq: int, *, msg_type: int = MSG_REPLY,
                           service: str = "nfs-rivals-pc",
                           component_ids: list[int] | None = None,
                           client_config: dict[str, str] | None = None,
                           qos: bool = True, qos_host: str = "127.0.0.1",
                           qos_port: int = 17502,
                           qos_alias: str = "ams", pad_to: int = 0) -> bytes:
    """Odpowiedz Util.preAuth (component 9, command 7).

    Schemat PreAuthResponse (@0x1416c6440, kolejnosc tagow rosnaca):
      ASRC(str) CIDS(list int) CONF(struct) ESRC(str) INST(str) MINR(?) NASP(str)
      PILD(str) PLAT(str) QOSS(struct) RSRC(str) SVER(str).

    CONF to ClientConfig (@0x1416c5870) = JEDNO pole CONF typu MAPA. Wczesniej
    szla tu pusta struktura, czyli struktura BEZ mapy w srodku - a klient prosi o
    config wprost: request preAuth zawiera FCCR{CFID='BlazeSDK'}.
    """
    if component_ids is None:
        component_ids = DEFAULT_COMPONENT_IDS
    if client_config is None:
        client_config = DEFAULT_CLIENT_CONFIG
    conf = f_struct("CONF", [f_map_str("CONF", client_config)]) if client_config \
        else f_struct("CONF", [])
    qoss = f_qos_settings(alias=qos_alias, host=qos_host, port=qos_port) if qos \
        else f_struct("QOSS", [])

    def fields_with(pild: str) -> list[Field]:
        return [
            f_str("ASRC", "205604"),                # authentication source (id)
            f_list_int("CIDS", component_ids),
            conf,                                    # ClientConfig{ CONF: mapa }
            f_str("ESRC", "205604"),                # entitlement source
            f_str("INST", service),
            f_str("NASP", "cem_ea_id"),              # persona namespace EA
            f_str("PILD", pild),
            f_str("PLAT", "pc"),
            qoss,                                    # QosConfigInfo
            f_str("RSRC", "205604"),
            f_str("SVER", "Blaze 3.15.08.0 (CL# 1058939)"),
        ]

    fields = fields_with("")
    if pad_to:
        # Diagnostyka: dopchnij odpowiedz do ~pad_to bajtow, wydluzajac ZWYKLY
        # string (PILD). Duza odpowiedz bez ani jednej mapy - izoluje pytanie
        # "czy klienta wywraca rozmiar, czy zawartosc".
        base_len = len(encode_tdf(fields)) + FIRE2_HDR
        missing = pad_to - base_len
        if missing > 0:
            fields = fields_with("x" * missing)
    payload = encode_tdf(fields)
    return Fire2(component=9, command=7, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_login_response(seq: int, user_id: int, persona: str, *,
                         msg_type: int = MSG_REPLY,
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


# Bajt msgType na drucie = typ_logiczny << 4 (REPLY 1->0x10, NOTIFICATION 2->0x20,
# potwierdzone na zywo). Zatem serwerowy PING = MSG_PING(4) << 4 = 0x40, a klient
# odsyla PING_REPLY (0x50).
MSG_PING_BYTE = MSG_PING << 4          # 0x40


def build_server_ping(seq: int = 0) -> bytes:
    """Transportowy heartbeat Fire2 (msgType=PING) wysylany PRZEZ SERWER.

    Po co: po loginie klient robi QoS na osobnych gniazdach, a polaczenie Blaze
    TCP nie ma ruchu. Aktualizacja polaczenia co klatke (0xf3a580) sprawdza
    `stan==2 && (teraz - ostatnia_aktywnosc) > [conn+0x2fc]` i przy przekroczeniu
    zrywa polaczenie bledem 0x800e0000 (0xeffca0) -> teardown -> crash. Ramka od
    serwera resetuje licznik aktywnosci po stronie odbioru klienta. PING jest
    najczystszy - to heartbeat transportu, klient odpowiada PING_REPLY i nie
    przetwarza go jak notyfikacji komponentu."""
    return Fire2(component=0, command=0, payload=b"", error=0, seq=seq,
                 msg_type=MSG_PING_BYTE).encode()


def _telemetry_fields(ip: str = "127.0.0.1", *, locale: int = 1701729619,
                      port: int = 9988) -> list[Field]:
    """Pola TelemetryServer (tag rosnaco) - wspolne dla TELE (postAuth) i
    getTelemetryServer (9/5). Wzor z emulatora BF3 (ten sam silnik), typy
    zweryfikowane ze zrzutem NFS (klasa @0x1416c7510): ADRS/DISA/FILT/NOOK/SESS/
    SKEY/STIM = string; ANON/LOC/PORT/SDLY/SPCT = int. Telemetria wskazana na nas
    (127.0.0.1) i praktycznie wylaczona (SPCT nieistotne - i tak nie mamy serwera
    telemetrii; klient tylko zapisuje te dane)."""
    return [
        f_str("ADRS", ip),
        f_int("ANON", 0),
        f_str("DISA", ""),                 # kraje z wylaczona telemetria - puste
        f_str("FILT", ""),
        f_int("LOC", locale),
        f_str("NOOK", "US,CA,MX"),
        f_int("PORT", port),
        f_int("SDLY", 15000),
        f_str("SESS", "telemetry_session"),
        f_str("SKEY", "telemetry_key"),
        f_int("SPCT", 0),                  # 0% probek - nic nie wysylamy
        f_str("STIM", "Default"),
    ]


def build_postauth_response(seq: int, user_id: int, *, msg_type: int = MSG_REPLY,
                            ip: str = "127.0.0.1",
                            subsystems: bool = True) -> bytes:
    """Odpowiedz Util.postAuth (component 9, command 8) = PostAuthResponse.
    Struktura (@0x1416c3b50): { PSS TELE TICK UROP } - 4 zagniezdzone struktury.

    WCZESNIEJ pusto: puste STRUKTURY crashowaly (gra uzywa pol), a caly pusty
    payload nie crashowal, ale gra utykala na "Laczenie". Teraz WYPELNIAMY wg
    emulatora Blaze dla BF3 (ten sam silnik Fire2/heat2) - pola i typy pokrywaja
    sie ze zrzutem NFS:
      PSS (PssConfig)   = { ADRS CSIG PJID PORT RPRT TIID }
      TELE (Telemetry)  = _telemetry_fields()
      TICK (Ticker)     = { ADRS PORT SKEY }
      UROP (UserOptions)= { TMOP UID }
    Wszystko wskazane na nas / neutralne, by klient dokonczyl polaczenie.

    A/B 2026-09-11 (subsystems=False): ADRS puste i PORT=0 we wszystkich trzech
    podsystemach. Po naszej odpowiedzi na postAuth klient SAM zamykal polaczenie
    Blaze, a zaraz potem wywracal sie na callbacku spod NULL w sciezce zdejmowania
    komponentu (base+0xf4de00). Hipoteza: klient probuje podniesc PSS/TELE/TICK
    pod adresami, pod ktorymi nikt nie slucha, i to konczy sesje. Struktur NIE
    usuwamy - puste STRUKTURY crashowaly juz wczesniej - tylko neutralizujemy
    adresy, wiec ksztalt i typy pol zostaja identyczne."""
    addr = ip if subsystems else ""
    pss = f_struct("PSS", [
        f_str("ADRS", addr),
        f_blob("CSIG", b""),
        f_str("PJID", "123071"),
        f_int("PORT", 8443 if subsystems else 0),
        f_int("RPRT", 9),
        f_int("TIID", 0),
    ])
    tele = f_struct("TELE", _telemetry_fields(addr,
                                             port=9988 if subsystems else 0))
    tick = f_struct("TICK", [
        f_str("ADRS", addr),
        f_int("PORT", 8999 if subsystems else 0),
        f_str("SKEY", f"{user_id}_tick"),
    ])
    urop = f_struct("UROP", [
        f_int("TMOP", 1),
        f_int("UID", user_id),
    ])
    payload = encode_tdf([pss, tele, tick, urop])       # PSS < TELE < TICK < UROP
    return Fire2(component=9, command=8, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_telemetry_response(seq: int, *, msg_type: int = MSG_REPLY,
                             ip: str = "127.0.0.1") -> bytes:
    """Odpowiedz Util.getTelemetryServer (component 9, command 5) =
    GetTelemetryServerResponse (te same pola co TELE w postAuth)."""
    payload = encode_tdf(_telemetry_fields(ip))
    return Fire2(component=9, command=5, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_fetch_client_config_response(seq: int, *, msg_type: int = MSG_REPLY,
                                       config: dict[str, str] | None = None) -> bytes:
    """Odpowiedz Util.fetchClientConfig (component 9, command 1) = { CONF map<str,str> }.
    Klient prosi o sekcje konfiguracji (CFID w zadaniu) i cache'uje odpowiedz.
    Pusta mapa = "brak wpisow dla tej sekcji" -> klient idzie dalej. Konkretne
    sekcje (np. listy achievementow) dopelnimy, jesli gra bez nich utknie."""
    payload = encode_tdf([f_map_str("CONF", config or {})])
    return Fire2(component=9, command=1, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_user_settings_load_all_response(seq: int, *, msg_type: int = MSG_REPLY,
                                          settings: dict[str, str] | None = None) -> bytes:
    """Odpowiedz Util.userSettingsLoadAll (component 9, command 0xC) =
    { SMAP map<str,str> } - zapisane ustawienia usera. Pusto na start."""
    payload = encode_tdf([f_map_str("SMAP", settings or {})])
    return Fire2(component=9, command=0xC, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_empty_reply(component: int, command: int, seq: int, *,
                      msg_type: int = MSG_REPLY) -> bytes:
    """Pusta odpowiedz-potwierdzenie (np. userSettingsSave 9/0xB). Sam naglowek
    Fire2 z error=0 - klient wie, ze RPC sie powiodlo i idzie dalej."""
    return Fire2(component=component, command=command, payload=b"", error=0,
                 seq=seq, msg_type=msg_type).encode()


MSG_NOTIFY_BYTE = 0x20        # bajt msgType dla notyfikacji (typ 2 w gornym nibble)


def build_notification(component: int, command: int, payload: bytes, *,
                       seq: int = 0, msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """Serwerowa notyfikacja Fire2 (async, nie odpowiedz)."""
    return Fire2(component=component, command=command, payload=payload,
                 error=0, seq=seq, msg_type=msg_type).encode()


def reseq(frame: bytes, seq: int) -> bytes:
    """Podmienia messageId (uint16 na offsecie 10) w gotowej ramce Fire2.
    Uzywane do nadania notyfikacjom wlasnej rosnacej sekwencji serwera."""
    return frame[:10] + struct.pack(">H", seq & 0xFFFF) + frame[12:]


def build_useradded_notify(user_id: int, persona: str,
                           session_key: str | None = None, *, component: int = 0x7802,
                           command: int = 2, seq: int = 0,
                           msg_type: int = MSG_NOTIFY_BYTE,
                           email: str = "player@nfsrivals.local",
                           rich_data: bool = True, legacy_user: bool = False,
                           addr: tuple[int, int, int, int, int] | None = None) -> bytes:
    """UserSessions notyfikacja UserAdded (cmd 2) = Blaze::NotifyUserAdded.
    Struktura (@0x1416d87d0): { DATA mExtendedData, USER mUserInfo }.

    USER = UserIdentification (tablica pol @0x1416d78c0, tagi z binarki):
        AID mAccountId  ALOC mAccountLocale  EXBB mExternalBlob  EXID mExternalId
        ID mBlazeId  NAME mName  ORIG mOriginPersonaId  PIDI mPidId
    Do 2026-09-13 wysylalismy tu tagi UserSessionLoginInfo (BUID DSNM KEY ...), z ktorych
    UserIdentification zna tylko ALOC - dekoder heat2 pomija nieznane tagi, wiec gra
    tworzyla lokalnego usera z ID=0 i pustym NAME (nie pasowal do BUID z loginu).
    Pewnosc: nazwy klas/pol z binarki + standardowy uklad BlazeSDK (mUserInfo to
    UserIdentification); sama tablica pol nie trzyma wskaznika na klase pola, wiec
    powiazania USER -> @0x1416d78c0 nie da sie odczytac z danych wprost.
    EXBB (kod typu 8, kodowanie nieustalone) pomijamy - brak pola = wartosc domyslna.
    legacy_user=True przywraca stary uklad (A/B)."""
    import time
    now = int(time.time())
    if session_key is None:
        session_key = f"1_{user_id}_sess"
    if legacy_user:
        user = f_struct("USER", [            # stary uklad: UserSessionLoginInfo
            f_int("ALOC", 1701729619),
            f_int("BUID", user_id),
            f_str("DSNM", persona),
            f_int("FRST", 0),
            f_str("KEY", session_key),
            f_int("LAST", now),
            f_int("LLOG", now),
            f_str("MAIL", email),
            f_int("PID", user_id),
            f_int("PLAT", 4),
            f_int("UID", user_id),
            f_int("USTP", 0),
            f_int("XREF", 0),
        ])
    else:
        user = f_struct("USER", [            # UserIdentification (tagi rosnaco)
            f_int("AID", user_id),           # mAccountId
            f_int("ALOC", 1701729619),       # mAccountLocale (~enUS)
            f_int("EXID", 0),                # mExternalId
            f_int("ID", user_id),            # mBlazeId - MUSI == BUID z loginu
            f_str("NAME", persona),          # mName
            f_int("ORIG", user_id),          # mOriginPersonaId
            f_int("PIDI", 0),                # mPidId
        ])
    data = f_extended_data("DATA", addr=addr) if rich_data else f_struct("DATA", [])
    payload = encode_tdf([data, user])       # DATA < USER
    return build_notification(component, command, payload, seq=seq, msg_type=msg_type)


def build_usersession_update(user_id: int, *, component: int = 0x7802,
                             command: int = 1, seq: int = 0,
                             msg_type: int = MSG_NOTIFY_BYTE,
                             rich_data: bool = True) -> bytes:
    """UserSessions notyfikacja UserSessionExtendedDataUpdate.
    Struktura (@0x1416d81c0): { DATA(UserSessionExtendedData) SUBS(bool) USID(int64) }.
    POTWIERDZONE (jump table createNotification): UserSessions=0x7802,
    ExtendedDataUpdate = command 1, UserAdded = command 2, UserAuthenticated = command 8."""
    payload = encode_tdf([
        f_extended_data("DATA") if rich_data else f_struct("DATA", []),
        f_int("SUBS", 1),
        f_int("USID", user_id),
    ])
    return build_notification(component, command, payload, seq=seq, msg_type=msg_type)


def f_objid(tag: str, component: int, obj_type: int, obj_id: int) -> Field:
    """EA::TDF::ObjectId na drucie heat2: trzy varinty (komponent, typ, id) - ten sam
    uklad, ktory czyta _dec_value dla T_OBJID."""
    return Field(tag, T_OBJID, enc_int(component) + enc_int(obj_type) + enc_int(obj_id))


def build_user_authenticated_notify(user_id: int, persona: str,
                                    session_key: str | None = None, *,
                                    component: int = 0x7802, command: int = 8, seq: int = 0,
                                    msg_type: int = MSG_NOTIFY_BYTE,
                                    email: str = "player@nfsrivals.local") -> bytes:
    """UserSessions notyfikacja UserAuthenticated (cmd 8).

    Klasa ODCZYTANA Z BINARKI: tablica pol @0x141a2f160, konstruktor 0xf5ccf0 w bloku
    cmd 8 dyspozytora notyfikacji UserSessions 0xf29f90. To splaszczone SessionInfo +
    PersonaDetails z odpowiedzi na login, plus ALOC, CGID i USTP:
        ALOC mAccountLocale  BUID mBlazeUserId  CGID mConnectionGroupObjectId (objid)
        DSNM mDisplayName  FRST mIsFirstLogin  KEY mSessionKey  LAST mLastAuthenticated
        LLOG mLastLoginDateTime  MAIL mEmail  PID mPersonaId  PLAT mClientPlatform
        UID mUserId  USTP mUserSessionType  XREF mExtId
    Kody typow pol sa identyczne jak w SessionInfo/PersonaDetails loginu (gra je
    dekoduje), wiec kodujemy je tak samo i z tymi samymi wartosciami.

    Do 2026-09-13 cmd 8 szlo z PUSTYM payloadem: gra dostawala "zalogowano usera" z
    BUID=0 i bez klucza sesji, a maszyna stanow online gry (0xa1bb00) stala na 5/6 i
    nie dochodzila do 9 (zalogowany) - ekran "Logowanie".
    CGID = (UserSessions 0x7802, typ 2, user_id): typ obiektu NIEPOTWIERDZONY w kodzie."""
    import time
    now = int(time.time())
    if session_key is None:
        session_key = f"1_{user_id}_sess"             # ten sam KEY co w loginie
    payload = encode_tdf([                             # tagi rosnaco
        f_int("ALOC", 1701729619),                     # jak USER w UserAdded
        f_int("BUID", user_id),
        f_objid("CGID", 0x7802, 2, user_id),
        f_str("DSNM", persona),
        f_int("FRST", 0),
        f_str("KEY", session_key),
        f_int("LAST", now),
        f_int("LLOG", now),
        f_str("MAIL", email),
        f_int("PID", user_id),
        f_int("PLAT", 4),                              # pc
        f_int("UID", user_id),
        f_int("USTP", 0),
        f_int("XREF", 0),
    ])
    return build_notification(component, command, payload, seq=seq, msg_type=msg_type)


# ---------------------------------------------------------------- RPC po zalogowaniu
# Numery komend z emulacji getCommandName w binarce (scratchpad rpcnames.py):
#   Authentication 0xf20180, Util 0xf28720, Stats 0xf28460, AssociationLists 0xf200b0,
#   NFS (komponent 2050) 0xf68100. Uklady klas z docs/recon/tdf_members.json.

def f_list_struct(tag: str, items: list[list[Field]]) -> Field:
    """Lista heat2 struktur: typ elementu(struct) + licznik + kazda struktura
    (pola + terminator 0x00) bez tagow elementow."""
    body = bytes((T_STRUCT,)) + enc_int(len(items))
    for fields in items:
        body += b"".join(f.encode() for f in fields) + b"\x00"
    return Field(tag, T_LIST, body)


def f_list_str(tag: str, values: list[str]) -> Field:
    body = bytes((T_STRING,)) + enc_int(len(values))
    for v in values:
        body += enc_str(v)
    return Field(tag, T_LIST, body)


def build_user_settings_load_response(seq: int, key: str, data: str = "", *,
                                      msg_type: int = MSG_REPLY) -> bytes:
    """Util.userSettingsLoad (9/10) -> UserSettingsResponse @0x1416c3f80 {DATA mData, KEY mKey}.
    Brak zapisanego ustawienia = pusty DATA."""
    payload = encode_tdf([f_str("DATA", data), f_str("KEY", key)])
    return Fire2(component=9, command=10, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_key_scopes_response(seq: int, *, msg_type: int = MSG_REPLY) -> bytes:
    """Stats.getKeyScopesMap (7/15) -> KeyScopes @0x1416c5a68 {KSIT mKeyScopesMap}
    (mapa nazwa -> KeyScopeItem). Brak zakresow = pusta mapa."""
    payload = encode_tdf([f_map_empty("KSIT", T_STRING, T_STRUCT)])
    return Fire2(component=7, command=15, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_stat_group_response(seq: int, name: str, *, msg_type: int = MSG_REPLY) -> bytes:
    """Stats.getStatGroup (7/4) -> StatGroupResponse @0x1416c4a10
    {CNAM DESC ETYP KSUM META NAME STAT}. ETYP (objtype) i KSUM pomijamy - brak pola
    = wartosc domyslna; STAT (lista StatDescSummary) pusta."""
    payload = encode_tdf([
        f_str("CNAM", ""),
        f_str("DESC", ""),
        f_str("META", ""),
        f_str("NAME", name),
        f_list_struct("STAT", []),
    ])
    return Fire2(component=7, command=4, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_get_lists_response(seq: int, *, msg_type: int = MSG_REPLY) -> bytes:
    """AssociationLists.getLists (25/6) -> Lists @0x1416aeb50 {LMAP mListMembersVector}.
    Bez znajomych = pusta lista ListMembers."""
    payload = encode_tdf([f_list_struct("LMAP", [])])
    return Fire2(component=25, command=6, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_geolocation_info_response(seq: int, blaze_id: int, *, country: str = "PL",
                                    msg_type: int = MSG_REPLY) -> bytes:
    """NFS (komponent 2050) getGeolocationInfo (38) -> GetGeolocationInfoResponse
    @0x1416d9890 {CNTY CTY ID LAT LON OPT OVER ST}."""
    payload = encode_tdf([
        f_str("CNTY", country),
        f_str("CTY", ""),
        f_int("ID", blaze_id),
        f_int("LAT", 0),
        f_int("LON", 0),
        f_int("OPT", 0),                    # mOptIn
        f_int("OVER", 0),                   # mIsOverridden
        f_str("ST", ""),
    ])
    return Fire2(component=2050, command=38, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


STATS_NOTIFY_GET_STATS_ASYNC = 0x32   # nazwa notyfikacji Stats 0xf29610: 0x32 -> GetStatsAsyncNotification


def build_stats_async_notification(view_id: int, group_name: str, entity_ids: list[int], *,
                                   seq: int = 0, msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """Wynik Stats.getStatsByGroupAsync (7/16) - przychodzi NOTYFIKACJA 7/0x32, nie odpowiedz.
    GetStatsAsyncNotification @0x1416c55d0 {GRNM mGroupName, KEY mKeyString, LAST mLast,
    STS mStatValues, VID mViewId}; STS = StatValues @0x1416c4310 {AGGR, STAT list<EntityStats>},
    EntityStats @0x1416c5d60 {EID ETYP POFF STAT list<string>}. LAST=1 zamyka widok VID -
    bez tej notyfikacji zapytanie asynchroniczne nigdy sie nie konczy."""
    entities = [[f_int("EID", eid), f_int("POFF", 0), f_list_str("STAT", [])]
                for eid in entity_ids]
    payload = encode_tdf([
        f_str("GRNM", group_name),
        f_str("KEY", ""),
        f_int("LAST", 1),
        f_struct("STS", [f_list_struct("AGGR", []), f_list_struct("STAT", entities)]),
        f_int("VID", view_id),
    ])
    return build_notification(7, STATS_NOTIFY_GET_STATS_ASYNC, payload, seq=seq,
                              msg_type=msg_type)


def build_get_auth_token_response(seq: int, token: str, *, msg_type: int = MSG_REPLY) -> bytes:
    """Authentication.getAuthToken (1/36) -> @0x1416ad9f8 {AUTH mAuthToken}. Gra wstawia ten
    token do naglowka Authorization zapytan ByteVault (bez niego szedl pusty)."""
    payload = encode_tdf([f_str("AUTH", token)])
    return Fire2(component=1, command=36, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


# ---------------------------------------------------------------- GameManager (komponent 4)
# Numery z tablic nazw w binarce: RPC 0xf68420 (1 createGame, 2 destroyGame, 3 advanceGameState,
# 15 finalizeGameCreation, 29 updateMeshConnection), notyfikacje 0xf69450 (20 NotifyGameSetup,
# 30 NotifyPlayerJoinCompleted, 100 NotifyGameStateChange). Enumy z tablic {nazwa, wartosc}.
GM_NOTIFY_GAME_SETUP = 20
GM_NOTIFY_PLAYER_JOIN_COMPLETED = 30
GM_NOTIFY_GAME_STATE_CHANGE = 100
GAME_STATE = {"NEW_STATE": 0, "INITIALIZING": 1, "INACTIVE_VIRTUAL": 2, "PRE_GAME": 130,
              "IN_GAME": 131, "POST_GAME": 4, "MIGRATING": 5, "DESTRUCTING": 6, "RESETABLE": 7}
PLAYER_STATE = {"RESERVED": 0, "QUEUED": 1, "ACTIVE_CONNECTING": 2, "ACTIVE_MIGRATING": 3,
                "ACTIVE_CONNECTED": 4, "ACTIVE_KICK_PENDING": 5}
JOIN_STATE_JOINED_GAME = 0
SETUP_CONTEXT_CREATE_GAME = 0


def _ip_pair_fields(exip: int, export: int, inip: int, inport: int, maci: int) -> list[Field]:
    """Pola IpPairAddress w kolejnosci tagow: EXIP{IP MACI PORT} INIP{IP MACI PORT} MACI."""
    return [f_struct("EXIP", [f_int("IP", exip), f_int("MACI", 0), f_int("PORT", export)]),
            f_struct("INIP", [f_int("IP", inip), f_int("MACI", 0), f_int("PORT", inport)]),
            f_int("MACI", maci)]


def f_union_ip_pair(tag: str, exip: int, export: int, inip: int, inport: int, maci: int) -> Field:
    """Pole-unia NetworkAddress z aktywnym IpPairAddress (wariant 2), jak ADDR w ExtendedData."""
    return f_union(tag, 2, f_struct("VALU", _ip_pair_fields(exip, export, inip, inport, maci)))


def f_list_ip_pair(tag: str, exip: int, export: int, inip: int, inport: int, maci: int) -> Field:
    """Lista NetworkAddress (HNET). Typ elementu na drucie = 3 (struct), ale element to UNIA:
    bajt wariantu (2 = IpPairAddress) + pola czlonu + terminator 0x00. Uklad podpatrzony w
    zadaniu createGame wyslanym przez klienta (HNET: 03 01 02 EXIP... MACI... 00)."""
    body = bytes((T_STRUCT,)) + enc_int(1) + bytes((2,))
    body += b"".join(f.encode() for f in _ip_pair_fields(exip, export, inip, inport, maci)) + b"\x00"
    return Field(tag, T_LIST, body)


def build_create_game_response(seq: int, game_id: int, *, command: int = 1,
                               msg_type: int = MSG_REPLY) -> bytes:
    """GameManager.createGame (4/1) -> @0x141a300b0 {GID mGameId, JGS mJoinState, REX}."""
    payload = encode_tdf([f_int("GID", game_id), f_int("JGS", JOIN_STATE_JOINED_GAME),
                          f_list_struct("REX", [])])
    return Fire2(component=4, command=command, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_reset_dedicated_server_response(seq: int, game_id: int, *,
                                          msg_type: int = MSG_REPLY) -> bytes:
    """GameManager.resetDedicatedServer (4/25) -> ta sama klasa co createGame: w binarce NIE MA
    stringu "ResetDedicatedServerResponse" (jest tylko ...SetupContext), a CreateGameResponse
    @0x141a300b0 to jedyna odpowiedz GameManagera z samym GID."""
    return build_create_game_response(seq, game_id, command=25, msg_type=msg_type)


# SlotType z tablicy {nazwa, wartosc} @0x1416d9790 (MAX_PARTICIPANT_SLOT_TYPE = 2, INVALID = -1).
SLOT_TYPE = {"SLOT_PUBLIC_PARTICIPANT": 0, "SLOT_PRIVATE_PARTICIPANT": 1,
             "SLOT_PUBLIC_SPECTATOR": 2, "SLOT_PRIVATE_SPECTATOR": 3}


def build_replicated_player(game_id: int, player: dict) -> list[Field]:
    """ReplicatedGamePlayer @0x141a2f3a0 (18 z 20 pol) - gracz w rosterze NotifyGameSetup i w
    NotifyPlayerJoining. player = {uid, persona, slot, state, addr=(exip, export, inip, inport, maci)}.
    Numer miejsca gracza idzie do SID (mSlotId) i CSID (mConnectionSlotId); SLOT to mSlotType, czyli
    rodzaj miejsca, nie numer. Do 15.09 numer trafial do SLOT, a SID/CSID byly 0 u kazdego gracza -
    dolaczajacy dostawal to samo miejsce polaczenia co host (log-29: obie gry meldowaly STAT=0)."""
    import time
    uid = player["uid"]
    slot = player.get("slot", 0)
    return [                                           # tagi rosnaco
        f_int("CONG", uid),
        f_int("CSID", slot),
        f_int("EXID", 0),
        f_int("GID", game_id),
        f_int("JFPS", 0),
        f_int("LOC", 1701729619),
        f_str("NAME", player["persona"]),
        f_map_str("PATT", {}),
        f_int("PID", uid),
        f_union_ip_pair("PNET", *player["addr"]),
        f_str("ROLE", ""),
        f_int("SID", slot),
        f_int("SLOT", SLOT_TYPE["SLOT_PUBLIC_PARTICIPANT"]),
        f_int("STAT", player.get("state", PLAYER_STATE["ACTIVE_CONNECTED"])),
        f_int("TIDX", 0),
        f_int("TIME", int(time.time())),
        f_int("UID", uid),
        f_str("UUID", ""),
    ]


def build_notify_game_setup(game_id: int, host_id: int, players: list[dict], *, game_name: str,
                            game_settings: int, network_topology: int, presence_mode: int,
                            voip: int, version_string: str, max_players: int,
                            slot_capacities: list[int], team_ids: list[int],
                            attributes: dict[str, str],
                            host_addr: tuple[int, int, int, int, int], game_state: int = 1,
                            setup_context: tuple[int, int, int] | str | None = None,
                            host_slot: int = 0, creator_id: int = 0,
                            admins: list[int] | None = None,
                            seq: int = 0, msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyGameSetup (4/20) @0x1416d7cf0 {GAME mGameData, LFPJ, PROS mGameRoster, QUEU,
    REAS mGameSetupReason}. GAME = ReplicatedGameData @0x141a2f590 (tu 32 z 42 pol, reszta
    domyslna), PROS = roster (build_replicated_player dla kazdego gracza z `players`), host
    (ADMN, HSES, OGHI, PHST/THST) = host_id, HNET = adres hosta. REAS = unia: wariant 0
    DatalessSetupContext {DCTX = CREATE_GAME_SETUP_CONTEXT}, 1 ResetDedicatedServerSetupContext
    (setup_context="reset_dedicated", bez pol) albo 3 MatchmakingSetupContext.
    Wartosci gry (nazwa, ustawienia, topologia, VSTR, pojemnosc) bierzemy z zadania klienta
    tworzacego gre, zeby dostal to, o co prosil; dolaczajacy dostaje te same."""
    # The host's slot has to be the real one. It used to be hardwired to 0, which held while the
    # host was always the creator of the game (slot 0). After a host migration the new host keeps
    # its own slot (1 in test 50) and a returning player gets the freed slot 0 - so a joiner was
    # told the topology host sat in its OWN slot, never opened a mesh connection and gave up.
    host_info = [f_int("CONG", host_id), f_int("CSID", host_slot), f_int("HPID", host_id),
                 f_int("HSLT", host_slot)]
    exip, export, inip, inport, maci = host_addr
    user_id = host_id
    game = [                                           # tagi rosnaco
        f_list_int("ADMN", list(admins) if admins else [user_id]),
        f_map_str("ATTR", attributes),
        f_list_int("CAP", slot_capacities),
        f_int("GID", game_id),
        f_int("GMRG", 0),
        f_str("GNAM", game_name),
        f_int("GPVH", 0),
        f_int("GSET", game_settings),
        f_int("GSID", game_id),
        f_int("GSTA", game_state),
        f_str("GTYP", ""),
        f_str("GURL", ""),
        f_list_ip_pair("HNET", exip, export, inip, inport, maci),
        f_int("HSES", user_id),
        f_int("IGNO", 0),
        f_map_str("MATR", {}),
        f_int("MCAP", max_players),
        f_struct("NQOS", [f_int("DBPS", 100000), f_int("NATT", 0), f_int("UBPS", 100000)]),
        f_int("NRES", 0),
        f_int("NTOP", network_topology),
        # OGHI is mGameCreatorId (ReplicatedGameData @0x141a2f590), not the current host. Same
        # value until a host migration; after one, a joiner must see the same creator as the host.
        f_int("OGHI", creator_id or user_id),
        f_str("PGID", ""),
        f_struct("PHST", host_info),
        f_int("PRES", presence_mode),
        f_str("PSAS", "ams"),
        f_int("QCAP", 0),
        f_int("SEED", 0x5EED),
        f_struct("THST", host_info),
        f_list_int("TIDS", team_ids),
        f_str("UUID", f"turborivals-game-{game_id}"),
        f_int("VOIP", voip),
        f_str("VSTR", version_string),
    ]
    if setup_context == "reset_dedicated":             # resetDedicatedServer: kontekst bez pol
        reas = f_union("REAS", GAME_SETUP_REASON_RESET_DEDICATED, f_struct("VALU", []))
    elif setup_context is None:                        # createGame: DatalessSetupContext
        reas = f_union("REAS", 0, f_struct("VALU", [f_int("DCTX", SETUP_CONTEXT_CREATE_GAME)]))
    else:                                              # matchmaking: (MSID, RSLT, USID)
        mm_session_id, mm_result, user_session_id = setup_context
        reas = f_union("REAS", GAME_SETUP_REASON_MATCHMAKING, f_struct("VALU", [
            f_int("FIT", MM_FIT_SCORE), f_int("MAXF", MM_FIT_SCORE), f_int("MSID", mm_session_id),
            f_int("RSLT", mm_result), f_int("USID", user_session_id)]))
    payload = encode_tdf([
        f_struct("GAME", game),
        f_int("LFPJ", 0),
        f_list_struct("PROS", [build_replicated_player(game_id, p) for p in players]),
        f_list_struct("QUEU", []),
        reas,
    ])
    return build_notification(4, GM_NOTIFY_GAME_SETUP, payload, seq=seq, msg_type=msg_type)


def build_notify_game_state_change(game_id: int, state: int, *, seq: int = 0,
                                   msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyGameStateChange (4/100) @0x141a2ff08 {GID mGameId, GSTA mNewGameState}."""
    payload = encode_tdf([f_int("GID", game_id), f_int("GSTA", state)])
    return build_notification(4, GM_NOTIFY_GAME_STATE_CHANGE, payload, seq=seq, msg_type=msg_type)


def build_notify_player_join_completed(game_id: int, player_id: int, *, seq: int = 0,
                                       msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyPlayerJoinCompleted (4/30) - kandydat klasy {GID mGameId, PID mPlayerId}."""
    payload = encode_tdf([f_int("GID", game_id), f_int("PID", player_id)])
    return build_notification(4, GM_NOTIFY_PLAYER_JOIN_COMPLETED, payload, seq=seq,
                              msg_type=msg_type)


# ---------------------------------------------------------------- GameManager: matchmaking (4/13)
# StartMatchmakingRequest @0x141a30840 (stringi "StartMatchmakingRequest::m..."): MODE mSessionMode
# (run-26: 3 = szukaj i utworz), DUR mSessionDurationMS (6000), CRIT mCriteriaData, GNAM, GSET, GVER,
# NTOP, PMAX, PNET, PRES, TID, VOIP. Enum MatchmakingResult z tablicy {nazwa, wartosc} @0x1416d8f00.
MATCHMAKING_RESULT = {"SUCCESS_CREATED_GAME": 0, "SUCCESS_JOINED_NEW_GAME": 1,
                      "SUCCESS_JOINED_EXISTING_GAME": 2, "SESSION_TIMED_OUT": 3,
                      "SESSION_CANCELED": 4, "SESSION_TERMINATED": 5,
                      "SESSION_ERROR_GAME_SETUP_FAILED": 6}
GM_NOTIFY_MATCHMAKING_FAILED = 10
# Unia GameSetupReason: tablice czlonow @0x141a30280.. kolejno Dataless(0), ResetDedicatedServer(1),
# IndirectJoinGame(2), Matchmaking(3), IndirectMatchmaking(4). Wariant 0 dziala od run-23 (createGame).
# MatchmakingSetupContext @0x141a30120 {FIT mFitScore, MAXF mMaxPossibleFitScore, MSID mSessionId,
# RSLT mMatchmakingResult, USID mUserSessionId}.
GAME_SETUP_REASON_MATCHMAKING = 3
# Wariant 1 unii = mResetDedicatedServerSetupContext (tablica @0x141a30298). Sama klasa
# NIE MA pol: miedzy DatalessSetupContext {DCTX} @0x141a30100 a MatchmakingSetupContext
# {FIT...} @0x141a30120 nie ma zadnej tablicy czlonkow, wiec VALU zostaje puste.
GAME_SETUP_REASON_RESET_DEDICATED = 1
MM_FIT_SCORE = 100      # FIT = MAXF: dopasowanie to ulamek FIT/MAXF - nie wysylamy zer


def build_start_matchmaking_response(seq: int, session_id: int, *,
                                     msg_type: int = MSG_REPLY) -> bytes:
    """StartMatchmakingResponse {MSID}. Tag MSID maja w binarce dwie klasy-kandydaci: @0x1416da370
    {MSID mMatchmakingSessionId} i @0x1416d9ef0 {COID ESNM MSID mSessionId SCID STMN} (pola sesji
    zewnetrznej Xbox) - samo MSID pasuje do obu, reszta zostaje domyslna."""
    payload = encode_tdf([f_int("MSID", session_id)])
    return Fire2(component=4, command=13, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_notify_matchmaking_failed(session_id: int, user_session_id: int, result: int, *,
                                    seq: int = 0, msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyMatchmakingFailed (4/10) @0x141a30a90 {MAXF mMaxPossibleFitScore, MSID mSessionId,
    RSLT mMatchmakingResult, USID mUserSessionId}."""
    payload = encode_tdf([f_int("MAXF", MM_FIT_SCORE), f_int("MSID", session_id),
                          f_int("RSLT", result), f_int("USID", user_session_id)])
    return build_notification(4, GM_NOTIFY_MATCHMAKING_FAILED, payload, seq=seq, msg_type=msg_type)


# ---------------------------------------------------------------- GameManager: kilku graczy
# Numery notyfikacji z tablicy nazw 0xf69450. Enumy z tablic {nazwa, wartosc} w zrzucie:
#   PlayerRemovedReason @0x1416d9d70, PlayerNetConnectionStatus @0x1416d9ae8,
#   GameDestructionReason @0x1416d9ba0.
GM_NOTIFY_GAME_REMOVED = 16
GM_NOTIFY_PLAYER_JOINING = 21
GM_NOTIFY_PLAYER_REMOVED = 40
PLAYER_REMOVED_REASON = {"PLAYER_JOIN_TIMEOUT": 0, "PLAYER_CONN_LOST": 1, "BLAZESERVER_CONN_LOST": 2,
                         "GAME_DESTROYED": 4, "GAME_ENDED": 5, "PLAYER_LEFT": 6, "GROUP_LEFT": 7,
                         "PLAYER_KICKED": 8}
GAME_DESTRUCTION_REASON = {"SYS_GAME_ENDING": 0, "HOST_LEAVING": 3, "LOCAL_PLAYER_LEAVING": 6}
MESH_STATUS = {"DISCONNECTED": 0, "ESTABLISHING_CONNECTION": 1, "CONNECTED": 2}


def build_notify_player_joining(game_id: int, player: dict, *, seq: int = 0,
                                msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyPlayerJoining (4/21) @0x1416d8220 {GID mGameId, PDAT mJoiningPlayer} - do graczy juz
    bedacych w grze, gdy ktos dolacza. PDAT = ReplicatedGamePlayer dolaczajacego."""
    payload = encode_tdf([f_int("GID", game_id),
                          f_struct("PDAT", build_replicated_player(game_id, player))])
    return build_notification(4, GM_NOTIFY_PLAYER_JOINING, payload, seq=seq, msg_type=msg_type)


def build_notify_player_removed(game_id: int, player_id: int, reason: int, *, seq: int = 0,
                                msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyPlayerRemoved (4/40), kandydat klasy @0x141a30560 {CNTX mPlayerRemovedTitleContext,
    GID mGameId, LFPJ mLockedForPreferredJoins, PID mPlayerId, REAS mPlayerRemovedReason} -
    uklad z nazw pol (zadania removePlayer maja te same tagi bez LFPJ)."""
    payload = encode_tdf([f_int("CNTX", 0), f_int("GID", game_id), f_int("LFPJ", 0),
                          f_int("PID", player_id), f_int("REAS", reason)])
    return build_notification(4, GM_NOTIFY_PLAYER_REMOVED, payload, seq=seq, msg_type=msg_type)


def build_notify_game_removed(game_id: int, reason: int, *, seq: int = 0,
                              msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyGameRemoved (4/16), kandydat klasy @0x141a303a8 {GID mGameId, REAS mDestructionReason}."""
    payload = encode_tdf([f_int("GID", game_id), f_int("REAS", reason)])
    return build_notification(4, GM_NOTIFY_GAME_REMOVED, payload, seq=seq, msg_type=msg_type)


# Numery notyfikacji GameManager odczytane z tablicy skokow getNotificationName 0xf69450 (indeks =
# id-10: bajt @0xf6963c, offset RVA @0xf695a8): 10 MatchmakingFailed, 12 MatchmakingAsyncStatus,
# 16 GameRemoved, 20 GameSetup, 21 PlayerJoining, 22 JoiningPlayerInitiateConnections, 23 PlayerJoiningQueue,
# 24 PlayerPromotedFromQueue, 25 PlayerClaimingReservation, 30 PlayerJoinCompleted, 40 PlayerRemoved,
# 60 HostMigrationFinished, 70 HostMigrationStart, 71 PlatformHostInitialized, 80 GameAttribChange,
# 90 PlayerAttribChange, 95 PlayerCustomDataChange, 100 GameStateChange, 110 GameSettingsChange,
# 111 GameCapacityChange, 112 GameReset, 113 GameReportingIdChange, 115 GameSessionUpdated,
# 116 GamePlayerStateChange, 117 GamePlayerTeamRoleSlotChange, 118 GameTeamIdChange, 119 ProcessQueue,
# 120 PresenceModeChanged, 121 QueueChanged, 122 GameRecreateRequested, 123 GameModRegisterChanged,
# 124 GameEntryCriteriaChanged, 201 GameListUpdate, 202 AdminListChange,
# 220 CreateDynamicDedicatedServerGame, 230 GameNameChange.
GM_NOTIFY_ADMIN_LIST_CHANGE = 202
GM_NOTIFY_GAME_PLAYER_STATE_CHANGE = 116
# UpdateAdminListOperation z tablicy {nazwa, wartosc} @0x1416da628.
GM_ADMIN_OPERATION = {"GM_ADMIN_ADDED": 0, "GM_ADMIN_REMOVED": 1, "GM_ADMIN_MIGRATED": 2}


def build_notify_game_player_state_change(game_id: int, player_id: int, state: int, *,
                                          seq: int = 0, msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyGamePlayerStateChange (4/116) @0x141a30660 {GID mGameId, PID mPlayerId,
    STAT mPlayerState}; `state` z PLAYER_STATE.

    Klasa wyodrebniona z tdf_members.json miedzy {GID, PID} a {GID, PID, ROLE, SLOT} - klasy leza
    w tej samej kolejnosci co numery notyfikacji (116 GamePlayerStateChange, 117
    GamePlayerTeamRoleSlotChange). Rozna od NotifyPlayerJoinCompleted (30): 30 mowi "dolaczanie
    zakonczone", 116 niesie STAN gracza. Do run-39 wysylalismy tylko 30, a stan zmienialismy
    wylacznie u siebie - obiekt gracza u dolaczajacego zostawal w ACTIVE_CONNECTING."""
    payload = encode_tdf([f_int("GID", game_id), f_int("PID", player_id), f_int("STAT", state)])
    return build_notification(4, GM_NOTIFY_GAME_PLAYER_STATE_CHANGE, payload, seq=seq,
                              msg_type=msg_type)


# ---------------------------------------------------------------- GameManager: host migration
# The game itself supports migration, not just the SDK: NFS14.exe carries
# ClientHostMigrationManagerEntity, WaitingForHostMigration and the UI string
# ID_ONLINE_HOST_MIGRATION_FAILED. HostMigrationType read from the {name, value} table
# @0x1416da118 in NFS14.exe.
GM_NOTIFY_HOST_MIGRATION_FINISHED = 60
GM_NOTIFY_HOST_MIGRATION_START = 70
HOST_MIGRATION_TYPE = {"TOPOLOGY_HOST_MIGRATION": 0, "PLATFORM_HOST_MIGRATION": 1,
                       "TOPOLOGY_PLATFORM_HOST_MIGRATION": 2}


def build_notify_host_migration_start(game_id: int, new_host_id: int, slot: int, *,
                                      migration_type: int = 0, seq: int = 0,
                                      msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyHostMigrationStart (4/70) @0x141a305e0 {CSLT mNewHostConnectionSlotId, GID mGameId,
    HOST mNewHostId, PMIG mMigrationType, SLOT mNewHostSlotId}.

    Found in the run of GameManager notification classes laid out in id order, between
    NotifyPlayerRemoved (40) @0x141a30560 and NotifyGamePlayerStateChange (116) @0x141a30660 -
    the same method that recovered the working 4/116. Here SLOT is the new host's slot NUMBER
    (mNewHostSlotId), unlike the roster, where SLOT is the slot type; the number that goes to
    SID/CSID in the roster goes to both SLOT and CSLT here.

    Must reach clients BEFORE NotifyPlayerRemoved of the old host: on 15.09 (log-29) a client
    that got the host removed with no migration announced tore the game down and crashed."""
    payload = encode_tdf([f_int("CSLT", slot), f_int("GID", game_id), f_int("HOST", new_host_id),
                          f_int("PMIG", migration_type), f_int("SLOT", slot)])
    return build_notification(4, GM_NOTIFY_HOST_MIGRATION_START, payload, seq=seq,
                              msg_type=msg_type)


def build_notify_host_migration_finished(game_id: int, *, seq: int = 0,
                                         msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyHostMigrationFinished (4/60). ASSUMED layout {GID mGameId}: a single-field class
    cannot be isolated from tdf_members.json by tag order, and {GID} is what BlazeSDK uses.
    First suspect if a migration hangs in WaitingForHostMigration."""
    payload = encode_tdf([f_int("GID", game_id)])
    return build_notification(4, GM_NOTIFY_HOST_MIGRATION_FINISHED, payload, seq=seq,
                              msg_type=msg_type)


GM_NOTIFY_PLATFORM_HOST_INITIALIZED = 71


def build_notify_platform_host_initialized(game_id: int, host_id: int, slot: int, *, seq: int = 0,
                                           msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyPlatformHostInitialized (4/71). PROBABLE layout @0x1416d8db8 {BUID mUserId,
    GID mGameId, PHID mPlatformHostId, PHST mPlatformHostSlotId} - the only class carrying both
    mPlatformHostId and mPlatformHostSlotId.

    Closes the platform half of a TOPOLOGY_PLATFORM_HOST_MIGRATION. In test 53 we migrated only
    the topology host: the new host kept the mesh but stopped acting as the game's owner (no
    addAdminPlayer for a joiner), and a player joining the migrated game left after ~8 s."""
    payload = encode_tdf([f_int("BUID", host_id), f_int("GID", game_id), f_int("PHID", host_id),
                          f_int("PHST", slot)])
    return build_notification(4, GM_NOTIFY_PLATFORM_HOST_INITIALIZED, payload, seq=seq,
                              msg_type=msg_type)


def build_notify_admin_list_change(game_id: int, admin_id: int, operation: int, updater_id: int, *,
                                   seq: int = 0, msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyAdminListChange (4/202) @0x141a30480 {ALST mAdminPlayerId, GID mGameId, OPER mOperation,
    UID mUpdaterPlayerId} - do wszystkich graczy gry po addAdminPlayer (4/106) i removeAdminPlayer
    (4/107). Zadanie tych RPC to @0x1416d8978 {GID mGameId, PID mAdminPlayerId}."""
    payload = encode_tdf([f_int("ALST", admin_id), f_int("GID", game_id), f_int("OPER", operation),
                          f_int("UID", updater_id)])
    return build_notification(4, GM_NOTIFY_ADMIN_LIST_CHANGE, payload, seq=seq, msg_type=msg_type)


# ---------------------------------------------------------------- Authentication.listUserEntitlements2
# Enumy z tablic {nazwa, wartosc} w .rdata: EntitlementType @0x1416aeac0, EntitlementStatus @0x1416ac490.
ENTITLEMENT_TYPE = {"UNKNOWN": 0, "ONLINE_ACCESS": 1, "TRIAL_ONLINE_ACCESS": 2, "SUBSCRIPTIONS": 3,
                    "PARENTAL_APPROVAL": 4, "DEFAULT": 5}
ENTITLEMENT_STATUS = {"UNKNOWN": 0, "ACTIVE": 1, "DISABLED": 2, "PENDING": 3, "DELETED": 4, "BANNED": 5}


def build_list_entitlements_response(seq: int, entitlements: list[dict], *,
                                     msg_type: int = MSG_REPLY) -> bytes:
    """Authentication.listUserEntitlements2 (1/29) -> Entitlements @0x1416adfe8 {NLST mEntitlements},
    element Entitlement @0x141a2b2b0 {DEVI GDAY GNAM ID ISCO PID PJID PRCA PRID STAT STRC TAG TDAY TYPE
    UCNT VER}. entitlements = [{id, group, type, tag, persona_id, product_id, project_id, status,
    grant_date}] - brakujace pola zostaja domyslne."""
    rows = [[
        f_str("DEVI", ""),
        f_str("GDAY", e.get("grant_date", "")),
        f_str("GNAM", e["group"]),
        f_int("ID", e["id"]),
        f_int("ISCO", 0),
        f_int("PID", e.get("persona_id", 0)),
        f_str("PJID", e.get("project_id", "")),
        f_int("PRCA", 0),
        f_str("PRID", e.get("product_id", "")),
        f_int("STAT", e.get("status", ENTITLEMENT_STATUS["ACTIVE"])),
        f_int("STRC", 0),
        f_str("TAG", e.get("tag", "")),
        f_str("TDAY", ""),
        f_int("TYPE", e["type"]),
        f_int("UCNT", 0),
        f_int("VER", 0),
    ] for e in entitlements]
    payload = encode_tdf([f_list_struct("NLST", rows)])
    return Fire2(component=1, command=29, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


# ---------------------------------------------------------------- Util.filterForProfanity
# Nazwy enuma FilterResult w .rdata @0x16c70d0.. w tej kolejnosci; klient wysyla w zadaniu
# DIRT=2 dla tekstu jeszcze nie sprawdzonego, co zgadza sie z numeracja od zera (UNPROCESSED).
FILTER_RESULT = {"PASSED": 0, "OFFENSIVE": 1, "UNPROCESSED": 2, "STRING_TOO_LONG": 3, "OTHER": 4}


def build_filter_profanity_response(seq: int, texts: list[str], *,
                                    msg_type: int = MSG_REPLY) -> bytes:
    """Util.filterForProfanity (9/20). Zadanie i odpowiedz to ta sama klasa @0x1416c41d8
    {TLST mFilteredTextList}, element @0x141a2e150 {DIRT mResult, UTXT mFilteredText}.
    Nie filtrujemy: kazdy tekst wraca bez zmian z wynikiem PASSED, w kolejnosci zadania."""
    items = [[f_int("DIRT", FILTER_RESULT["PASSED"]), f_str("UTXT", t)] for t in texts]
    payload = encode_tdf([f_list_struct("TLST", items)])
    return Fire2(component=9, command=20, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


# ---------------------------------------------------------------- nazwy komend RPC
# Z emulacji 13 funkcji getCommandName w binarce (switch po numerze -> `lea rax, nazwa; ret`),
# zrzut NFS14-0912.DMP.dmp. Numery komponentow z ruchu. Komponent 28 nie ma w binarce tablicy
# nazw - "GameReporting" wynika z klasy zadania {FNSH PRVT RPRT} (@0x141a32ad0).
_RPC_TABLES = {
    (1, "Authentication"): """20 updateAccount 21 upgradeAccount 29 listUserEntitlements2
        30 getAccount 31 grantEntitlement 32 listEntitlements 34 getUseCount 35 decrementUseCount
        36 getAuthToken 38 getPasswordRules 39 grantEntitlement2 43 modifyEntitlement2
        44 consumecode 45 passwordForgot 47 getPrivacyPolicyContent 48 listPersonaEntitlements2
        51 checkAgeReq 52 getOptIn 53 enableOptIn 54 disableOptIn 60 expressLogin 70 logout
        90 getPersona 100 listPersonas 101 expressCreateAccount 152 originLogin
        210 validateSessionKey 230 createWalUserSession 241 acceptLegalDocs
        242 getEmailOptInSettings 246 getTermsOfServiceContent 260 getOriginPersona
        270 checkEmail 280 getPersonaNameSuggestions 290 guestLogin""",
    (4, "GameManager"): """1 createGame 2 destroyGame 3 advanceGameState 4 setGameSettings
        5 setPlayerCapacity 6 setPresenceMode 7 setGameAttributes 8 setPlayerAttributes 9 joinGame
        11 removePlayer 13 startMatchmaking 14 cancelMatchmaking 15 finalizeGameCreation
        18 setPlayerCustomData 19 replayGame 20 returnDedicatedServerToPool 22 leaveGameByGroup
        23 migrateGame 24 updateGameHostMigrationStatus 25 resetDedicatedServer
        26 updateGameSession 27 banPlayer 29 updateMeshConnection 30 joinGameByUserList
        31 removePlayerFromBannedList 32 clearBannedList 33 getBannedList
        38 addQueuedPlayerToGame 39 updateGameName 40 ejectHost 41 setGameModRegister
        42 setGameEntryCriteria 43 preferredJoinOptOut 100 getGameListSnapshot
        101 getGameListSubscription 102 destroyGameList 103 getFullGameData
        104 getMatchmakingConfig 105 getGameDataFromId 106 addAdminPlayer 107 removeAdminPlayer
        109 changeGameTeamId 110 migrateAdminPlayer 111 getUserSetGameListSubscription
        112 swapPlayers 113 getGameDataByUser 152 getGameListSnapshotSync""",
    (5, "Redirector"): "1 getServerInstance",
    (7, "Stats"): """1 getStatDescs 2 getStats 3 getStatGroupList 4 getStatGroup 5 getStatsByGroup
        6 getDateRange 7 getEntityCount 10 getLeaderboardGroup 11 getLeaderboardFolderGroup
        12 getLeaderboard 13 getCenteredLeaderboard 14 getFilteredLeaderboard 15 getKeyScopesMap
        16 getStatsByGroupAsync 17 getLeaderboardTreeAsync 18 getLeaderboardEntityCount
        19 getStatCategoryList 20 getPeriodIds 21 getLeaderboardRaw 22 getCenteredLeaderboardRaw
        23 getFilteredLeaderboardRaw 24 changeKeyscopeValue 25 getEntityRank""",
    (9, "Util"): """1 fetchClientConfig 2 ping 3 setClientData 4 localizeStrings
        5 getTelemetryServer 6 getTickerServer 7 preAuth 8 postAuth 10 userSettingsLoad
        11 userSettingsSave 12 userSettingsLoadAll 14 deleteUserSettings 20 filterForProfanity
        21 fetchQosConfig 22 setClientMetrics 23 setConnectionState 24 getPssConfig
        25 getUserOptions 26 setUserOptions 27 suspendUserPing 28 setClientState""",
    (25, "AssociationLists"): """1 addUsersToList 2 removeUsersFromList 3 clearLists
        4 setUsersToList 5 getListForUser 6 getLists 7 subscribeToLists 8 unsubscribeFromLists
        9 getConfigListsInfo 10 getMemberHash""",
    (28, "GameReporting"): "",
    (2050, "NFS"): """11 getBestScores 14 uploadEntitlements 20 getInGameSpeedWalls
        21 getInGameRecommendations 25 sendTwoWayCommunicationCustomMessage
        26 getFriendsRecommendations 27 ignoreFriendRecommendation 29 getAutologPlaylist
        30 setAutologPlaylist 31 setRecommendationRivalScore 32 setRichPresenceWatchList
        33 setInGameRichPresence 34 getInGameRichPresence 35 setOverwatchWeaponFeedback
        37 setGeolocationInfo 38 getGeolocationInfo 39 getSpecialGuestInfo
        40 setSpecialGuestAttempt 41 getSpecialGuestSpeedWall 42 setGeoLocationOptOut
        43 getGeolocationFromIP 44 getOverwatchStats 45 incrementOverwatchStats
        46 resetOverwatchStats 47 getOverwatchStatsConfig
        48 sendTwoWayCommunicationCustomMessageSpendFuel 61 reportContent 62 fetchContent
        63 showContent""",
    (0x7802, "UserSessions"): """3 fetchExtendedData 5 updateExtendedDataAttribute
        8 updateHardwareFlags 12 lookupUser 13 lookupUsers 14 lookupUsersByPrefix
        15 lookupUsersIdentification 20 updateNetworkInfo 23 lookupUserGeoIPData
        24 overrideUserGeoIPData 25 updateUserSessionClientData 26 setUserInfoAttribute
        27 resetUserGeoIPData 32 lookupUserSessionId 33 fetchLastLocaleUsedAndAuthError
        34 fetchUserFirstLastAuthTime 35 resumeSession 37 setUserGeoOptIn
        41 enableUserAuditLogging 42 disableUserAuditLogging""",
}
COMPONENT_NAMES = {comp: name for comp, name in _RPC_TABLES}
RPC_NAMES = {}
for (_comp, _cname), _spec in _RPC_TABLES.items():
    _tok = _spec.split()
    for _num, _name in zip(_tok[::2], _tok[1::2]):
        RPC_NAMES[(_comp, int(_num))] = f"{_cname}.{_name}"


def rpc_name(component: int, command: int) -> str:
    """"Komponent.komenda" z tablic binarki; sam komponent, gdy komendy nie znamy; "" gdy nic."""
    if (component, command) in RPC_NAMES:
        return RPC_NAMES[(component, command)]
    return f"{COMPONENT_NAMES[component]}#{command}" if component in COMPONENT_NAMES else ""


# ---------------------------------------------------------------- NFS.getInGameSpeedWalls (2050/20)
# Klasy przypiete do tablic pol po stringach "Klasa::mPole" z binarki (np.
# "InGameSpeedWallResponseRow::mStatsFlt"):
#   InGameSpeedWallsRequest          @0x1416b76c0 {BLID mBlazeId, SWIS mSpeedWallIds, USGE, USPG}
#   InGameSpeedWallResponseSpeedWall @0x1416b7120 {ROWS mSpeedWall, SWID mSpeedWallId}
#   InGameSpeedWallResponseRow       @0x1416b87a0 {BLUS mBlazeUser, STAF mStatsFlt, STAI mStatsInt,
#                                                  STAS mStatsStr}
#   BlazeUser (kandydat, nazwy pol)  @0x141a2c040 {BLIS mBlazeId, PENA mPersonaName, URTY mRelationType}
# Wiersz ma te same mapy STAF/STAI/STAS, co wpis gracza w raporcie GameReporting ({ENTI STAF STAI
# STAS}), a id speed walla to ENTI z raportu - serwer odsyla zapisane statystyki obiektu.
# InGameSpeedWallResponse::mSpeedwalls ma w binarce dwie mozliwe tablice pol: lista pod tagiem ROWS
# (@0x1416b50f0, @0x1416b61e8) albo SPWA (@0x1416b5870). Wysylamy OBA tagi z ta sama lista - dekoder
# heat2 klienta pomija tagi nieznane swojej klasie.

def f_map_int(tag: str, items: dict[str, int]) -> Field:
    """Mapa heat2 string -> int, klucze posortowane (jak f_map_str)."""
    body = bytes((T_STRING, T_INT)) + enc_int(len(items))
    for k, v in sorted(items.items()):
        body += enc_str(k) + enc_int(int(v))
    return Field(tag, T_MAP, body)


def f_map_float(tag: str, items: dict[str, float]) -> Field:
    """Mapa heat2 string -> float: 4 B big-endian, tak jak czyta _dec_value (wartosci z raportow
    wychodza sensowne, np. speed=69.1). Klucze posortowane."""
    body = bytes((T_STRING, T_FLOAT)) + enc_int(len(items))
    for k, v in sorted(items.items()):
        body += enc_str(k) + struct.pack(">f", float(v))
    return Field(tag, T_MAP, body)


def build_in_game_speed_walls_response(seq: int, walls: list[tuple[int, list[dict]]], *,
                                       msg_type: int = MSG_REPLY) -> bytes:
    """walls = [(id speed walla, [wiersz, ...])], wiersz = {blaze_id, persona, int, float, str}.
    Speed wall bez zapisanych danych idzie z pusta lista wierszy - gra dostaje odpowiedz na kazde
    zapytane id."""
    items = []
    for swid, rows in walls:
        row_structs = [[
            f_struct("BLUS", [f_int("BLIS", r["blaze_id"]), f_str("PENA", r.get("persona", "")),
                              f_int("URTY", 0)]),
            f_map_float("STAF", r.get("float", {})),
            f_map_int("STAI", r.get("int", {})),
            f_map_str("STAS", r.get("str", {})),
        ] for r in rows]
        items.append([f_list_struct("ROWS", row_structs), f_int("SWID", swid)])
    payload = encode_tdf([f_list_struct("ROWS", items), f_list_struct("SPWA", items)])
    return Fire2(component=2050, command=20, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def _dec_value(buf: bytes, p: int, wtype: int, end: int) -> tuple[object, int]:
    """Dekoduje JEDNA wartosc danego typu; zwraca (wartosc, nowa pozycja).
    Wartosci bez taga - uzywane tez dla elementow list i par mapy."""
    if wtype == T_INT:
        return dec_int(buf, p)
    if wtype == T_STRING:
        return dec_str(buf, p)
    if wtype == T_BLOB:
        ln, p = dec_int(buf, p)
        return buf[p:p + ln], p + ln
    if wtype == T_STRUCT:
        return _dec_fields(buf, p, end)
    if wtype == T_UNION:
        active = buf[p]; p += 1
        if active == UNION_UNSET:
            return ("union", "unset"), p
        member, p = _dec_one_field(buf, p, end)
        return ("union", active, member), p
    if wtype == T_LIST:
        elem = buf[p]; p += 1
        n, p = dec_int(buf, p)
        items = []
        for _ in range(n):
            if elem == T_STRUCT and 0 < buf[p] < 0x80:
                # Element listy struktur bywa UNIA: bajt wariantu przed polami czlonu. Tak
                # klient koduje HNET (createGame, resetDedicatedServer) i tak samo koduje to
                # nasz f_list_ip_pair. Poznajemy po tym, ze pierwszy bajt TAGA ma zawsze
                # ustawiony bit 7 (pierwszy znak taga >= '@'), a numer wariantu jest mniejszy;
                # zero zostawiamy terminatorowi pustej struktury.
                variant = buf[p]; p += 1
                v, p = _dec_value(buf, p, elem, end)
                items.append(("union", variant, v))
                continue
            v, p = _dec_value(buf, p, elem, end)
            items.append(v)
        return items, p
    if wtype == T_MAP:
        kt, vt = buf[p], buf[p + 1]; p += 2
        n, p = dec_int(buf, p)
        pairs = []
        for _ in range(n):
            k, p = _dec_value(buf, p, kt, end)
            v, p = _dec_value(buf, p, vt, end)
            pairs.append((k, v))
        return dict(pairs) if all(isinstance(k, (str, int)) for k, _ in pairs) else pairs, p
    if wtype == T_OBJTYPE:
        a, p = dec_int(buf, p)
        b, p = dec_int(buf, p)
        return (a, b), p
    if wtype == T_OBJID:
        a, p = dec_int(buf, p)
        b, p = dec_int(buf, p)
        c, p = dec_int(buf, p)
        return (a, b, c), p
    if wtype == T_FLOAT:
        return struct.unpack_from(">f", buf, p)[0], p + 4
    if wtype == T_VARIABLE:
        # Pole "variable" (obiekt TDF dowolnej klasy): bajt obecnosci; gdy 1 - tdfId klasy
        # (varint) i pola obiektu zakonczone 0x00. Tak wyglada raport GameReporting 28/2:
        # PRVT = 00 (brak), RPRT.GAME = 01 + id + struktura.
        present = buf[p]; p += 1
        if not present:
            return ("variable", None), p
        tdf_id, p = dec_int(buf, p)
        fields, p = _dec_fields(buf, p, end)
        return ("variable", tdf_id, fields), p
    raise ValueError(f"nieznany typ TDF 0x{wtype:02x} na offsecie {p - 1}")


def _dec_one_field(buf: bytes, p: int, end: int) -> tuple[tuple, int]:
    tag = dec_tag(buf[p:p + 3])
    wtype = buf[p + 3]
    v, p = _dec_value(buf, p + 4, wtype, end)
    return (tag, wtype, v), p


def _dec_fields(buf: bytes, p: int, end: int) -> tuple[list, int]:
    """Pola az do terminatora struktury (0x00) albo konca bufora."""
    out = []
    while p < end:
        if buf[p] == 0x00:                 # terminator zagniezdzonej struktury
            return out, p + 1
        f, p = _dec_one_field(buf, p, end)
        out.append(f)
    return out, p


def decode_tdf(buf: bytes, p: int = 0, end: int | None = None) -> list[tuple]:
    """Dekoduje payload TDF (heat2) REKURENCYJNIE. Zwraca liste (tag, typ, wartosc);
    struktury/unie/listy/mapy schodza w glab. Sluzy do weryfikacji round-trip
    wlasnych odpowiedzi: jesli nasz dekoder gubi sie na naszym pakiecie, gra
    tym bardziej."""
    if end is None:
        end = len(buf)
    fields, _ = _dec_fields(buf, p, end)
    return fields


def dump_tdf(fields: list[tuple], indent: int = 0) -> str:
    """Czytelny wydruk drzewa pol (do logu i testow)."""
    pad = "  " * indent
    lines = []
    for tag, wtype, val in fields:
        if wtype == T_STRUCT:
            lines.append(f"{pad}{tag} (struct)")
            lines.append(dump_tdf(val, indent + 1))
        elif wtype == T_UNION and isinstance(val, tuple) and val[0] == "union":
            if val[1] == "unset":
                lines.append(f"{pad}{tag} (union) = UNSET")
            else:
                lines.append(f"{pad}{tag} (union, wariant {val[1]})")
                lines.append(dump_tdf([val[2]], indent + 1))
        elif wtype == T_VARIABLE and isinstance(val, tuple) and val[0] == "variable":
            if val[1] is None:
                lines.append(f"{pad}{tag} (variable) = BRAK")
            else:
                lines.append(f"{pad}{tag} (variable, tdfId 0x{val[1]:x})")
                lines.append(dump_tdf(val[2], indent + 1))
        else:
            lines.append(f"{pad}{tag} = {val!r}")
    return "\n".join(l for l in lines if l)
