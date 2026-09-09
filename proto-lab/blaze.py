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
                    latencies: list[int] | None = None) -> Field:
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
        f_ip_pair("ADDR", ip, port),
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
    body = bytes((T_STRING, T_STRING)) + enc_int(len(items))
    for k, v in items.items():
        body += enc_str(k) + enc_str(v)
    return Field(tag, T_MAP, body)


# Komponenty Blaze, ktore zwykle sa hostowane (CIDS). Klient dowiaduje sie z tego,
# jakie komponenty ma serwer. Zestaw orientacyjny - do korekty wg reakcji gry.
DEFAULT_COMPONENT_IDS = [1, 4, 5, 7, 9, 11, 15, 21, 25, 30, 63, 2000]


# Klucze client configu obecne w binarce (@0x016d2d80 i okolice: pingPeriod,
# defaultRequestTimeout, connIdleTimeout; @0x016ea7c8 associationListSkipInitialSet;
# @0x016eaac8 voipHeadsetUpdateRate). Wartosci sa nasze - klient parsuje je jako
# tekst, wiec liczby ida stringami.
DEFAULT_CLIENT_CONFIG = {
    "associationListSkipInitialSet": "1",
    "connIdleTimeout": "90",
    "defaultRequestTimeout": "30",
    "pingPeriod": "15000",                 # ms; gra i tak pinguje co ~15 s
    "voipHeadsetUpdateRate": "500",
}


def f_qos_ping_site(alias: str, host: str, port: int) -> list[Field]:
    """Pola QosPingSiteInfo (@0x1417065c0, potwierdzone z binarki):
    PSA(adres) PSP(port) SNA(nazwa site) - tagi rosnaco."""
    return [f_str("PSA", host), f_int("PSP", port), f_str("SNA", alias)]


def f_qos_settings(tag: str = "QOSS", *, alias: str = "ams",
                   host: str = "127.0.0.1", port: int = 17502,
                   service_id: int = 0) -> Field:
    """QosConfigInfo - ustawienia testu QoS.

    Sam QosConfigInfo nie ma tablicy pol w naszym zrzucie .rdata, ale zawarty w
    nim QosPingSiteInfo zgadza sie z emulatorem BF3 pole w pole (PSA/PSP/SNA),
    wiec bierzemy z BF3 tez uklad opakowania:
        BWPS(struct) LNP(int) LTPS(map alias->struct) SVID(int).
    Ping-site wskazuje na nas - inaczej klient sonduje martwe serwery EA.
    """
    site = f_qos_ping_site(alias, host, port)
    return f_struct(tag, [
        f_struct("BWPS", site),                      # bandwidth ping site
        f_int("LNP", 1),                             # liczba sond latencji
        f_map_struct("LTPS", {alias: site}),         # ping sites po aliasie
        f_int("SVID", service_id),
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


def _telemetry_fields(ip: str = "127.0.0.1", *, locale: int = 1701729619) -> list[Field]:
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
        f_int("PORT", 9988),
        f_int("SDLY", 15000),
        f_str("SESS", "telemetry_session"),
        f_str("SKEY", "telemetry_key"),
        f_int("SPCT", 0),                  # 0% probek - nic nie wysylamy
        f_str("STIM", "Default"),
    ]


def build_postauth_response(seq: int, *, msg_type: int = MSG_REPLY,
                            ip: str = "127.0.0.1",
                            user_id: int = REDACTED_EA_USER_ID) -> bytes:
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
    Wszystko wskazane na nas / neutralne, by klient dokonczyl polaczenie."""
    pss = f_struct("PSS", [
        f_str("ADRS", ip),
        f_blob("CSIG", b""),
        f_str("PJID", "123071"),
        f_int("PORT", 8443),
        f_int("RPRT", 9),
        f_int("TIID", 0),
    ])
    tele = f_struct("TELE", _telemetry_fields(ip))
    tick = f_struct("TICK", [
        f_str("ADRS", ip),
        f_int("PORT", 8999),
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


def build_useradded_notify(user_id: int = REDACTED_EA_USER_ID, persona: str = "PayTonkaaa",
                           session_key: str | None = None, *, component: int = 0x7802,
                           command: int = 2, seq: int = 0,
                           msg_type: int = MSG_NOTIFY_BYTE,
                           email: str = "player@nfsrivals.local",
                           rich_data: bool = True) -> bytes:
    """UserSessions notyfikacja UserAdded (cmd 1) = Blaze::NotifyUserAdded.
    Struktura (@0x1416d87d0): { DATA(UserSessionExtendedData) USER(mUserInfo) }.
    USER wypelniamy jako UserSessionLoginInfo (tozsamosc+sesja lokalnego usera).
    To najpewniejszy trigger: gra tworzy lokalnego usera i idzie do postAuth."""
    import time
    now = int(time.time())
    if session_key is None:
        session_key = f"1_{user_id}_sess"
    user = f_struct("USER", [                # UserSessionLoginInfo (tagi rosnaco)
        f_int("ALOC", 1701729619),           # locale (~enUS)
        f_int("BUID", user_id),              # blaze user id
        f_str("DSNM", persona),              # display name
        f_int("FRST", 0),
        f_str("KEY", session_key),
        f_int("LAST", now),
        f_int("LLOG", now),
        f_str("MAIL", email),
        f_int("PID", user_id),               # persona id
        f_int("PLAT", 4),                    # pc
        f_int("UID", user_id),
        f_int("USTP", 0),
        f_int("XREF", 0),
    ])
    data = f_extended_data("DATA") if rich_data else f_struct("DATA", [])
    payload = encode_tdf([data, user])       # DATA < USER
    return build_notification(component, command, payload, seq=seq, msg_type=msg_type)


def build_usersession_update(user_id: int = REDACTED_EA_USER_ID, *, component: int = 0x7802,
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
        else:
            lines.append(f"{pad}{tag} = {val!r}")
    return "\n".join(l for l in lines if l)
