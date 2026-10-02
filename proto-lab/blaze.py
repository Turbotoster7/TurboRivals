#!/usr/bin/env python3
"""Blaze protocol encoder/decoder: the Fire2 frame + TDF (heat2).

Once TLS is broken (tls_terminator.py) we read the Blaze traffic in the clear.
The client's first packet is Redirector.getServerInstance (component 5, cmd 1).
For the game to go any further we have to ANSWER - and that needs a TDF
encoder. This module mirrors the decoder verified on a captured packet
(docs/recon/capture, blaze-first-*.bin): 24-bit tag (6 bits/char), 1-byte type,
then the value. The format was established empirically and by round-tripping a
real packet.

NOTE on the response schema: the .text section of the Steam binary is encrypted
(entropy 1.000), so map_tdf_classes.py cannot dump the class layout. The exact
set of response fields (ServerInstanceInfo) is established empirically - we send
and read the client's reaction (as with the cert and the record version).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# --- TDF wire types (heat2) ---
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

UNION_UNSET = 0x7F         # no active union member


# ---------------------------------------------------------------- tags
def enc_tag(label: str) -> bytes:
    """4-character tag -> 3 bytes (6 bits/char; space = 0). Mirror of decode_tag."""
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


# ---------------------------------------------------------------- numbers (heat2 varint)
def enc_int(v: int) -> bytes:
    """heat2 varint (verified on the LOC field of a live request):
    1st byte: bits 0-5 = value, bit6 = SIGN (negative), bit7 = CONTINUATION;
    following bytes: bits 0-6 = value, bit7 = continuation.
    NOTE: continuation is ALWAYS bit7 - an earlier version confused it with bit6
    (the sign), so IP/PORT >= 0x40 came out wrong and the client rejected the cert."""
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


# ---------------------------------------------------------------- values
def enc_str(s: str | bytes) -> bytes:
    data = (s.encode("latin1") if isinstance(s, str) else s) + b"\x00"
    return enc_int(len(data)) + data


def dec_str(buf: bytes, p: int) -> tuple[str, int]:
    ln, p = dec_int(buf, p)
    s = buf[p:p + ln]; p += ln
    return s.rstrip(b"\x00").decode("latin1"), p


# ---------------------------------------------------------------- fields and structures
@dataclass
class Field:
    """One TDF field: (tag, wire type, value already encoded to bytes)."""
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
    """Nested structure: fields + 0x00 terminator (heat2 convention)."""
    return Field(tag, T_STRUCT, b"".join(f.encode() for f in fields) + b"\x00")


def f_union(tag: str, active: int, member: Field | None) -> Field:
    """Union: index of the active member + the (tagged) member, or UNSET."""
    if member is None:
        return Field(tag, T_UNION, bytes((UNION_UNSET,)))
    return Field(tag, T_UNION, bytes((active,)) + member.encode())


def f_blob(tag: str, data: bytes) -> Field:
    return Field(tag, T_BLOB, enc_int(len(data)) + data)


def encode_tdf(fields: list[Field]) -> bytes:
    """Encodes a list of fields as a top-level TDF body (no terminator -
    the length is set by the Fire2 frame)."""
    return b"".join(f.encode() for f in fields)


# ---------------------------------------------------------------- Fire2 frame
FIRE2_HDR = 12

# messageType (uint16 field at header offset 8). Values per Blaze Fire2.
MSG_MESSAGE = 0        # request (what the client sends)
MSG_REPLY = 1          # reply to a request (what we MUST answer with)
MSG_NOTIFICATION = 2
MSG_ERROR_REPLY = 3
MSG_PING = 4
MSG_PING_REPLY = 5


@dataclass
class Fire2:
    """Fire2 frame. 12 B header = 6x uint16 BE:
    size, component, command, errorCode, messageType, messageId.
    In a client request messageType=MESSAGE(0), messageId grows 0,1,2...
    The reply MUST have messageType=REPLY(1) and the same messageId (echo)."""
    component: int
    command: int
    payload: bytes
    error: int = 0
    seq: int = 0                 # messageId
    msg_type: int = MSG_MESSAGE

    def encode(self) -> bytes:
        # 12 B header: size(2) comp(2) cmd(2) err(2) msgType(1) reserved(1) msgId(2)
        # NOTE: messageType is a SINGLE BYTE at offset 8 (not a uint16 at [8-9]).
        # It used to be encoded as uint16 -> REPLY(1) put 0x00 into byte 8 =>
        # the game read our reply as a MESSAGE (another request), not a REPLY.
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


# ---------------------------------------------------------------- TDF decoder (helper)
def f_list_empty(tag: str, elem_wtype: int) -> Field:
    """Empty heat2 list: element type + count 0."""
    return Field(tag, T_LIST, bytes((elem_wtype,)) + enc_int(0))


def build_getserverinstance_response(ip: str, port: int, *, secure: bool = True,
                                     service: str = "nfs-rivals-pc",
                                     seq: int = 0, addr_index: int = 0,
                                     minimal: bool = False,
                                     msg_type: int = MSG_REPLY,
                                     host: str | None = None) -> bytes:
    """Reply to Redirector.getServerInstance (comp 5, cmd 1, error 0).

    Schema EXTRACTED from the decrypted binary (memory dump + map_tdf_classes):
    the ServerInstanceInfo class (@0x1416f6890) has fields in tag order:
        ADDR (union, mAddress) | AMAP (list) | CERT (list, mCertificateList) |
        MSGS (list) | NMAP (list) | SECU (bool, mSecure) | XDNS (int, mDefaultDnsAddress)
    Address structure (@0x1416f8580): HOST (mHostname) | IP (mIp) | PORT (mPort).

    IMPORTANT: heat2 requires fields in ASCENDING tag order (that is how the request
    looked: BSDK<BTIM<...<NAME). We emit exactly in that order, otherwise the decoder
    skips fields (that sank the first draft - ADDR came after SECU, descending).

    Points the game at the given address - by default at US, so the client comes
    back with its next packet (preAuth/auth). We give both HOST and IP, so the client
    can use either.

    Still empirical (the reaction log will confirm): index/tag of the ADDR union member.
    """
    ADDR_MEMBER_INDEX = addr_index         # 0=ServerAddressInfo.mIpAddress; for experiments
    ADDR_MEMBER_TAG = "VALU"
    ip_int = int.from_bytes(bytes(int(o) for o in ip.split(".")), "big")

    # union ADDR -> member = address struct {HOST, IP, PORT} (ascending by tag).
    # HOST = a host name that (a) is in the hosts file -> points at us and
    # (b) matches the cert CN (gosredirector.ea.com) - otherwise the game rejects the
    # cert on the Blaze connection. The game PREFERS HOST (it resolves it) over the IP field.
    addr_struct = f_struct(ADDR_MEMBER_TAG, [
        f_str("HOST", host if host is not None else ip),
        f_int("IP", ip_int),
        f_int("PORT", port),
    ])
    if minimal:
        # only ADDR - isolates the union (no lists/bools, which could break decoding)
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
    """heat2 int list: element type (int=0) + count + values."""
    body = bytes((T_INT,)) + enc_int(len(values))
    for v in values:
        body += enc_int(v)
    return Field(tag, T_LIST, body)


def f_map_struct(tag: str, items: dict[str, list[Field]]) -> Field:
    """heat2 map string -> struct: key type, value type, count, then
    (key, struct fields + terminator) pairs WITHOUT tags (just like f_map_str)."""
    body = bytes((T_STRING, T_STRUCT)) + enc_int(len(items))
    for k, fields in items.items():
        body += enc_str(k) + b"".join(f.encode() for f in fields) + b"\x00"
    return Field(tag, T_MAP, body)


def f_map_empty(tag: str, key_wtype: int, val_wtype: int) -> Field:
    """Empty heat2 map: key type + value type + count 0. The client gets a
    properly tagged but empty field instead of a missing field."""
    return Field(tag, T_MAP, bytes((key_wtype, val_wtype)) + enc_int(0))


# --- network addresses -------------------------------------------------------
# NetworkAddress is a UNION; variants (confirmed earlier from the binary):
#   0=XboxClientAddress 1=XboxServerAddress 2=IpPairAddress 3=IpAddress 4=HostNameAddress
# The PC client describes itself as IpPairAddress (@0x141706320): EXIP INIP MACI,
# where EXIP/INIP are address structures (@0x1416f8580): HOST IP PORT.
NETADDR_IPPAIR = 2
NETADDR_IPADDR = 3


def _ip_to_int(ip: str) -> int:
    return int.from_bytes(bytes(int(o) for o in ip.split(".")), "big")


def f_ip_pair(tag: str, ip: str = "127.0.0.1", port: int = 3659, *,
              machine_id: int = 0) -> Field:
    """NetworkAddress union with IpPairAddress active (internal address == external)."""
    inner = [f_int("IP", _ip_to_int(ip)), f_int("PORT", port)]
    pair = f_struct("VALU", [                    # tags ascending: EXIP < INIP < MACI
        f_struct("EXIP", inner),
        f_struct("INIP", inner),
        f_int("MACI", machine_id),
    ])
    return f_union(tag, NETADDR_IPPAIR, pair)


# Bandwidth (bit/s, both ways) every player is shown to the others with: QDAT in the session data
# and NQOS of the game. Up to 1.0.8 it was 100 kbit/s, while the games themselves measure
# 5.12/100 Mbit/s (NQOS in updateNetworkInfo). Experiment (01.10): whether a "slow" player is why
# name tags show only up close. tls_terminator --session-bps sets it; 100000 = the old value.
SESSION_BPS = 10_000_000


def f_extended_data(tag: str = "DATA", *, ip: str = "127.0.0.1", port: int = 3659,
                    ping_site: str = "ams", country: str = "PL",
                    latencies: list[int] | None = None,
                    addr: tuple[int, int, int, int, int] | None = None) -> Field:
    """UserSessionExtendedData (@0x1416d7ac0) - the user session state.

    Fields in tag order (heat2 reads sequentially, so ASCENDING):
        ADDR(union NetworkAddress) BPS(str, alias of the best ping site)
        CTY(str) DMAP(map) HWFG(int) PSLM(list of latencies) QDAT(struct QosData)
        UATT(int) ULST(list ObjectId)

    We used to send an EMPTY structure here. After login the client keeps its
    own session state in it; without an address and a QoS result it does not
    consider itself ready for online and does not send updateNetworkInfo - hence
    the "Connecting" screen.
    """
    if latencies is None:
        latencies = [10]                          # one ping site, 10 ms
    return f_struct(tag, [
        # addr = the player's full address pair (exip, export, inip, inport, maci) - multiplayer:
        # other players get the real address in UserAdded, not 127.0.0.1
        f_union_ip_pair("ADDR", *addr) if addr else f_ip_pair("ADDR", ip, port),
        f_str("BPS", ping_site),
        f_str("CTY", country),
        f_map_empty("DMAP", T_INT, T_INT),        # mDataMap - no own data
        f_int("HWFG", 0),                         # mHardwareFlags
        f_list_int("PSLM", latencies),            # mLatencyList
        f_struct("QDAT", [                        # mQosData - QoS test result
            f_int("DBPS", SESSION_BPS),           # downstream bit/s
            f_int("NATT", 0),                     # NAT type: OPEN
            f_int("UBPS", SESSION_BPS),           # upstream bit/s
        ]),
        f_int("UATT", 0),                         # mUserInfoAttribute
        f_list_empty("ULST", T_OBJID),            # mBlazeObjectIdList
    ])


def f_map_str(tag: str, items: dict[str, str]) -> Field:
    """heat2 map string->string: key type(1) + value type(1) + count +
    (key, value) pairs WITHOUT tag headers. Format per the BlazeSDK TdfEncoder
    (confirmed on the BF3 emulator - the same engine): keyType, valType, count,
    then enc_str(key)+enc_str(val) for every pair."""
    # Keys SORTED: the client keeps the map as a sorted vector and binary-searches
    # it (config lookup 0xf39cb0). In run-20 the bytevault* keys appended at the end
    # (after voipHeadsetUpdateRate) were therefore "not found" and ByteVault went to
    # the default EA host. Blaze servers send maps sorted.
    body = bytes((T_STRING, T_STRING)) + enc_int(len(items))
    for k, v in sorted(items.items()):
        body += enc_str(k) + enc_str(v)
    return Field(tag, T_MAP, body)


# Blaze components that are usually hosted (CIDS). The client learns from this
# which components the server has. A rough set - to be corrected based on the game's reaction.
DEFAULT_COMPONENT_IDS = [1, 4, 5, 7, 9, 11, 15, 21, 25, 30, 63, 2000]


# Client config keys present in the binary (@0x016d2d80 and around: pingPeriod,
# defaultRequestTimeout, connIdleTimeout; @0x016ea7c8 associationListSkipInitialSet;
# @0x016eaac8 voipHeadsetUpdateRate). The values are ours - the client parses them as
# text, so numbers go as strings.
#
# TIMES MUST HAVE A UNIT. The three time keys are read only by 0xf419b0, through the
# connection getter 0xf39dc0 -> TimeValue parser 0xf79d60: segments <number><d|h|m|s|ms>
# (can be combined, optionally with ':'), result in microseconds. A bare number ("90")
# ends with a NUL instead of a unit -> the parser returns false and stores nothing, but
# the getter IGNORES that result and reports "found" -> the reader takes variable = 0.
# That was the case until 2026-09-13: connIdleTimeout="90" gave [conn+0x2fc]=0 ms and the
# client dropped Blaze (0x800e0000) right after preAuth. Client defaults when the key is
# missing (constructor 0xf2e7d0): idle 40 s, ping 15 s. Details: docs/protocol.md section 11.
DEFAULT_CLIENT_CONFIG = {
    "associationListSkipInitialSet": "1",
    "connIdleTimeout": "90s",
    "defaultRequestTimeout": "30s",
    "pingPeriod": "15s",
    "voipHeadsetUpdateRate": "500",
}


def f_qos_ping_site(alias: str, host: str, port: int) -> list[Field]:
    """QosPingSiteInfo fields (@0x1417065c0, read from the binary):
    PSA(mAddress) PSP(mPort) SNA(mSiteName) - tags ascending."""
    return [f_str("PSA", host), f_int("PSP", port), f_str("SNA", alias)]


def f_qos_settings(tag: str = "QOSS", *, alias: str = "ams",
                   host: str = "127.0.0.1", port: int = 17502,
                   service_id: int = 0, timeout_us: int = 5000000) -> Field:
    """QosConfigInfo (@0x141a32d80) - QoS test settings.

    Layout READ FROM THE BINARY (not guessed from BF3):
        BWPS(struct) mBandwidthPingSiteInfo
        LNP (uint16) mNumLatencyProbes
        LTPS(map)    mPingSiteInfoByAliasMap
        SVID(int32)  mServiceId
        TIME(time)   mTimeout            <- this field is NOT in the BF3 layout

    The field table of this class lives in the .data section, not .rdata - that is
    why the earlier scan did not see it and we took the layout by analogy to BF3,
    without TIME. The ping site points at us; otherwise the client probes dead EA servers.
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
    """Reply to Util.preAuth (component 9, command 7).

    PreAuthResponse schema (@0x1416c6440, ascending tag order):
      ASRC(str) CIDS(list int) CONF(struct) ESRC(str) INST(str) MINR(?) NASP(str)
      PILD(str) PLAT(str) QOSS(struct) RSRC(str) SVER(str).

    CONF is ClientConfig (@0x1416c5870) = ONE field CONF of type MAP. An empty
    structure used to go here, i.e. a structure WITHOUT the map inside - and the
    client asks for the config explicitly: the preAuth request contains FCCR{CFID='BlazeSDK'}.
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
            conf,                                    # ClientConfig{ CONF: map }
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
        # Diagnostics: pad the reply to ~pad_to bytes by lengthening an ORDINARY
        # string (PILD). A big reply without a single map - isolates the question
        # "does the size break the client, or the content".
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
    """Reply to Authentication.login (component 1, command 152) = FullLoginResponse.

    Structure from the binary:
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
    """Reply to Util.ping (component 9, command 2) = { STIM mServerTime }."""
    import time
    payload = encode_tdf([f_int("STIM", int(time.time()))])
    return Fire2(component=9, command=2, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


# The msgType byte on the wire = logical_type << 4 (REPLY 1->0x10, NOTIFICATION 2->0x20,
# confirmed live). So the server PING = MSG_PING(4) << 4 = 0x40, and the client
# answers with PING_REPLY (0x50).
MSG_PING_BYTE = MSG_PING << 4          # 0x40


def build_server_ping(seq: int = 0) -> bytes:
    """Fire2 transport heartbeat (msgType=PING) sent BY THE SERVER.

    Why: after login the client runs QoS on separate sockets, and the Blaze TCP
    connection has no traffic. The per-frame connection update (0xf3a580) checks
    `state==2 && (now - last_activity) > [conn+0x2fc]` and when exceeded it drops
    the connection with error 0x800e0000 (0xeffca0) -> teardown -> crash. A frame
    from the server resets the activity counter on the client's receive side. PING
    is the cleanest - it is a transport heartbeat, the client answers PING_REPLY
    and does not process it like a component notification."""
    return Fire2(component=0, command=0, payload=b"", error=0, seq=seq,
                 msg_type=MSG_PING_BYTE).encode()


def _telemetry_fields(ip: str = "127.0.0.1", *, locale: int = 1701729619,
                      port: int = 9988) -> list[Field]:
    """TelemetryServer fields (tags ascending) - shared by TELE (postAuth) and
    getTelemetryServer (9/5). Template from the BF3 emulator (the same engine), types
    verified against the NFS dump (class @0x1416c7510): ADRS/DISA/FILT/NOOK/SESS/
    SKEY/STIM = string; ANON/LOC/PORT/SDLY/SPCT = int. Telemetry pointed at us
    (127.0.0.1) and practically disabled (SPCT does not matter - we have no telemetry
    server anyway; the client only stores this data)."""
    return [
        f_str("ADRS", ip),
        f_int("ANON", 0),
        f_str("DISA", ""),                 # countries with telemetry disabled - empty
        f_str("FILT", ""),
        f_int("LOC", locale),
        f_str("NOOK", "US,CA,MX"),
        f_int("PORT", port),
        f_int("SDLY", 15000),
        f_str("SESS", "telemetry_session"),
        f_str("SKEY", "telemetry_key"),
        f_int("SPCT", 0),                  # 0% of samples - we send nothing
        f_str("STIM", "Default"),
    ]


def build_postauth_response(seq: int, user_id: int, *, msg_type: int = MSG_REPLY,
                            ip: str = "127.0.0.1",
                            subsystems: bool = True) -> bytes:
    """Reply to Util.postAuth (component 9, command 8) = PostAuthResponse.
    Structure (@0x1416c3b50): { PSS TELE TICK UROP } - 4 nested structures.

    It USED TO be empty: empty STRUCTURES crashed (the game uses the fields), and a
    fully empty payload did not crash, but the game got stuck on "Connecting". Now we
    FILL it in per the Blaze emulator for BF3 (the same Fire2/heat2 engine) - fields
    and types match the NFS dump:
      PSS (PssConfig)   = { ADRS CSIG PJID PORT RPRT TIID }
      TELE (Telemetry)  = _telemetry_fields()
      TICK (Ticker)     = { ADRS PORT SKEY }
      UROP (UserOptions)= { TMOP UID }
    Everything pointed at us / neutral, so the client completes the connection.

    A/B 2026-09-11 (subsystems=False): empty ADRS and PORT=0 in all three
    subsystems. After our postAuth reply the client closed the Blaze connection BY
    ITSELF, and right after that crashed on a callback through NULL in the component
    teardown path (base+0xf4de00). Hypothesis: the client tries to bring up
    PSS/TELE/TICK at addresses nobody listens on, and that ends the session. We do
    NOT remove the structures - empty STRUCTURES crashed already before - we only
    neutralize the addresses, so the shape and the field types stay identical."""
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
    """Reply to Util.getTelemetryServer (component 9, command 5) =
    GetTelemetryServerResponse (the same fields as TELE in postAuth)."""
    payload = encode_tdf(_telemetry_fields(ip))
    return Fire2(component=9, command=5, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_fetch_client_config_response(seq: int, *, msg_type: int = MSG_REPLY,
                                       config: dict[str, str] | None = None) -> bytes:
    """Reply to Util.fetchClientConfig (component 9, command 1) = { CONF map<str,str> }.
    The client asks for a config section (CFID in the request) and caches the reply.
    Empty map = "no entries for this section" -> the client moves on. Specific
    sections (e.g. achievement lists) we will fill in if the game gets stuck without them."""
    payload = encode_tdf([f_map_str("CONF", config or {})])
    return Fire2(component=9, command=1, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_user_settings_load_all_response(seq: int, *, msg_type: int = MSG_REPLY,
                                          settings: dict[str, str] | None = None) -> bytes:
    """Reply to Util.userSettingsLoadAll (component 9, command 0xC) =
    { SMAP map<str,str> } - the user's saved settings. Empty at the start."""
    payload = encode_tdf([f_map_str("SMAP", settings or {})])
    return Fire2(component=9, command=0xC, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_empty_reply(component: int, command: int, seq: int, *,
                      msg_type: int = MSG_REPLY) -> bytes:
    """Empty acknowledgement reply (e.g. userSettingsSave 9/0xB). Just the Fire2
    header with error=0 - the client knows the RPC succeeded and moves on."""
    return Fire2(component=component, command=command, payload=b"", error=0,
                 seq=seq, msg_type=msg_type).encode()


MSG_NOTIFY_BYTE = 0x20        # msgType byte for notifications (type 2 in the upper nibble)


def build_notification(component: int, command: int, payload: bytes, *,
                       seq: int = 0, msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """Server-side Fire2 notification (async, not a reply)."""
    return Fire2(component=component, command=command, payload=payload,
                 error=0, seq=seq, msg_type=msg_type).encode()


def reseq(frame: bytes, seq: int) -> bytes:
    """Replaces the messageId (uint16 at offset 10) in a ready Fire2 frame.
    Used to give notifications the server's own increasing sequence."""
    return frame[:10] + struct.pack(">H", seq & 0xFFFF) + frame[12:]


def f_user_identification(tag: str, user_id: int, persona: str) -> Field:
    """UserIdentification (@0x1416d78c0, tags ascending): AID mAccountId, ALOC mAccountLocale
    (~enUS), EXID mExternalId, ID mBlazeId, NAME mName, ORIG mOriginPersonaId, PIDI mPidId.
    EXBB (mExternalBlob) is left out - missing field = default value."""
    return f_struct(tag, [
        f_int("AID", user_id),
        f_int("ALOC", 1701729619),
        f_int("EXID", 0),
        f_int("ID", user_id),
        f_str("NAME", persona),
        f_int("ORIG", user_id),
        f_int("PIDI", 0),
    ])


def build_useradded_notify(user_id: int, persona: str,
                           session_key: str | None = None, *, component: int = 0x7802,
                           command: int = 2, seq: int = 0,
                           msg_type: int = MSG_NOTIFY_BYTE,
                           email: str = "player@nfsrivals.local",
                           rich_data: bool = True, legacy_user: bool = False,
                           addr: tuple[int, int, int, int, int] | None = None) -> bytes:
    """UserSessions notification UserAdded (cmd 2) = Blaze::NotifyUserAdded.
    Structure (@0x1416d87d0): { DATA mExtendedData, USER mUserInfo }.

    USER = UserIdentification (field table @0x1416d78c0, tags from the binary):
        AID mAccountId  ALOC mAccountLocale  EXBB mExternalBlob  EXID mExternalId
        ID mBlazeId  NAME mName  ORIG mOriginPersonaId  PIDI mPidId
    Until 2026-09-13 we sent UserSessionLoginInfo tags here (BUID DSNM KEY ...), of which
    UserIdentification only knows ALOC - the heat2 decoder skips unknown tags, so the game
    created a local user with ID=0 and an empty NAME (it did not match the BUID from login).
    Confidence: class/field names from the binary + the standard BlazeSDK layout (mUserInfo is
    UserIdentification); the field table itself holds no pointer to the field's class, so the
    USER -> @0x1416d78c0 link cannot be read straight from the data.
    EXBB (type code 8, encoding unknown) is skipped - missing field = default value.
    legacy_user=True restores the old layout (A/B)."""
    import time
    now = int(time.time())
    if session_key is None:
        session_key = f"1_{user_id}_sess"
    if legacy_user:
        user = f_struct("USER", [            # old layout: UserSessionLoginInfo
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
        user = f_user_identification("USER", user_id, persona)  # ID MUST == BUID from login
    data = f_extended_data("DATA", addr=addr) if rich_data else f_struct("DATA", [])
    payload = encode_tdf([data, user])       # DATA < USER
    return build_notification(component, command, payload, seq=seq, msg_type=msg_type)


def build_usersession_update(user_id: int, *, component: int = 0x7802,
                             command: int = 1, seq: int = 0,
                             msg_type: int = MSG_NOTIFY_BYTE,
                             rich_data: bool = True) -> bytes:
    """UserSessions notification UserSessionExtendedDataUpdate.
    Structure (@0x1416d81c0): { DATA(UserSessionExtendedData) SUBS(bool) USID(int64) }.
    CONFIRMED (createNotification jump table): UserSessions=0x7802,
    ExtendedDataUpdate = command 1, UserAdded = command 2, UserAuthenticated = command 8."""
    payload = encode_tdf([
        f_extended_data("DATA") if rich_data else f_struct("DATA", []),
        f_int("SUBS", 1),
        f_int("USID", user_id),
    ])
    return build_notification(component, command, payload, seq=seq, msg_type=msg_type)


# UserDataFlags in UserData.FLGS: SUBSCRIBED (1) | ONLINE (2). ASSUMED from the standard BlazeSDK
# enum - the binary's {name, value} table for it has not been found.
USER_DATA_FLAGS_ONLINE = 3


def build_lookup_users_response(seq: int, users: list[dict], *,
                                msg_type: int = MSG_REPLY) -> bytes:
    """UserSessions.lookupUsers (0x7802/13) -> UserDataResponse @0x1416d96a8 {ULST mUserDataList},
    one UserData @0x1416da330 {EDAT mExtendedData, FLGS mStatusFlags, USER mUserInfo} per user
    found. users = [{id, persona, addr}]; `id` is the BlazeId the game asked for (it may be an
    alias of the player's uid), addr the player's IP pair or None. The request is
    {LTYP mLookupType, ULST mUserIdentificationList} @0x141a2ef98, LTYP 0 = BLAZE_ID.

    The game asks this when a car in its world carries an id no Blaze user has - before 1.0.4 the
    host's PersonaId while the host was logged in under its EA App user id (log-40). An empty
    answer left that car an ordinary racer: icon and name only up close."""
    payload = encode_tdf([f_list_struct("ULST", [
        [f_extended_data("EDAT", addr=u.get("addr")),
         f_int("FLGS", USER_DATA_FLAGS_ONLINE),
         f_user_identification("USER", int(u["id"]), str(u["persona"]))]
        for u in users])])
    return Fire2(component=0x7802, command=13, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def f_objid(tag: str, component: int, obj_type: int, obj_id: int) -> Field:
    """EA::TDF::ObjectId on the heat2 wire: three varints (component, type, id) - the same
    layout that _dec_value reads for T_OBJID."""
    return Field(tag, T_OBJID, enc_int(component) + enc_int(obj_type) + enc_int(obj_id))


def build_user_authenticated_notify(user_id: int, persona: str,
                                    session_key: str | None = None, *,
                                    component: int = 0x7802, command: int = 8, seq: int = 0,
                                    msg_type: int = MSG_NOTIFY_BYTE,
                                    email: str = "player@nfsrivals.local") -> bytes:
    """UserSessions notification UserAuthenticated (cmd 8).

    Class READ FROM THE BINARY: field table @0x141a2f160, constructor 0xf5ccf0 in the
    cmd 8 block of the UserSessions notification dispatcher 0xf29f90. It is a flattened
    SessionInfo + PersonaDetails from the login reply, plus ALOC, CGID and USTP:
        ALOC mAccountLocale  BUID mBlazeUserId  CGID mConnectionGroupObjectId (objid)
        DSNM mDisplayName  FRST mIsFirstLogin  KEY mSessionKey  LAST mLastAuthenticated
        LLOG mLastLoginDateTime  MAIL mEmail  PID mPersonaId  PLAT mClientPlatform
        UID mUserId  USTP mUserSessionType  XREF mExtId
    The field type codes are identical to those in the login's SessionInfo/PersonaDetails
    (the game decodes them), so we encode them the same way and with the same values.

    Until 2026-09-13 cmd 8 went out with an EMPTY payload: the game got "user logged in"
    with BUID=0 and no session key, and the game's online state machine (0xa1bb00) sat at
    5/6 and never reached 9 (logged in) - the "Logging in" screen.
    CGID = (UserSessions 0x7802, type 2, user_id): object type NOT CONFIRMED in the code."""
    import time
    now = int(time.time())
    if session_key is None:
        session_key = f"1_{user_id}_sess"             # the same KEY as in the login
    payload = encode_tdf([                             # tags ascending
        f_int("ALOC", 1701729619),                     # like USER in UserAdded
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


# ---------------------------------------------------------------- post-login RPCs
# Command numbers from emulating getCommandName in the binary (scratchpad rpcnames.py):
#   Authentication 0xf20180, Util 0xf28720, Stats 0xf28460, AssociationLists 0xf200b0,
#   NFS (component 2050) 0xf68100. Class layouts from docs/recon/tdf_members.json.

def f_list_struct(tag: str, items: list[list[Field]]) -> Field:
    """heat2 list of structs: element type (struct) + count + every struct
    (fields + 0x00 terminator) without element tags."""
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
    No saved setting = empty DATA."""
    payload = encode_tdf([f_str("DATA", data), f_str("KEY", key)])
    return Fire2(component=9, command=10, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_key_scopes_response(seq: int, *, msg_type: int = MSG_REPLY) -> bytes:
    """Stats.getKeyScopesMap (7/15) -> KeyScopes @0x1416c5a68 {KSIT mKeyScopesMap}
    (map name -> KeyScopeItem). No scopes = empty map."""
    payload = encode_tdf([f_map_empty("KSIT", T_STRING, T_STRUCT)])
    return Fire2(component=7, command=15, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_stat_group_response(seq: int, name: str, *, msg_type: int = MSG_REPLY) -> bytes:
    """Stats.getStatGroup (7/4) -> StatGroupResponse @0x1416c4a10
    {CNAM DESC ETYP KSUM META NAME STAT}. ETYP (objtype) and KSUM are skipped - missing
    field = default value; STAT (list of StatDescSummary) empty."""
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
    No friends = empty ListMembers list."""
    payload = encode_tdf([f_list_struct("LMAP", [])])
    return Fire2(component=25, command=6, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_geolocation_info_response(seq: int, blaze_id: int, *, country: str = "PL",
                                    msg_type: int = MSG_REPLY) -> bytes:
    """NFS (component 2050) getGeolocationInfo (38) -> GetGeolocationInfoResponse
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


STATS_NOTIFY_GET_STATS_ASYNC = 0x32   # Stats notification name 0xf29610: 0x32 -> GetStatsAsyncNotification


def build_stats_async_notification(view_id: int, group_name: str, entity_ids: list[int], *,
                                   seq: int = 0, msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """Result of Stats.getStatsByGroupAsync (7/16) - it arrives as NOTIFICATION 7/0x32, not a reply.
    GetStatsAsyncNotification @0x1416c55d0 {GRNM mGroupName, KEY mKeyString, LAST mLast,
    STS mStatValues, VID mViewId}; STS = StatValues @0x1416c4310 {AGGR, STAT list<EntityStats>},
    EntityStats @0x1416c5d60 {EID ETYP POFF STAT list<string>}. LAST=1 closes view VID -
    without this notification the asynchronous query never finishes."""
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
    """Authentication.getAuthToken (1/36) -> @0x1416ad9f8 {AUTH mAuthToken}. The game puts this
    token into the Authorization header of ByteVault requests (without it, it went out empty)."""
    payload = encode_tdf([f_str("AUTH", token)])
    return Fire2(component=1, command=36, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


# ---------------------------------------------------------------- GameManager (component 4)
# Numbers from the name tables in the binary: RPC 0xf68420 (1 createGame, 2 destroyGame, 3 advanceGameState,
# 15 finalizeGameCreation, 29 updateMeshConnection), notifications 0xf69450 (20 NotifyGameSetup,
# 30 NotifyPlayerJoinCompleted, 100 NotifyGameStateChange). Enums from {name, value} tables.
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
    """IpPairAddress fields in tag order: EXIP{IP MACI PORT} INIP{IP MACI PORT} MACI."""
    return [f_struct("EXIP", [f_int("IP", exip), f_int("MACI", 0), f_int("PORT", export)]),
            f_struct("INIP", [f_int("IP", inip), f_int("MACI", 0), f_int("PORT", inport)]),
            f_int("MACI", maci)]


def f_union_ip_pair(tag: str, exip: int, export: int, inip: int, inport: int, maci: int) -> Field:
    """NetworkAddress union field with IpPairAddress active (variant 2), like ADDR in ExtendedData."""
    return f_union(tag, 2, f_struct("VALU", _ip_pair_fields(exip, export, inip, inport, maci)))


def f_list_ip_pair(tag: str, exip: int, export: int, inip: int, inport: int, maci: int) -> Field:
    """NetworkAddress list (HNET). The element wire type = 3 (struct), but the element is a UNION:
    variant byte (2 = IpPairAddress) + the member's fields + 0x00 terminator. Layout observed in
    the createGame request sent by the client (HNET: 03 01 02 EXIP... MACI... 00)."""
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
    """GameManager.resetDedicatedServer (4/25) -> the same class as createGame: the binary has NO
    "ResetDedicatedServerResponse" string (only ...SetupContext), and CreateGameResponse
    @0x141a300b0 is the only GameManager reply with just a GID."""
    return build_create_game_response(seq, game_id, command=25, msg_type=msg_type)


# SlotType from the {name, value} table @0x1416d9790 (MAX_PARTICIPANT_SLOT_TYPE = 2, INVALID = -1).
SLOT_TYPE = {"SLOT_PUBLIC_PARTICIPANT": 0, "SLOT_PRIVATE_PARTICIPANT": 1,
             "SLOT_PUBLIC_SPECTATOR": 2, "SLOT_PRIVATE_SPECTATOR": 3}


def build_replicated_player(game_id: int, player: dict) -> list[Field]:
    """ReplicatedGamePlayer @0x141a2f3a0 (18 of 20 fields) - a player in the NotifyGameSetup roster
    and in NotifyPlayerJoining. player = {uid, persona, slot, state, addr=(exip, export, inip, inport, maci)}.
    The player's slot number goes to SID (mSlotId) and CSID (mConnectionSlotId); SLOT is mSlotType, i.e.
    the kind of slot, not its number. Until 15.09 the number went to SLOT, and SID/CSID were 0 for every
    player - a joiner got the same connection slot as the host (log-29: both games reported STAT=0)."""
    import time
    uid = player["uid"]
    slot = player.get("slot", 0)
    return [                                           # tags ascending
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
    REAS mGameSetupReason}. GAME = ReplicatedGameData @0x141a2f590 (32 of 42 fields here, the rest
    default), PROS = roster (build_replicated_player for every player in `players`), host
    (ADMN, HSES, OGHI, PHST/THST) = host_id, HNET = host address. REAS = union: variant 0
    DatalessSetupContext {DCTX = CREATE_GAME_SETUP_CONTEXT}, 1 ResetDedicatedServerSetupContext
    (setup_context="reset_dedicated", no fields) or 3 MatchmakingSetupContext.
    Game values (name, settings, topology, VSTR, capacity) come from the request of the client
    creating the game, so it gets what it asked for; joiners get the same."""
    # The host's slot has to be the real one. It used to be hardwired to 0, which held while the
    # host was always the creator of the game (slot 0). After a host migration the new host keeps
    # its own slot (1 in test 50) and a returning player gets the freed slot 0 - so a joiner was
    # told the topology host sat in its OWN slot, never opened a mesh connection and gave up.
    host_info = [f_int("CONG", host_id), f_int("CSID", host_slot), f_int("HPID", host_id),
                 f_int("HSLT", host_slot)]
    exip, export, inip, inport, maci = host_addr
    user_id = host_id
    game = [                                           # tags ascending
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
        f_struct("NQOS", [f_int("DBPS", SESSION_BPS), f_int("NATT", 0),
                          f_int("UBPS", SESSION_BPS)]),
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
    if setup_context == "reset_dedicated":             # resetDedicatedServer: context without fields
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
    """NotifyPlayerJoinCompleted (4/30) - candidate class {GID mGameId, PID mPlayerId}."""
    payload = encode_tdf([f_int("GID", game_id), f_int("PID", player_id)])
    return build_notification(4, GM_NOTIFY_PLAYER_JOIN_COMPLETED, payload, seq=seq,
                              msg_type=msg_type)


# ---------------------------------------------------------------- GameManager: matchmaking (4/13)
# StartMatchmakingRequest @0x141a30840 ("StartMatchmakingRequest::m..." strings): MODE mSessionMode
# (run-26: 3 = find or create), DUR mSessionDurationMS (6000), CRIT mCriteriaData, GNAM, GSET, GVER,
# NTOP, PMAX, PNET, PRES, TID, VOIP. MatchmakingResult enum from the {name, value} table @0x1416d8f00.
MATCHMAKING_RESULT = {"SUCCESS_CREATED_GAME": 0, "SUCCESS_JOINED_NEW_GAME": 1,
                      "SUCCESS_JOINED_EXISTING_GAME": 2, "SESSION_TIMED_OUT": 3,
                      "SESSION_CANCELED": 4, "SESSION_TERMINATED": 5,
                      "SESSION_ERROR_GAME_SETUP_FAILED": 6}
GM_NOTIFY_MATCHMAKING_FAILED = 10
# GameSetupReason union: member tables @0x141a30280.. in order Dataless(0), ResetDedicatedServer(1),
# IndirectJoinGame(2), Matchmaking(3), IndirectMatchmaking(4). Variant 0 has worked since run-23 (createGame).
# MatchmakingSetupContext @0x141a30120 {FIT mFitScore, MAXF mMaxPossibleFitScore, MSID mSessionId,
# RSLT mMatchmakingResult, USID mUserSessionId}.
GAME_SETUP_REASON_MATCHMAKING = 3
# Union variant 1 = mResetDedicatedServerSetupContext (table @0x141a30298). The class itself
# HAS NO fields: between DatalessSetupContext {DCTX} @0x141a30100 and MatchmakingSetupContext
# {FIT...} @0x141a30120 there is no member table at all, so VALU stays empty.
GAME_SETUP_REASON_RESET_DEDICATED = 1
MM_FIT_SCORE = 100      # FIT = MAXF: the fit is the fraction FIT/MAXF - we do not send zeros


def build_start_matchmaking_response(seq: int, session_id: int, *,
                                     msg_type: int = MSG_REPLY) -> bytes:
    """StartMatchmakingResponse {MSID}. Two candidate classes in the binary have the MSID tag: @0x1416da370
    {MSID mMatchmakingSessionId} and @0x1416d9ef0 {COID ESNM MSID mSessionId SCID STMN} (external Xbox
    session fields) - MSID alone fits both, the rest stays default."""
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


# ---------------------------------------------------------------- GameManager: several players
# Notification numbers from the name table 0xf69450. Enums from {name, value} tables in the dump:
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
    """NotifyPlayerJoining (4/21) @0x1416d8220 {GID mGameId, PDAT mJoiningPlayer} - to players already
    in the game when someone joins. PDAT = the joiner's ReplicatedGamePlayer."""
    payload = encode_tdf([f_int("GID", game_id),
                          f_struct("PDAT", build_replicated_player(game_id, player))])
    return build_notification(4, GM_NOTIFY_PLAYER_JOINING, payload, seq=seq, msg_type=msg_type)


def build_notify_player_removed(game_id: int, player_id: int, reason: int, *, seq: int = 0,
                                msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyPlayerRemoved (4/40), candidate class @0x141a30560 {CNTX mPlayerRemovedTitleContext,
    GID mGameId, LFPJ mLockedForPreferredJoins, PID mPlayerId, REAS mPlayerRemovedReason} -
    layout from the field names (removePlayer requests have the same tags without LFPJ)."""
    payload = encode_tdf([f_int("CNTX", 0), f_int("GID", game_id), f_int("LFPJ", 0),
                          f_int("PID", player_id), f_int("REAS", reason)])
    return build_notification(4, GM_NOTIFY_PLAYER_REMOVED, payload, seq=seq, msg_type=msg_type)


def build_notify_game_removed(game_id: int, reason: int, *, seq: int = 0,
                              msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyGameRemoved (4/16), candidate class @0x141a303a8 {GID mGameId, REAS mDestructionReason}."""
    payload = encode_tdf([f_int("GID", game_id), f_int("REAS", reason)])
    return build_notification(4, GM_NOTIFY_GAME_REMOVED, payload, seq=seq, msg_type=msg_type)


# GameManager notification numbers read from the getNotificationName jump table 0xf69450 (index =
# id-10: byte @0xf6963c, RVA offset @0xf695a8): 10 MatchmakingFailed, 12 MatchmakingAsyncStatus,
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
# UpdateAdminListOperation from the {name, value} table @0x1416da628.
GM_ADMIN_OPERATION = {"GM_ADMIN_ADDED": 0, "GM_ADMIN_REMOVED": 1, "GM_ADMIN_MIGRATED": 2}


def build_notify_game_player_state_change(game_id: int, player_id: int, state: int, *,
                                          seq: int = 0, msg_type: int = MSG_NOTIFY_BYTE) -> bytes:
    """NotifyGamePlayerStateChange (4/116) @0x141a30660 {GID mGameId, PID mPlayerId,
    STAT mPlayerState}; `state` from PLAYER_STATE.

    Class isolated from tdf_members.json between {GID, PID} and {GID, PID, ROLE, SLOT} - the classes
    lie in the same order as the notification numbers (116 GamePlayerStateChange, 117
    GamePlayerTeamRoleSlotChange). Different from NotifyPlayerJoinCompleted (30): 30 says "join
    complete", 116 carries the player's STATE. Up to run-39 we only sent 30, and changed the state
    only on our side - the player object on the joiner stayed in ACTIVE_CONNECTING."""
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
    UID mUpdaterPlayerId} - to all players of the game after addAdminPlayer (4/106) and
    removeAdminPlayer (4/107). The request of those RPCs is @0x1416d8978 {GID mGameId, PID mAdminPlayerId}."""
    payload = encode_tdf([f_int("ALST", admin_id), f_int("GID", game_id), f_int("OPER", operation),
                          f_int("UID", updater_id)])
    return build_notification(4, GM_NOTIFY_ADMIN_LIST_CHANGE, payload, seq=seq, msg_type=msg_type)


# ---------------------------------------------------------------- Authentication.listUserEntitlements2
# Enums from {name, value} tables in .rdata: EntitlementType @0x1416aeac0, EntitlementStatus @0x1416ac490.
ENTITLEMENT_TYPE = {"UNKNOWN": 0, "ONLINE_ACCESS": 1, "TRIAL_ONLINE_ACCESS": 2, "SUBSCRIPTIONS": 3,
                    "PARENTAL_APPROVAL": 4, "DEFAULT": 5}
ENTITLEMENT_STATUS = {"UNKNOWN": 0, "ACTIVE": 1, "DISABLED": 2, "PENDING": 3, "DELETED": 4, "BANNED": 5}


def build_list_entitlements_response(seq: int, entitlements: list[dict], *,
                                     msg_type: int = MSG_REPLY) -> bytes:
    """Authentication.listUserEntitlements2 (1/29) -> Entitlements @0x1416adfe8 {NLST mEntitlements},
    element Entitlement @0x141a2b2b0 {DEVI GDAY GNAM ID ISCO PID PJID PRCA PRID STAT STRC TAG TDAY TYPE
    UCNT VER}. entitlements = [{id, group, type, tag, persona_id, product_id, project_id, status,
    grant_date}] - missing fields stay default."""
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
# FilterResult enum names in .rdata @0x16c70d0.. in this order; the client sends DIRT=2 in the
# request for text not checked yet, which matches zero-based numbering (UNPROCESSED).
FILTER_RESULT = {"PASSED": 0, "OFFENSIVE": 1, "UNPROCESSED": 2, "STRING_TOO_LONG": 3, "OTHER": 4}


def build_filter_profanity_response(seq: int, texts: list[str], *,
                                    msg_type: int = MSG_REPLY) -> bytes:
    """Util.filterForProfanity (9/20). Request and reply are the same class @0x1416c41d8
    {TLST mFilteredTextList}, element @0x141a2e150 {DIRT mResult, UTXT mFilteredText}.
    We do not filter: every text comes back unchanged with the PASSED result, in request order."""
    items = [[f_int("DIRT", FILTER_RESULT["PASSED"]), f_str("UTXT", t)] for t in texts]
    payload = encode_tdf([f_list_struct("TLST", items)])
    return Fire2(component=9, command=20, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


# ---------------------------------------------------------------- RPC command names
# From emulating the 13 getCommandName functions in the binary (switch on the number ->
# `lea rax, name; ret`), dump NFS14-0912.DMP.dmp. Component numbers from traffic. Component 28 has no
# name table in the binary - "GameReporting" follows from the request class {FNSH PRVT RPRT} (@0x141a32ad0).
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
    """"Component.command" from the binary's tables; just the component when the command is unknown; "" when nothing."""
    if (component, command) in RPC_NAMES:
        return RPC_NAMES[(component, command)]
    return f"{COMPONENT_NAMES[component]}#{command}" if component in COMPONENT_NAMES else ""


# ---------------------------------------------------------------- NFS.getInGameSpeedWalls (2050/20)
# Classes pinned to field tables by the "Class::mField" strings from the binary (e.g.
# "InGameSpeedWallResponseRow::mStatsFlt"):
#   InGameSpeedWallsRequest          @0x1416b76c0 {BLID mBlazeId, SWIS mSpeedWallIds, USGE, USPG}
#   InGameSpeedWallResponseSpeedWall @0x1416b7120 {ROWS mSpeedWall, SWID mSpeedWallId}
#   InGameSpeedWallResponseRow       @0x1416b87a0 {BLUS mBlazeUser, STAF mStatsFlt, STAI mStatsInt,
#                                                  STAS mStatsStr}
#   BlazeUser (candidate, field names) @0x141a2c040 {BLIS mBlazeId, PENA mPersonaName, URTY mRelationType}
# A row has the same STAF/STAI/STAS maps as a player entry in a GameReporting report ({ENTI STAF STAI
# STAS}), and the speed wall id is the ENTI from the report - the server sends back the object's stored stats.
# InGameSpeedWallResponse::mSpeedwalls has two possible field tables in the binary: a list under the ROWS
# tag (@0x1416b50f0, @0x1416b61e8) or SPWA (@0x1416b5870). We send BOTH tags with the same list - the
# client's heat2 decoder skips tags unknown to its class.

def f_map_int(tag: str, items: dict[str, int]) -> Field:
    """heat2 map string -> int, keys sorted (like f_map_str)."""
    body = bytes((T_STRING, T_INT)) + enc_int(len(items))
    for k, v in sorted(items.items()):
        body += enc_str(k) + enc_int(int(v))
    return Field(tag, T_MAP, body)


def f_map_float(tag: str, items: dict[str, float]) -> Field:
    """heat2 map string -> float: 4 B big-endian, just as _dec_value reads it (the values from
    reports come out sensible, e.g. speed=69.1). Keys sorted."""
    body = bytes((T_STRING, T_FLOAT)) + enc_int(len(items))
    for k, v in sorted(items.items()):
        body += enc_str(k) + struct.pack(">f", float(v))
    return Field(tag, T_MAP, body)


# UserRelationType for BlazeUser.URTY. The names come from the binary in this order: NOT_SET,
# LOCAL_PLAYER, FIRSTPARTY_FRIEND, RECENTLY_PLAYED, GEO_LOCATION, MUTUAL, SPECIAL_GUEST,
# SPECIAL_GUEST_DEVELOPER. The VALUES are ASSUMED to follow that order: the {name, value} table
# is built in memory at run time and is not in NFS14.exe (no pointers to the names, 01.10).
RELATION_NOT_SET, RELATION_LOCAL_PLAYER, RELATION_FRIEND, RELATION_RECENTLY_PLAYED = 0, 1, 2, 3


def build_in_game_speed_walls_response(seq: int, walls: list[tuple[int, list[dict]]], *,
                                       local_id: int = 0, rival_relation: int = RELATION_FRIEND,
                                       command: int = 20, msg_type: int = MSG_REPLY) -> bytes:
    """walls = [(speed wall id, [row, ...])], row = {blaze_id, persona, int, float, str}.
    A speed wall without stored data goes out with an empty row list - the game gets an answer for
    every id it asked about. The asker's own row (local_id = BLID of the request) is LOCAL_PLAYER,
    everyone else's rival_relation: up to 1.0.11 every row was NOT_SET, and the walls showed no one
    to beat, though the rows were there."""
    items = [_speed_wall_fields(swid, rows, local_id, rival_relation) for swid, rows in walls]
    payload = encode_tdf([f_list_struct("ROWS", items), f_list_struct("SPWA", items)])
    return Fire2(component=2050, command=command, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def f_blaze_user(tag: str, blaze_id: int, persona: str, relation: int) -> Field:
    """BlazeUser (candidate @0x141a2c040) {BLIS mBlazeId, PENA mPersonaName, URTY mRelationType}."""
    return f_struct(tag, [f_int("BLIS", blaze_id), f_str("PENA", persona), f_int("URTY", relation)])


def _speed_wall_fields(swid: int, rows: list[dict], local_id: int,
                       rival_relation: int) -> list[Field]:
    """InGameSpeedWallResponseSpeedWall {ROWS mSpeedWall, SWID mSpeedWallId}: a row per player,
    InGameSpeedWallResponseRow {BLUS, STAF, STAI, STAS} - the stats a GameReporting report filed
    under that object."""
    row_structs = [[
        f_blaze_user("BLUS", r["blaze_id"], r.get("persona", ""),
                     RELATION_LOCAL_PLAYER if r["blaze_id"] == local_id else rival_relation),
        f_map_float("STAF", r.get("float", {})),
        f_map_int("STAI", r.get("int", {})),
        f_map_str("STAS", r.get("str", {})),
    ] for r in rows]
    return [f_list_struct("ROWS", row_structs), f_int("SWID", swid)]


def f_map_int_struct(tag: str, items: dict[int, list[Field]]) -> Field:
    """heat2 map int -> struct, keys ascending (the client keeps maps as sorted vectors): key type,
    value type, count, then (key, struct fields + terminator) pairs without tags."""
    body = bytes((T_INT, T_STRUCT)) + enc_int(len(items))
    for k in sorted(items):
        body += enc_int(int(k)) + b"".join(f.encode() for f in items[k]) + b"\x00"
    return Field(tag, T_MAP, body)


# NFS.getInGameRecommendations (2050/21) - Autolog. Classes from the TDF tables:
#   InGameRecommendationsRequest  {BLID mBlazeId}
#   InGameRecommendationsResponse @0x1416b7490 {RILI mRivalList, SPWA mSpeedWallIDToSpeedWallMap}
#   InGameRecommendationsRival    @0x1416b5d20 {BLUS mRivalBlazeUser, PENA mRivalName, PLSC
#                                  mPlayerScore, RECM mRecommendationsList, RIBL mRivalBlazeId,
#                                  RISC mRivalScore}
#   ...ResponseRecommendation     @0x141a2c160 {BLUS mTargetBlazeUser, RETY mRecommendationType,
#                                  STAF/STAI/STAS mMisc*, STOB/STOT mStoryString*ID, SWID
#                                  mSpeedWallId, TABL mTargetBlazeId, TANA mTargetName,
#                                  TITL mTitleStringID}
# The map's values are the same InGameSpeedWallResponseSpeedWall as in getInGameSpeedWalls.
RECOMMENDATIONS_MAX_PAYLOAD = 60000     # Fire2 carries a 16-bit length
# RecommendationType: BEAT_YOU, HOT, POPULAR = 0, 1, 2 - confirmed in the code: 0x93bf30 turns
# RETY into the card's own title, 0 -> ID_REC_TITLE_BEAT, 1 -> _HOT, 2 -> _POP (else _BEAT).
RECOMMENDATION_BEAT_YOU, RECOMMENDATION_HOT, RECOMMENDATION_POPULAR = 0, 1, 2
# TITL mTitleStringID, STOT mStoryStringTopID, STOB mStoryStringBottomID are NOT plain string ids:
# 0x93be80 / 0x93bdd0 / 0x93bd20 (the recommendation for a speed wall id, fields +0x118/+0x128/
# +0x138) hand each to 0x93afd0, which looks it up in the game's table of 11 Autolog story
# templates @0x1415807e0 (0x93af50, strcmp). A key that is not there shows "String not on Autolog
# Yet". Until 1.1.1 TITL was ID_REC_TITLE_BEAT - the card's title, not a template - so the banner
# at a speed camera read "String not on Autolog Yet" above a correct story (02.10, after a host
# migration). STOT/STOB were empty until 1.0.12.7, with the same placeholder on the rival card.
AUTOLOG_STORY_TEMPLATES = (                          # the table @0x1415807e0, in its order
    "ID_HOT_TITLE", "ID_HOT_STORY_TOP", "ID_HOT_STORY_BOTTOM",
    "ID_POPULAR_TITLE", "ID_POPULAR_STORY_TOP", "ID_POPULAR_STORY_BOTTOM",
    "ID_BEAT_YOU_TITLE", "ID_BEAT_YOU_STORY_ONE_TOP", "ID_BEAT_YOU_STORY_ONE_BOTTOM",
    "ID_REC_PE_RECOMMENDATION_BEATEN", "ID_REC_PE_RECOMMENDATION_NOT_BEATEN")
RECOMMENDATION_TITLES = {RECOMMENDATION_BEAT_YOU: "ID_BEAT_YOU_TITLE",
                         RECOMMENDATION_HOT: "ID_HOT_TITLE",
                         RECOMMENDATION_POPULAR: "ID_POPULAR_TITLE"}
RECOMMENDATION_STORIES = {RECOMMENDATION_BEAT_YOU: ("ID_BEAT_YOU_STORY_ONE_TOP",
                                                    "ID_BEAT_YOU_STORY_ONE_BOTTOM"),
                          RECOMMENDATION_HOT: ("ID_HOT_STORY_TOP", "ID_HOT_STORY_BOTTOM"),
                          RECOMMENDATION_POPULAR: ("ID_POPULAR_STORY_TOP", "ID_POPULAR_STORY_BOTTOM")}


def _recommendation_fields(rec: dict, rival_relation: int) -> list[Field]:
    """rec = {swid, blaze_id, persona, type, title, row}: row = the target's speed wall result."""
    row = rec.get("row") or {}
    top, bottom = RECOMMENDATION_STORIES.get(rec["type"], ("", ""))
    return [                                            # tags ascending
        f_blaze_user("BLUS", rec["blaze_id"], rec["persona"], rival_relation),
        f_int("RETY", rec["type"]),
        f_map_float("STAF", row.get("float", {})),
        f_map_int("STAI", row.get("int", {})),
        f_map_str("STAS", row.get("str", {})),
        f_str("STOB", bottom),
        f_str("STOT", top),
        f_int("SWID", rec["swid"]),
        f_int("TABL", rec["blaze_id"]),
        f_str("TANA", rec["persona"]),
        f_str("TITL", rec["title"]),
    ]


def build_in_game_recommendations_response(seq: int, rivals: list[dict],
                                           walls: list[tuple[int, list[dict]]], *,
                                           local_id: int, rival_relation: int = RELATION_FRIEND,
                                           max_payload: int = RECOMMENDATIONS_MAX_PAYLOAD,
                                           msg_type: int = MSG_REPLY,
                                           report: dict | None = None,
                                           legacy_trim: bool = False) -> tuple[bytes, int]:
    """rivals = [{blaze_id, persona, player_score, rival_score, recommendations=[rec]}] (rec: see
    _recommendation_fields), walls = [(id, rows)] in priority order. Returns (frame, how many
    walls went in); `report` gets "dropped" (entries) and "rivals_dropped" (personas).

    Every "beat you" entry goes out WITH its speed wall: the game takes the wall by id for each
    entry (0x9d5660 for the card). The walls a rival's entries point at come first; the rest go
    in while the payload stays under max_payload; an entry whose wall still did not fit is
    dropped, and a rival left with none goes too (an empty RECM crashes the game). Up to 1.1.1
    the walls went in by id until the frame was full, so with ~450 shared walls the events (high
    ids) fell out while their entries stayed - and 7 of 7 games crashed right after such a reply
    at the end of an event (02.10, three hosts); with every wall in, none did. legacy_trim
    (--autolog-legacy-trim) is the 1.1.1 way, kept to reproduce that crash."""
    rec_walls = {rec["swid"] for r in rivals for rec in r.get("recommendations", [])}
    ordered = ([w for w in walls if w[0] in rec_walls] + [w for w in walls if w[0] not in rec_walls])

    def rili_of(rs: list[dict]) -> Field:
        return f_list_struct("RILI", [[
            f_blaze_user("BLUS", r["blaze_id"], r["persona"], rival_relation),
            f_str("PENA", r["persona"]),
            f_int("PLSC", r["player_score"]),
            f_list_struct("RECM", [_recommendation_fields(rec, rival_relation)
                                   for rec in r.get("recommendations", [])]),
            f_int("RIBL", r["blaze_id"]),
            f_int("RISC", r["rival_score"]),
        ] for r in rs])

    def fill(chosen: dict, size: int) -> int:
        for swid, rows in ordered:
            if swid in chosen:
                continue
            fields = _speed_wall_fields(swid, rows, local_id, rival_relation)
            entry = len(enc_int(swid)) + sum(len(f.encode()) for f in fields) + 1
            if size + entry <= max_payload:
                chosen[swid] = fields
                size += entry
        return size

    chosen: dict[int, list[Field]] = {}
    if legacy_trim:
        size = len(rili_of(rivals).encode()) + 16
        for swid, rows in walls:                     # by the given order, up to the first misfit
            fields = _speed_wall_fields(swid, rows, local_id, rival_relation)
            entry = len(enc_int(swid)) + sum(len(f.encode()) for f in fields) + 1
            if size + entry > max_payload:
                break
            chosen[swid] = fields
            size += entry
        missing = sum(rec["swid"] not in chosen for r in rivals for rec in r.get("recommendations", []))
        if report is not None:
            report.update(dropped=0, rivals_dropped=[], without_wall=missing)
        payload = encode_tdf([rili_of(rivals), f_map_int_struct("SPWA", chosen)])
        return Fire2(component=2050, command=21, payload=payload, error=0, seq=seq,
                     msg_type=msg_type).encode(), len(chosen)
    fill(chosen, len(rili_of(rivals).encode()) + 16)
    kept, dropped, gone = [], 0, []
    for r in rivals:
        had = r.get("recommendations", [])
        recs = [rec for rec in had if rec["swid"] in chosen]
        dropped += len(had) - len(recs)
        if recs or not had:            # one sent without entries on purpose stays (tests only)
            kept.append({**r, "recommendations": recs})
        else:
            gone.append(r["persona"])
    rili = rili_of(kept)
    # the list only shrank: what went in still fits, and the room it left takes more walls
    fill(chosen, len(rili.encode()) + 16 + sum(
        len(enc_int(s)) + sum(len(f.encode()) for f in fs) + 1 for s, fs in chosen.items()))
    if report is not None:
        report.update(dropped=dropped, rivals_dropped=gone)
    payload = encode_tdf([rili, f_map_int_struct("SPWA", chosen)])
    return Fire2(component=2050, command=21, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode(), len(chosen)


def build_special_guest_info_response(seq: int, *, msg_type: int = MSG_REPLY) -> bytes:
    """NFS.getSpecialGuestInfo (2050/39) {BLIS} -> @0x141a2c0d0 {BLIS mSpecialGuests, SPGN
    mSpecialGroupName, SPGT mSpecialGuestType, SPLA mSplashScreenFileName, STAI
    mSpecialGuestRealNames}. Special Guests were EA people's results; there are none now, so an
    empty but well-formed reply. The bare acknowledgement before 1.0.12.3 had the game ask ~700
    times a session."""
    payload = encode_tdf([f_list_int("BLIS", []), f_str("SPGN", ""), f_int("SPGT", 0),
                          f_str("SPLA", ""), f_map_str("STAI", {})])
    return Fire2(component=2050, command=39, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def build_autolog_playlist_response(seq: int, blaze_id: int, *,
                                    msg_type: int = MSG_REPLY) -> bytes:
    """NFS.getAutologPlaylist (2050/29) {BLID}. Two classes fit the reply - {BLID, PLAY mPlaylist}
    and {BLID, ROWS mPlaylist} - and the elements of a playlist are unknown, so: both lists,
    empty. The client skips the tag its class does not have."""
    payload = encode_tdf([f_int("BLID", blaze_id), f_list_struct("PLAY", []),
                          f_list_struct("ROWS", [])])
    return Fire2(component=2050, command=29, payload=payload, error=0, seq=seq,
                 msg_type=msg_type).encode()


def _dec_value(buf: bytes, p: int, wtype: int, end: int) -> tuple[object, int]:
    """Decodes ONE value of the given type; returns (value, new position).
    Values without a tag - also used for list elements and map pairs."""
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
                # An element of a struct list can be a UNION: a variant byte before the member's
                # fields. That is how the client encodes HNET (createGame, resetDedicatedServer), and
                # our f_list_ip_pair encodes it the same way. We tell it apart by the fact that the
                # first byte of a TAG always has bit 7 set (the first tag character >= '@'), while
                # the variant number is smaller; zero is left to the empty-struct terminator.
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
        # A "variable" field (a TDF object of any class): presence byte; when 1 - the class tdfId
        # (varint) and the object's fields terminated by 0x00. That is what the GameReporting 28/2
        # report looks like: PRVT = 00 (absent), RPRT.GAME = 01 + id + struct.
        present = buf[p]; p += 1
        if not present:
            return ("variable", None), p
        tdf_id, p = dec_int(buf, p)
        fields, p = _dec_fields(buf, p, end)
        return ("variable", tdf_id, fields), p
    raise ValueError(f"unknown TDF type 0x{wtype:02x} at offset {p - 1}")


def _dec_one_field(buf: bytes, p: int, end: int) -> tuple[tuple, int]:
    tag = dec_tag(buf[p:p + 3])
    wtype = buf[p + 3]
    v, p = _dec_value(buf, p + 4, wtype, end)
    return (tag, wtype, v), p


def _dec_fields(buf: bytes, p: int, end: int) -> tuple[list, int]:
    """Fields up to the struct terminator (0x00) or the end of the buffer."""
    out = []
    while p < end:
        if buf[p] == 0x00:                 # nested struct terminator
            return out, p + 1
        f, p = _dec_one_field(buf, p, end)
        out.append(f)
    return out, p


def decode_tdf(buf: bytes, p: int = 0, end: int | None = None) -> list[tuple]:
    """Decodes a TDF (heat2) payload RECURSIVELY. Returns a list of (tag, type, value);
    structs/unions/lists/maps are descended into. Used to verify round-trips of our
    own replies: if our decoder gets lost on our packet, the game will all the more."""
    if end is None:
        end = len(buf)
    fields, _ = _dec_fields(buf, p, end)
    return fields


def dump_tdf(fields: list[tuple], indent: int = 0) -> str:
    """Readable dump of the field tree (for the log and tests)."""
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
                lines.append(f"{pad}{tag} (union, variant {val[1]})")
                lines.append(dump_tdf([val[2]], indent + 1))
        elif wtype == T_VARIABLE and isinstance(val, tuple) and val[0] == "variable":
            if val[1] is None:
                lines.append(f"{pad}{tag} (variable) = ABSENT")
            else:
                lines.append(f"{pad}{tag} (variable, tdfId 0x{val[1]:x})")
                lines.append(dump_tdf(val[2], indent + 1))
        else:
            lines.append(f"{pad}{tag} = {val!r}")
    return "\n".join(l for l in lines if l)
