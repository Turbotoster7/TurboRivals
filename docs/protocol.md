# NFS Rivals protocol - what we know

A living document. Every finding records its source: either an extract from the binary or an
observation of the live client. Anything unconfirmed is marked as a hypothesis.

Binary under study: `NFS14.exe`, Steam version (app 1262600, build 10351327), x64, image base
`0x140000000`.

---

## 1. Backend endpoints

Extracted from `.rdata` (`tools/dump_strings.py`). Offsets are file positions.

| host | offset | role |
| --- | --- | --- |
| `gosredirector.online.ea.com` | `0x016ce2a0` | **production redirector** - the main target |
| `gosredirector.stest.ea.com` | `0x016ce2c0` | test environment |
| `gosredirector.scert.ea.com` | `0x016ce2e0` | certification environment |
| `gosredirector.ea.com` | `0x016ce300` | development environment |
| `https://gosca.ea.com:44125/redirector` | `0x0170d9b0` | redirector over HTTPS (alternative variant) |
| `demangler.ea.com` | `0x0170d300` | **NAT punch-through** (DirtySDK ProtoMangle) |
| `peach.online.ea.com` | `0x016eab10` | telemetry |
| `https://reports.tools.gos.ea.com/bugsentry` | `0x016768f8` | crash reports |

The four `gosredirector` variants are the standard BlazeSDK environment table (the same layout as
in Dead Space 2). The client picks one by `BlazeEnvironment`.

**Redirector port: 42127/TCP** - the standard value for Blaze of this era; confirmed by
observation (the game connected to `159.153.51.18:42127`, which is `gosredirector.ea.com`).

### P2P layer (DirtySDK)

The `dirtysdk` part of the string dump confirms that gameplay does not go through the server:

```
netgamelink          the connection layer between players
commudp-global       UDP transport
protoadvt            LAN advertising
protossl session     SSL
User-Agent: ProtoHttp %d.%d/DS %d.%d.%d.%d.%d (Windows)
```

The demangler has a simple HTTP API - the request format is in the binary verbatim:

```
http://%s:%d/getPeerAddress?myIP=%s&myPort=%d&version=1.0
myIP=%s&myPort=%d&version=1.0&status=%s&gameFeatureID=%s
```

That means **NAT traversal can be emulated with a simple HTTP server** - nothing needs breaking.
Relevant to phase 5. The binary also carries UPnP code of its own (`-noupnp`, `peerport=`).

---

## 2. Blaze components

The binary contains the TDF type names of every component it uses. Types per component
(`docs/recon/strings_NFS14.md`):

| component | types | notes |
| --- | --- | --- |
| `GameManager` | 124 | AllDrive sessions, matchmaking, host migration |
| `GameReporting` | 89 | result reporting |
| `NFS` | 51 | **Ghost Games' own component** |
| `Authentication` | 29 | login, personas, entitlements |
| `Util` | 21 | preAuth/postAuth/ping/configuration |
| `ByteVault` | 20 | player data storage |
| `Stats` | 19 | statistics |
| `Playgroups` | 14 | player groups |
| `Redirector` | 13 | |
| `Association` | 10 | friend lists |
| `Rooms` | 8 | |
| `Clubs` | 5 | |
| `Authentication2` | 4 | newer login variant |
| `Messaging` | 3 | |
| `DynamicInetFilter` | 3 | |
| `CensusData` | 1 | |

Full type list: `docs/recon/strings_NFS14_all.txt`.

The `Blaze::NFS::` component is specific to Rivals and handles, among other things,
geolocation, rival recommendations, Overwatch, rich presence and speed walls. It also contains
`NotifyBlazeTwoWayCommunication` - a generic notification channel with parameter lists
(int32/uint64/float/string).

### Start-up sequence (original hypothesis)

Based on BlazeSDK logs from other titles of the era, before we had traffic:

```
Util::preAuth        [0x0009::0x0007]
Authentication::login[0x0001::0x0028]  / loginPersona [0x0001::0x006E]
Util::postAuth       [0x0009::0x0008]
UserSessions::updateNetworkInfo [0x7802::0x0014]
GameManager::createGame / joinGame [0x0004::...]
```

Since confirmed from traffic and the binary: Redirector.getServerInstance (5/1), Util.preAuth
(9/7), Util.ping (9/2), Authentication.login (1/152, Origin token), Util.postAuth (9/8); the
UserSessions component is `0x7802` (not 30); GameManager is 4. Command names come from the
`getCommandName` jump tables in the binary (section 9).

---

## 3. TDF format - **confirmed**

### Tag encoding

A tag is 4 characters packed into 24 bits, 6 bits per character. The value 0 means a space
(tags shorter than 4 characters are padded).

```python
def decode_tdf_tag(raw: int) -> str:          # raw = 24 bits
    return "".join(" " if (c := (raw >> s) & 0x3F) == 0 else chr(c + 0x20)
                   for s in (18, 12, 6, 0))
```

Implementation: `tools/pe_probe.py::decode_tdf_tag`.

**Verification:** applied to the metadata in `.rdata`, the algorithm gives pairs that match the
field names - that cannot be a coincidence:

| tag | field |
| --- | --- |
| `BID ` | `mBlazeId` |
| `MAIL` | `mEmail` |
| `PASS` | `mPassword` |
| `PNAM` | `mPersonaName` |
| `NLST` | `mEntitlements` |
| `GID ` | `mGameId` |
| `GSET` | `mGameSettings` |
| `ATTR` | `mAttributes` / `mGameAttributes` |
| `STTE` | `mGameStateField` |

### Field dictionary

`tools/extract_tdf_meta.py` pulled out of `.rdata`:

- **2,864** (tag, field name) pairs
- **1,152** unique tags
- 121 contiguous blocks of records

Output: `docs/recon/tdf_members.md` and `docs/recon/tdf_members.json`.

So **every captured packet can be printed with field names** instead of staring at raw bytes.
That changes the nature of phase 1 - instead of guessing, we read.

Class boundaries: a field record with `meta[1] == 0` is the LAST field of its class. That splits
the 2,864 records into 975 classes, none with tags out of ascending order
(`tools/tdf_classes.py --tag/--name/--at/--stats`). The older heuristic ("tag smaller than the
previous one") glued neighbouring classes together.

### Metadata record layout

```
+0   uint64   bytes 1..3 = TDF tag, bytes 4..7 = type metadata
+8   ptr      field name ("m" + CamelCase)
+16  ...      a type-dependent tail (text fields have 2 more qwords)
```

The byte `meta[0]` takes a small, discrete set of values - the TDF type code:

```
0x05 (638x)  0x15 (334x)  0x02 (310x)  0x0a (249x)  0x17 (225x)
0x01 (218x)  0x14 (172x)  0x13 (163x)  0x18 (149x)  0x0e  (84x)
```

Mapping, derived from replies the client accepted: 4/21/22/23/24 -> int, 5 -> string,
2 -> list, 1 -> map, 10 -> struct, 14 -> bool, 8 -> blob, 13 -> time.

---

## 4. Protection of the binary

Section entropy of both executables:

| section | entropy | state |
| --- | --- | --- |
| `.text` | 1.000 | encrypted |
| `.data` | 1.000 | encrypted |
| `typeinfo` | 1.000 | encrypted |
| `fieldinf` | 1.000 | encrypted |
| `ctr` | 1.000 | encrypted (probably the protector itself) |
| `.rdata` | 0.579 | **readable** |

Consequences, as first assessed:

1. **Static code analysis of the file is out.** A scan for `lea rip+disp32` found 15 hits in
   19 MB - noise.
2. **Class -> field table mapping postponed.** The table boundaries are encoded in code, not
   data (later solved from the data itself - section 3).
3. **Patching the exe is expensive.** All the more reason for the stand-in certificate, which
   leaves the binary alone.
4. The data stayed readable, so all the work above is valid.

How this was worked around: the code is decrypted in memory. A full process dump (Task Manager
or `procdump -ma`) plus `tools/dump_image.py` gives the module image by RVA, and capstone
disassembles it. Every RVA in this document comes from such a dump.

---

## 5. Redirector SSL handshake - **confirmed**

The probe `proto-lab/ssl_probe.py` against `159.153.51.18:42127` - the redirector was still alive
even though the game's online services were off. A hand-built ClientHello, in both SSLv3 and
TLS 1.2 form, gets the full `ServerHello -> Certificate -> ServerHelloDone` sequence (the record
tail is `16 03 03 00 04 0e 00 00 00` - ServerHelloDone). That answers open questions 1-3.

### Redirector certificate - the model for the stand-in

```
subject   C=US, ST=California, O=Electronic Arts, Inc.,
          OU=Global Online Studio, CN=gosredirector.ea.com
issuer    CN=OTG3 Certificate Authority, C=US, ST=California,
          L=Redwood City, O=Electronic Arts, Inc.,
          OU=Online Technology Group, emailAddress=dirtysock-contact@ea.com
validity  2015-05-07 .. 2035-05-02   (still valid by date)
serial    0x03C2
signature md5WithRSAEncryption, 1024-bit key
```

Two facts decide the strategy:

1. **The CN is `gosredirector.ea.com`, not `...online.ea.com`.** One certificate serves the whole
   environment table from section 1, so old ProtoSSL does no strict host matching. Our **stand-in
   certificate** must carry exactly this CN.
2. **MD5-RSA signature, 1024 bits, issued by EA's internal "OTG3 CA".** The stand-in server
   presents its own certificate with the same CN, generated with its own key. We do not need -
   and do not have - EA's private key; this is the identity of our own server, not an
   impersonation of a working service (EA's service is switched off). Section 8 describes what
   old ProtoSSL actually checks.

### Chosen cipher and version (from `.bin` via `parse_records`)

All three probes got the same ServerHello:

| probe | server version | chosen cipher |
| --- | --- | --- |
| SSLv3   | SSLv3   | `TLS_RSA_WITH_AES_256_CBC_SHA` (0x0035) |
| TLS 1.0 | TLS 1.0 | `TLS_RSA_WITH_AES_256_CBC_SHA` (0x0035) |
| TLS 1.2 | TLS 1.2 | `TLS_RSA_WITH_AES_256_CBC_SHA` (0x0035) |

Three conclusions:

- **The server echoes the client's version** rather than forcing its own. The real handshake
  version therefore depends on what the game offers.
- **Key exchange is RSA** (no ServerKeyExchange, no ECDHE/forward secrecy). The best case for a
  stand-in certificate: the client encrypts the premaster with the public key from our
  certificate and we decrypt it with our private key - nothing here needs EA's private key.
- The server picked AES-256-CBC-SHA even though our list started with RC4.

### Live client - proxy confirmed (Track A)

`proto-lab/tcp_proxy.py` between the game and the real EA (`159.153.51.18:42127`), session
`120822-003`. **The client connects and completes the whole handshake** - open question 1
answered. Its ClientHello:

- record layer: **SSLv3** (`0x0300`), version in the ClientHello body: **TLS 1.1** (`0x0302`).
  Typical of DirtySDK/ProtoSSL - an old stack wrapped in an SSLv3 record.
- offered ciphers (4): `RC4_128_SHA`, `RC4_128_MD5`, `AES_128_CBC_SHA`, `AES_256_CBC_SHA`. The
  server chose `AES_256_CBC_SHA` - consistent with the probes.
- right after the handshake the client sent `ApplicationData` (256 B) - the first encrypted Blaze
  packet. A passive proxy cannot read it; that needs a stand-in server terminating TLS with its
  own certificate (Track B, section 8).

Note on EA's ServerHello: the last 8 bytes of randomness are the `DOWNGRD\x00` sentinel
(downgrade protection) - our server need not reproduce it, the old client ignores it.

---

## 6. Open questions

In the order they were settled.

1. ~~**Does the client still try to connect?**~~ **YES (section 5).** The live client connects to
   the redirector through `hosts` and completes a full TLS 1.1 handshake.
2. ~~**SSLv3 or newer TLS?**~~ **Settled (section 5).** The client offers TLS 1.1 (in an SSLv3
   record) and RC4/AES ciphers; `TLS_RSA_WITH_AES_256_CBC_SHA` gets negotiated with EA.
3. ~~**Will the client accept a stand-in certificate?**~~ **YES (section 8)** - issuer DN OTG3,
   signature OID patched to `rsaEncryption`, record version 0x0302, RC4_SHA. Research first
   corrected the assumption: old ProtoSSL DOES check the signature, so a plain self-signed
   certificate would be rejected - the `rsaEncryption` OID bug (iHashSize=0) gets past it.
4. ~~**Framing: Fire or Fire2?**~~ **Fire2.** The message type sits in the high nibble of byte 8;
   a reply is `0x10`, a notification `0x20`.
5. ~~**Component and command numbers**~~ **Settled** from the `getCommandName` tables in the
   binary (section 9; Util = 9, UserSessions = 0x7802, GameManager = 4).
6. ~~**TDF type codes**~~ **Settled** - see the `meta[0]` mapping in section 3.
7. ~~**Is gameplay traffic encrypted with a key from Blaze?**~~ **Does not matter** - players
   connect directly (UDP 3659), the server only hands out addresses, and 2-6 player sessions work
   (section 12).

Open as of 2026-09-30: internet play without a VPN (NAT; the binary has its own UPnP code and
the demangler API, section 1), OTHER players' profile pictures in the game (section 14 - the
same path, not yet confirmed in a shared session), the upload format of a picture set in the
game itself, and a few RPCs answered with an empty acknowledgement.

---

## 7. External sources

- [Aim4kill/Bug_OldProtoSSL](https://github.com/Aim4kill/Bug_OldProtoSSL) - the certificate verification bug in old ProtoSSL
- [jacobtread/tdf](https://github.com/jacobtread/tdf), [blaze-ssl](https://github.com/jacobtread/blaze-ssl) - Rust libraries
- [PocketRelay/Server](https://github.com/PocketRelay/Server) - architecture model + [NAT tunnelling](https://jacobtread.com/blog/pocket-relay-tunnel/)
- [grid-leak/blaze](https://github.com/grid-leak/blaze) - Blaze for Mirror's Edge Catalyst
- [open-ds2-server](https://github.com/lowlevelmetal/open-ds2-server) - notes on the connection flow
- [pedromartins1/BlazeServer](https://github.com/pedromartins1/BlazeServer) - BF3 emulator (C#), the same Blaze Fire2/heat2 engine; a reference for Util commands and PostAuth structures

---

## 8. Track B - a server that terminates TLS - **works with the live client**

Goal: see the first Blaze packet in plain text. `proto-lab/tls_terminator.py` runs its own
handshake, decrypts the premaster with our private key and dumps `ApplicationData` to
`docs/recon/capture/` (the launcher: `%LOCALAPPDATA%\TurboRivals\capture`).

### Correcting an assumption: ProtoSSL DOES check the signature

We first assumed old ProtoSSL does not check the signature and a plain self-signed certificate
would do. Research ([Aim4kill/Bug_OldProtoSSL](https://github.com/Aim4kill/Bug_OldProtoSSL))
showed otherwise: the parser **compares the signature hash** (`memcmp` over `iHashSize` bytes), so
a plain self-signed certificate **would be rejected**. The workaround is a bug: set the signature
algorithm OID in the certificate to `rsaEncryption` (`2a 86 48 86 f7 0d 01 01 01`,
ASN_OBJ_RSA_PKCS_KEY), the parser falls into the `default` branch, sets `iHashSize = 0`, and then
`memcmp(...,0) == 0` - verification passes without checking. First tested on BF3/BF4
(Frostbite 2013, the same DirtySDK generation as Rivals). `make_stub_cert.py` generates the
certificate (issuer DN OTG3, both OID occurrences set to `rsaEncryption`) into `pki/server.der`.

Also found on the live client: the certificate must be issued by the OTG3 DN, and the record
version must be 0x0302 (do not echo the ClientHello's 0x0300). The game checks the CN against the
host name it connects to, so Blaze is handed a HOST name (`gosredirector.ea.com`), never a raw IP.

### RC4 instead of AES

EA negotiated AES-256-CBC-SHA, but the client **also offered `RC4_128_SHA`** (section 5,
Track A). Our server picks RC4 - the client accepts it. RC4 has no IV and no padding, so record
protection (RC4 + HMAC-SHA1 over the plaintext) is trivial. [jacobtread/blaze-ssl](https://github.com/jacobtread/blaze-ssl)
makes the same simplification.

### Parameters and verification

- Negotiation: ServerHello `0x0302`, cipher `0x0005`, no session id, null compression; RSA kx;
  TLS 1.0/1.1 PRF (P_MD5 XOR P_SHA1); HMAC-SHA1 MAC.
- Crypto in pure Python (RC4, PRF, RSA-decrypt PKCS#1 v1.5). The key is read by a DER parser of
  our own (`load_rsa_priv`), and the certificate is built with `cryptography` - since 29.09
  nothing needs `openssl` on the machine.
- The smoke test (a pure-Python test client mirroring the handshake): Finished `verify_data` OK
  in both directions, `ApplicationData` decrypted 1:1. On the live client the handshake closes
  and every Blaze exchange since runs over it.

---

## 9. QoS coordinator (DirtySDK `qosapi`) - **confirmed from the code**

After `Util.postAuth` the game starts a QoS test: it takes the ping site from `QOSS` (our
`preAuth` reply), queries it over **HTTP**, then probes it over **UDP**. The findings below come
from disassembling a memory dump (RVAs relative to module base `0x140000000`), not from analogy
with other titles.

### HTTP endpoints

URL patterns in the binary (`0x170ee60`+):

```
%s://%s:%u/qos/qos?vers=%d       + &qtyp=  &prpt=
%s://%s:%u/qos/firewall?vers=%d  + &nint=
%s://%s:%u/qos/firetype?vers=%d  + &rqid=  &rqsc=  &inip=  &inpt=
```

`prpt` = the port the client will probe from; `rqid`/`rqsc` are the `requestid`/`reqsecret` the
client read from OUR reply - their appearance in the `firetype` query proves the XML was parsed.

### Reply format: XML, not `key=value`

`_QosApiParseResponse` @`0xfdb070` (`rcx` = connection struct, `rdx` = `QosApiRef`) reads the HTTP
reply buffer at `*(QosApiRef+0x128) + 0x112` and tries `XmlFind(buf, "firewall")`,
`XmlFind(buf, "firetype")`, `XmlFind(buf, "qos")` in turn; when none hits, it returns `-2`.

| RVA | function | how it was identified |
| --- | --- | --- |
| `0xfee910` | `XmlFind(pXml, pName)` | scans to `0x3c` (`<`), skips `<?..?>` and `<!..>`, stops at `</`; name terminator mask `0x40008001FFFFFFFF` = `{0x00-0x20, '/', '>'}` - **no `=`**, so these are elements, not attributes or `key=value` pairs; `pName[0]=='.' && pList[0]=='<'` -> both `++` (descend to children) |
| `0xfee6a0` | `XmlContentGetInteger(pXml, iDefault)` | after `<` skips to `>`, `<tag/>` returns the default, then whitespace, `+`/`-`, digits |
| `0xfeeaf0` | `XmlNext` | the loop over `ips`/`ports` siblings @`0xfdb170` |

So the names `.numprobes`, `.probesize`, `.qosport`, `.requestid`, `.reqsecret`,
`.numinterfaces`, `.ips`, `.ports`, `.firetype` (`0x170ef08`+) are **XML element names**. Correct
replies:

```xml
<qos><numprobes>10</numprobes><probesize>64</probesize><qosport>17502</qosport>
<requestid>1</requestid><reqsecret>1</reqsecret></qos>

<firetype><firetype>1</firetype></firetype>

<firewall><numinterfaces>1</numinterfaces><ips>2130706433</ips><ports>17502</ports>
<requestid>1</requestid><reqsecret>1</reqsecret></firewall>
```

`ips` is the IP as a big-endian `uint32` written in decimal. The game walks the `ips`/`ports`
lists with `XmlNext` (over siblings), so `numinterfaces` pairs go as all the `<ips>` together,
then all the `<ports>`. A live memory dump later showed that `ips`/`ports` must be nested
(`<ips><ips>..</ips></ips>`) for the firewall branch - `tls_terminator._qos_body` sends that shape.

### Validation (`0xfdb3f1`-`0xfdb424`)

`return 0` (success) only when:

```
if (qtyp == 2)            -> probesize != 0 && numprobes >= 2    // bandwidth test
qosport != 0                                                     // always
requestid != 0                                                   // always
```

Return codes: `0` = accepted, `-1` = rejected by validation, `-2` = none of the three elements
found. State fields (`*(QosApiRef+0x128)`): `+0x1118` qtyp, `+0x111c` probesize, `+0x1120` probes
sent counter, `+0x1124` numprobes, `+0x1128` received counter, `+0x1130` requestid, `+0x1134`
reqsecret, `+0x1138` numinterfaces, `+0x113c` ips[], `+0x1144` ports[], `+0x1148` firetype;
`qosport` is a `word` at `QosApiRef+0x124`.

### UDP probe - receive requirements (confirmed live)

There are TWO kinds of probes. The client itself tells them apart by `ntohl(packet+0x04)`
(`0xfdb76d`): `< 2` is the latency measurement, `>= 2` the bandwidth path.

**Latency probe** - builder @`0xfdbe80`, length hard-coded to `0x14` (20 B), all big-endian:

```
+0x00  ping site id (*(u32*)[QosApi+8])      +0x04  requestid
+0x08  reqsecret                             +0x0c  [QosApi+0x14]
+0x10  send time (NetTick)
```

Receive @`0xfdb6a0` - **a bare echo is rejected**:

| RVA | condition / read |
| --- | --- |
| `0xfdb737` | `len >= 0x10`, otherwise the packet is dropped |
| `0xfdb76d` | `ntohl(+0x04) < 2` selects the latency path |
| `0xfdb777` | **`len >= 0x1e` (30 B)** - a 20-byte echo fails here |
| `0xfdb82e` | `RTT = receive_time - ntohl(+0x10)` - the time must be echoed |
| `0xfdb7cb` | `ntohl(+0x14)` -> the client's external IP (stored in state) |
| `0xfdb804` | `ntohs(+0x18)` -> the client's external PORT |
| `0xfdb8be` | `ntohl(+0x1a)` = tail length; `memcpy` from `+0x1e` only when `(length - 1) <= 0xff`, so `0` = no tail |
| `0xfdb918` | bit0 of `ntohl(+0x0c)` picks the "enough samples" threshold: `[..+0x13c] >> 2` or `[..+0x13c]` |

So the correct reply is **30 B**: the 20 B of the probe echoed + the sender's IP (4 B BE) + the
sender's port (2 B BE) + `0x00000000` as the tail length. That is the point of the QoS probe: the
client learns its external address and measures RTT. Implementation: `_qos_probe_reply` in
`tls_terminator.py`.

**Coupling with `requestid`:** the same field picks the receive path, so for the latency test it
must be `< 2`, while validation of the HTTP reply needs `!= 0` - i.e. **exactly 1**. The
bandwidth path probe (length `probesize`, builder @`0xfdbc30`: `+0x00` id, `+0x04` requestid,
`+0x08` reqsecret, `+0x0c` counter, `+0x10` numprobes) would need `requestid >= 2`; there the code
only compares requestid/reqsecret with its state and counts bytes, so a plain echo is enough.

### UserSessions component commands (0x7802)

`getCommandName` @`0xf285b0` has a jump table @`0xf2867c` (index = `cmd - 3`, 0x28 entries). From
it, without guessing:

| cmd | name | cmd | name |
| --- | --- | --- | --- |
| 3 | fetchExtendedData | 0x17 | lookupUserGeoIPData |
| 5 | updateExtendedDataAttribute | 0x18 | overrideUserGeoIPData |
| 8 | updateHardwareFlags | 0x19 | updateUserSessionClientData |
| 0xC | lookupUser | 0x1A | setUserInfoAttribute |
| 0xD | lookupUsers | 0x1B | resetUserGeoIPData |
| 0xE | lookupUsersByPrefix | 0x20 | lookupUserSessionId |
| 0xF | lookupUsersIdentification | 0x21 | fetchLastLocaleUsedAndAuthError |
| **0x14** | **updateNetworkInfo** | 0x22 | fetchUserFirstLastAuthTime |
| | | 0x23 | resumeSession |

The same technique (`getCommandName` + jump table) works for every component - cheaper than
guessing numbers from other games' emulators.

### resumeSession (0x23) - back after a dropped connection

`ResumeSessionRequest {SKEY mSessionKey}` (@`0x1416ae9e0`/@`0x1416d7c50`). A game whose Blaze
connection dropped (the server restarted, the PC slept) reconnects **straight to the Blaze
port** and sends the key from its login reply (`KEY = "1_<uid>_sess"`; 23 B on 01.10). Since
1.0.12 `Lobby.resume` gives the session that uid back, under these conditions:
- the player must be known here: the local player from 127.0.0.1, `ea:<uid>`, or an address
  entry with that uid;
- nobody may be logged in under that uid from another address;
- the player's old, possibly half-open connection leaves its games.

The reply is empty (success) and the login notifications follow (2, 1, 8). A key that cannot be
resumed gets `error = 1` (ERR_SYSTEM, ASSUMED: the value of
`USER_ERR_RESUMABLE_SESSION_NOT_FOUND` is unknown), so the game logs in from scratch. Up to
1.0.11 it got an empty acknowledgement, pinged once and closed the connection.

### lookupUsers (0xD) - which player owns a car

A game names every car in its world by the owner's **PersonaId** (from the EA App, section 13)
and looks for the Blaze user with that BlazeId. When none exists, it asks `lookupUsers`:
`{LTYP mLookupType, ULST mUserIdentificationList}` @`0x141a2ef98`, `LTYP 0 = BLAZE_ID` (enum
names `BLAZE_ID PERSONA_NAME EXTERNAL_ID ACCOUNT_ID ORIGIN_PERSONA_ID`). The reply is
`UserDataResponse` @`0x1416d96a8 {ULST}` of `UserData` @`0x1416da330 {EDAT mExtendedData, FLGS
mStatusFlags, USER mUserInfo}`; `FLGS = 3` (SUBSCRIBED|ONLINE) is the standard BlazeSDK value,
not read from this binary.

Left unanswered, the car stays an **ordinary racer**: icon and name only up close. On 16.09
(log-40) the guest asked about `1006431274704`, the host's PersonaId, while the host was logged
in under its EA App user id `1012917074704`. There were 126 such queries from 13 to 16.09 and none
in the 30.09 sessions, where every uid was already the PersonaId. `Lobby.resolve` answers with
the id that was asked. It checks, in order:

1. a live uid;
2. an alias learned earlier;
3. a player whose `listUserEntitlements2` BUID is that id;
4. a stored player;
5. the only other player in a shared game whose uid is unconfirmed (synthetic, or a launcher
   guess). Each player owns one such id.

`--no-lookup-users` restores the empty acknowledgement.

---

## 10. The EA activation gate (ActivationUI) and the launch environment

After "Play" in Steam the chain is: `EASteamLauncher` -> `Core/ActivationUI.exe` (the activation
gate, Qt) -> only then `NFS14.exe`. ActivationUI validates the entitlement with
`accounts.ea.com` (over TLS) and on failure shows a login window instead of starting the game
(strings `access_title_entitlement_failed`, `could not connect to EA Core`). The symptom of
missing fresh authorisation in the launch environment: `EAAuthCode=NeedsAFreshAuthCode`.

### The launch environment passed to the game

Taken from a memory dump of `ActivationUI.exe` (the process environment block, `NAME=VALUE` pairs
in UTF-16). Secret values are PER SESSION and expire - redacted here (`<...>`), because the repo
is meant to be public.

| variable | value | notes |
| --- | --- | --- |
| `EAConnectionId` | `Origin.OFR.50.0000676` | the game's offer id |
| `EALicenseToken` | `Origin.OFR.50.0000676` | the same offer id |
| `EAEntitlementSource` | `STEAM` | where the entitlement comes from |
| `EAExternalSource` | `STEAM` | |
| `EALaunchOwner` | `STEAM` | |
| `EALaunchEnv` | `production` | |
| `EALaunchOfflineMode` | `false` | **the only EA* variable the game itself reads** |
| `EAFreeTrialGame` | `false` | |
| `EAGameLocale` | `pl_PL` | |
| `EALsxPort` | `3216` | LSX port to the EA App (`127.0.0.1`) |
| `EALaunchEAID` | `<EA account nickname>` | in the clear, but specific to the account |
| `EAAuthCode` | `<auth code>` | **secret**; `NeedsAFreshAuthCode` = no authorisation |
| `EALaunchUserAuthToken` | `<EA account JWT>` | **secret**; RS256, `iss=accounts.ea.com` |
| `EASecureLaunchTokenTemp` | `<persona id>` | **secret**; = `UserId` from LSX |
| `EALaunchCode` | `<20 characters>` | **secret** |
| `EARtPLaunchCode` | `<number>` | **secret** |

### Consequence - the game does not validate the entitlement itself

`NFS14.exe` contains only `EALaunchOfflineMode` as a string (0x1413cd280; `tools/xref.py --str`,
no `lea` references). The rest of the block is consumed by ActivationUI. So the gate validates
the entitlement, not the game - hence `proto-lab/launch_direct.py` starts `NFS14.exe` directly
with a reconstructed environment, skipping activation. (For playing, start the game through the
EA App - that is what hands it an Origin token. `launch_direct.py` is an analysis tool.)

---

## 11. Client config (CONF in the preAuth reply) - **confirmed from the code**

In the preAuth request the client sends `FCCR{CFID='BlazeSDK'}`, and it receives its
configuration in `PreAuthResponse.CONF` = a struct with one `CONF` field of type
`map<string,string>`. The connection timing keys are read by one function, `0xf419b0`, through
the connection object's getter `0xf39dc0` (`[vtable+0x50]`, vtable `0x1416d41f0`). There are no
other references to these strings in `.text`. The map keys must be sorted - keys appended at the
end were "not found" (that is how the `bytevault*` keys once went missing).

| key | field | when the key is missing | stored as |
| --- | --- | --- | --- |
| `pingPeriod` | `[conn+0x2f8]` ms | 15000 | value/1000; a result < 1000 -> 15000 |
| `defaultRequestTimeout` | `[conn+0x1c4]` ms | unchanged | value/1000 |
| `connIdleTimeout` | `[conn+0x2fc]` ms | 40000 (constructor `0xf2e7d0`) | value/1000 |

### Time value format (parser `0xf79d60`)

Segments `<number><unit>`, units `d`, `h`, `m`, `s`, `ms`. Segments can be joined directly or
with `:` (`1m30s`, `1h:30m`). The result is in **microseconds**:
`((((d*24 + h)*60 + m)*60 + s)*1000 + ms)*1000`. A number without a unit is an error: the parser
reaches the NUL, which is not a unit, and returns false without storing.

The trap: the getter **ignores** the parser's result (`call 0xf79d60; mov al, 1`). For a key
present in the map it always reports "found", and the reader then takes an unwritten local
variable equal to 0. A bad format therefore gives not the default but **zero**.

### What `connIdleTimeout` is for

The per-frame connection update (`0xf3a580`, slot 0 of the conn vtable) drops the connection
with error `0x800e0000` (`0xeffca0`) when:

    [[conn+8]+0x52c] == 0  &&  [conn+0x30] == 2  &&
    (arg2 - [[conn+0x28]+0xcd0]) > [conn+0x2fc]      (unsigned, ms)

`arg2` is the current time passed to the function, `[[conn+0x28]+0xcd0]` the time of the last
activity (read through `0xefe7a0`). With `[conn+0x2fc]=0`, 1 ms of silence is enough.

---

## 12. Multiplayer (GameManager) - **works live: 2-6 players, host migration**

As of 2026-09-30: sessions of 3-6 players and host migration tested live, over a LAN and over
Radmin VPN.

### Topology

The game creates games with `NTOP=133` = `PEER_HOSTED_DIRTYCAST_FAILOVER` (enum `@0x141706950`):
players connect directly (UDP 3659), and EA's relay (DirtyCast) is only a fallback, which no
longer exists. The server carries no game traffic - it only has to give the players correct
addresses.

### Addresses

The client learns its external address from the reply to the QoS latency probe (`+0x14` IP,
`+0x18` port) and then reports it in `updateNetworkInfo` (ADDR), `createGame` (HNET) and
`startMatchmaking` (PNET). The player on the server's machine probes from `127.0.0.1`, so the
server gives it this machine's network address (`--public-ip`, by default the detected LAN
address). The ping site address (preAuth `QOSS.PSA`) and `<ips>` in `/qos/firewall` also depend
on the client: the local one gets `127.0.0.1`, another machine gets the server's network address.

### Join flow (matchmaking, `MODE=3` find or create)

| Step | To whom | Frame |
|---|---|---|
| `startMatchmaking` reply | joiner | `{MSID}` |
| other players in the game | joiner | `UserAdded` (0x7802/2) with the player's address |
| the game | joiner | `NotifyGameSetup` (4/20): roster of everyone, REAS variant 3 `RSLT=SUCCESS_JOINED_EXISTING_GAME` (2) |
| the new player | players in the game | `UserAdded` of the joiner + `NotifyPlayerJoining` (4/21) `{GID, PDAT}` |
| `updateMeshConnection` (4/29) `STAT=CONNECTED` (2) between joiner and host | everyone | `NotifyGamePlayerStateChange` (4/116) `{GID PID STAT}`, then `NotifyPlayerJoinCompleted` (4/30) `{GID, PID}` |

4/116 before 4/30 is required: without 4/116 the joiner's player object stayed
`ACTIVE_CONNECTING` and a timeout after the world loaded deleted the game (run-39 -> run-40,
see decisions.md 2026-09-16).

In the roster (`ReplicatedGamePlayer`) the player's seat number (host 0, then 1, 2...) goes into
`SID` (`mSlotId`) and `CSID` (`mConnectionSlotId`), while `SLOT` is `mSlotType` =
`SLOT_PUBLIC_PARTICIPANT` (0; enum `@0x1416d9790`: PUBLIC_PARTICIPANT 0, PRIVATE_PARTICIPANT 1,
PUBLIC_SPECTATOR 2, PRIVATE_SPECTATOR 3). The first LAN test (log-29) had `SID=CSID=0` for both
players and both games reported `STAT=0` - nobody saw anybody.

A game "to be found" = attribute `gameMembershipRequirements=Public`, host connected, state
`PRE_GAME`/`IN_GAME`, a free seat. Games in `CRIT.AGAM.GIDL` come last. A game that dropped out
of a session puts that session's gid there: on 01.10 the request of a laptop back from sleep
grew by exactly 11 B, `[0x10000001]`. Since 1.0.12.1 such a game is still taken when it is the
only joinable one; `--strict-avoid` skips it as before. No such game -> a new game with the
requester as host (`RSLT=SUCCESS_CREATED_GAME`).

### Private session - `resetDedicatedServer` (4/25)

A game with the session set to **private** does not matchmake at all: instead of
`startMatchmaking` it sends `resetDedicatedServer` (4/25) and waits for `NotifyGameSetup`.
Without a reply it sits on "Searching for game" forever (log-36 and log-37: empty ack, then
silence). Identified from the capture `blaze-012432-006-23.bin` (276 B, fully decoded):

| Field | Private session (4/25) | Public (4/13) |
|---|---|---|
| `ATTR.gameMembershipRequirements` | `Private` | `Public` (from `CRIT.RLST`) |
| `GSET` | 276 | 287 |
| `PMAX` | 0 (capacity only in `PCAP` = `[6,0,0,0]`) | 6 |
| `TIDS` | `[65534]` | `TID` 65534 |

The remaining tags are the same as in `createGame` (`ATTR GNAM GSET NTOP PRES VOIP VSTR PCAP TIDS
HNET`), so the game parameters are read by the same code. The difference 287 -> 276 is the
cleared "open to browsing" and "open to matchmaking" bits of the standard `GameSettings` bitfield
(the bit names are NOT in the binary - circumstantial; the `Private` string in `ATTR` decides).

Reply: `CreateGameResponse` `{GID, JGS, REX}` (@`0x141a300b0`) with command number 25 - the string
`ResetDedicatedServerResponse` is not in the binary, and this is the only GameManager reply with
just `GID`. Then `NotifyGameSetup` (4/20) with `REAS` = **variant 1**
`ResetDedicatedServerSetupContext` (the `VALU` table @`0x141a30298`). The context class **has no
fields**: between `DatalessSetupContext {DCTX}` @`0x141a30100` and `MatchmakingSetupContext
{FIT...}` @`0x141a30120` there is no member table at all, so `VALU` stays empty.

### A list of structs whose elements are unions (`HNET`)

`HNET` travels as a list (type 4) with element type 3 (struct), but each element begins with **a
union variant byte** (2 = `IpPairAddress`) before the member's fields. Our encoder had done this
for a long time (`f_list_ip_pair`), the decoder had not - and fell apart on
`resetDedicatedServer` ("unknown TDF type 0x70 at offset 117"). The decoder recognises the variant
because the first byte of a TAG always has bit 7 set (the first tag character is >= `@`), while a
variant number is smaller; zero remains the terminator of an empty struct. After the fix all
1,672 frames from the log-36/log-37 captures decode without error.

### Leaving

`leaveGameByGroup` (4/22), `removePlayer` (4/11), `destroyGame` (4/2) and a dropped connection ->
`NotifyPlayerRemoved` (4/40) `{CNTX GID LFPJ PID REAS}` to the remaining players. Enums:
PlayerRemovedReason `PLAYER_CONN_LOST=1 PLAYER_LEFT=6 GROUP_LEFT=7`. The host left and someone
stayed -> **host migration** (below). Only with `--no-host-migration` do the others get just
`NotifyGameRemoved` (4/16) `{GID, REAS=HOST_LEAVING}` (3) - the behaviour from before migration.

The layouts of `NotifyPlayerRemoved` (`@0x141a30560`) and `NotifyGameRemoved` (`@0x141a303a8`)
come from the field names of the tables; they work live.

### Host migration (`Lobby._start_migration`, `lobby.py`)

The player with the lowest seat number becomes the new host. The order matters - in log-29 a
client that got the host removed with no migration announced tore the game down and crashed:

| Step | To whom | Frame |
|---|---|---|
| 1 | the others | `NotifyHostMigrationStart` (4/70) @`0x141a305e0` `{CSLT GID HOST PMIG SLOT}` - `SLOT`/`CSLT` = the new host's seat NUMBER (in the roster `SLOT` is the seat type!), `PMIG` = `HOST_MIGRATION_TYPE` (by default 2 = topology + platform) |
| 2 | the others | `NotifyPlayerRemoved` (4/40) of the old host (`--migration-skip-player-removed` leaves it out) |
| 3 | the others | admin list (4/202): new host `GM_ADMIN_MIGRATED`/`GM_ADMIN_ADDED`, old host `GM_ADMIN_REMOVED` - without it (tests 53-59) a returning player never became admin and its game gave up the join after ~8 s |
| 4 | new host -> server | `updateGameHostMigrationStatus` (4/24) **twice** for type 2: `MTYP=1` (platform), then `MTYP=0` (topology) - test 54 |
| 5 | everyone | on `MTYP=1`: `NotifyPlatformHostInitialized` (4/71); after the last part: `NotifyHostMigrationFinished` (4/60) `{GID}` (layout ASSUMED - a single-field class) |

During the migration the game is in state `MIGRATING`, so matchmaking puts no new players into
it. A safety timer (`--migration-timeout`, 10 s) finishes the migration when the new host never
reports its status. After a migration the game is left out of matchmaking by default
(`--join-migrated-games` turns that on) - in test 62 a player joining a migrated game waited
~50 s and left.

### Player identity (server, `lobby.py`)

A player's uid = **the id of the career save its game loads** (the PersonaId, section 13) -
otherwise progress went into a file the game never reads. `players.json` (`~/TurboRivals/data`):

- `local` - the player on the server's machine (`127.0.0.1`); uid from `ea_identity.resolve()`
  (`--local-id` overrides it), name from `--local-persona`;
- `ea:<save id>` - a remote player whose id was reported by its launcher
  (`/turborivals/identify`, section 15) or by the host (`--player-id IP=ID`); the entry also keeps
  `user` (the EA App user id), so a later login without the launcher and from another address
  (LAN/Radmin) lands in the same entry by the token's account suffix;
- `<IP address>` - the fallback: a synthetic uid from a pool (1000.../1100...), progress does not
  survive a game restart.

A reported id must carry the suffix from the login token (AUTH, field [5]) - or the EA App user
id reported with it must (older accounts, section 13). An old `ea:<EA App user id>` entry (guessed
by launchers 1.0.2/1.0.3) is merged into the right one (`Lobby._settle_user`: the name and the
results move over).

**Names.** The game does NOT tell the server its EA nickname: `GNAM` in
`createGame`/`startMatchmaking` only echoes the name from our login (`DSNM`). Order: the name the
player typed into its own launcher (`identify`, `name=`) > the host's list `--player IP=NAME` >
the stored one > `Player_<octet>`. Names are folded to printable ASCII (`Ł`->`L`, NFKD), at most
32 characters (`_clean_name`).

### Setting up a second machine on the LAN

- the file `C:\Windows\System32\drivers\etc\hosts`: `<server address> gosredirector.ea.com` -
  **one** line with that name. Windows returns every match in file order and the game takes the
  first: an old hand-written `127.0.0.1 gosredirector.ea.com` line above the launcher's block
  sent the guest's game to itself (30.09 - the host's log empty, the game said "cannot connect").
  The launcher removes such lines (`hosts_switch.strip_redirects`) and checks `getaddrinfo`
  before starting the game (`commands.resolved_redirector`),
- the game through the EA App, as on the server's machine,
- on the server's machine, Windows firewall permission for the server (TCP 42127, 14219, 17502;
  UDP 17502-17503) and for the game (UDP 3659).

---

## 13. The career save id (PersonaId) - **confirmed live 30.09**

The career lives locally: `Documents\Ghost Games\Need for Speed(TM) Rivals\settings\<id>.sav`
(encrypted, 716,800 B; Documents may sit in OneDrive - `ea_identity.documents_dir` asks the
shell). The game **writes** to the file named after the uid in our reply to login (1/152), but
**loads** the file named after the PersonaId it gets from the EA App over LSX `GetProfile`. The
game does NOT send the PersonaId to Blaze (captures searched: not as text, not as heat2, not as
BE32), so the server has to get it from outside - from the player's launcher.

Sources, in order (`ea_identity.resolve`):

1. **The EA App's log** `%LOCALAPPDATA%\Electronic Arts\EA Desktop\Logs\EADesktopVerbose.log` (and
   `.bak`): `<GetProfileResponse UserIndex="0" UserId=".." PersonaId=".." Persona="nick" ...>`.
   The EA App USUALLY MASKS the ids (`UserId="####" PersonaId="####"`) - the desktop happened to
   have unmasked entries, on the laptop all were masked. The nickname (`Persona`) is always in the
   clear - the launcher puts it into the name field.
2. **A save with the account's suffix**: the EA App user id (`user.userid` from `user_*.ini`),
   the token (`AT1:...:<suffix>:...`) and the PersonaId of newer accounts end in the same 5
   digits (user `1012917074704`, save `1006431274704`).
3. **The only EA save on the disk** - not synthetic, not an EA App user id, not in the family of
   another account from `user_*.ini`. Older accounts do NOT follow the suffix rule: user
   `1004043460810`, save `1802434674` (10 digits; written on 15.09 while the game ran without our
   login, i.e. under its own PersonaId).
4. A guess (the EA App user id) - the launcher shows an orange warning. That is how the guest's
   first paint job was lost on 30.09.

Result: logged in under the right id, a paint change sticks (the host on the morning of 30.09,
the guest in the evening).

---

## 14. ByteVault - REST over TLS on the Blaze port

The `bytevaultHostname/Port/Secure` keys in CONF (preAuth) point ByteVault at our server
(`gosredirector.ea.com:14219`, TLS). It is HTTP, not Fire2 - handled by `_serve_http` (keep-alive;
`Connection: Close` ends the session). Client headers: `User-Agent: ProtoHttp 1.3/DS
13.3.1.2.1 (Windows)`, `X-USER-ID: 0`, `X-USER-TYPE: USER_TYPE_INVALID` (no token from
getAuthToken). Path templates from the binary: `contexts/{context}/categories`,
`.../{categoryName}`, `.../recordinfo`, `.../records/{recordName}`.

**Record size.** A reply goes out in TLS records of at most 16,384 B of plaintext
(`Wire.send_record`, `MAX_FRAGMENT`). Up to 1.0.9 the whole HTTP reply went into one record.
Pictures of 8-15 KB worked that way; a player's detailed photo (game JPEG up to 64 KB) went over
the TLS limit, and players reported a drop a few seconds after joining a session (01.10). The
launcher now keeps the game's JPEG within 16 KB as well. A Pictures GET serves only the
launcher's JPEG; what the game itself writes is kept but no longer served back.

| Request | Reply |
|---|---|
| `GET /1.0/contexts/nfs-rivals-{pc,common}/categories/Unlocks/recordinfo?ownerId=..&ownerType=NUCLEUS_{USER,PERSONA}` | `{"records":[],"totalCount":0}` |
| `GET /1.0/contexts/nfs-rivals-common/categories/Pictures/records/<uid>?ownerId=<uid>&ownerType=NUCLEUS%5FUSER&subrecord=` | **raw JPEG bytes**, `Content-Type: image/jpeg` - **confirmed 30.09**: the game showed the profile picture |

**Profile pictures.** The game asks for `Pictures/<uid>` for every player it shows (itself too),
once or a few times per session - not in a loop. `<uid>` = the uid from our login. An empty reply
(`{}`) = no picture. The server sends the player's 256x256 JPEG from its launcher
(`<data_dir>/avatars/<uid>.jpg`); `--bytevault-pictures raw|json|off` stays for comparisons, `raw`
is the right one. From the binary: `NFSNetworkSetProfilePicture`,
`UGC_CONTENT_TYPE_PROFILE_PICTURE`, `AllDriveProfilePicture`, `ByteVaultPicturesCategory`,
`ByteVaultPicturesContentType`; the game links libjpeg. Classes: Record `{DELT INFO LOAD}`
@`0x141a2c8e0`, payload `{DATA mBlob, MIME mContentType}` @`0x1416b50c0`, upsert
`{ADDR AUTH LOAD SUBR}` @`0x1416b6f30`.

Writes from the game (PUT/POST/PATCH) are kept in `<data_dir>/bytevault/<ctx>/<cat>/<name>.body`
(+ `.meta.json`) and served back on GET - in case a picture gets set in the game itself. No such
write has been caught yet.

---

## 15. The launcher channel - HTTP on the QoS port (TCP 17502)

The launcher talks to the host's server over plain HTTP on the same port as the game's QoS HTTP
(every player reaches it anyway). `_read_request` reads the headers and the body
(`Content-Length`), `_launcher_request` handles the `/turborivals/...` paths, and everything else
goes to QoS as before:

| Path | Role |
|---|---|
| `GET /turborivals/identify?id=&user=&saves=&src=&name=` | before the game starts: the player's save id, EA App user id and name -> `Lobby.register` (for the sender's address) |
| `POST /turborivals/avatar` | the sender's picture: PNG (launchers) or JPEG (the game), at most 64 KB. Whose it is follows from the sender's ADDRESS (`Lobby.uid_for`), not from a parameter |
| `GET /turborivals/players` | who is logged in (ONLINE NOW): `[{uid, name, local, avatar=<version>}]` |
| `GET /turborivals/avatar/<uid>` | the player's PNG |

An error while handling a launcher request does not end the thread (the same thread answers the
game's QoS).
