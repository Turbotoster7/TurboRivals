# Decision and discovery log

A record of what we tried and what we learned - so we never walk back into a dead end.

---

## 2026-09-06 - phase 0, reconnaissance

### Starting point

The NFS Rivals servers went dark on 7 October 2025. No public project brings them back to life
(checked: GitHub, NFS forums, Steam Discussions). Blaze emulators exist for BF3/BF4, Mass Effect 3,
Mirror's Edge Catalyst, Dead Space 2 and Skate 3 - those are our models.

**The constraint that defines the project:** with the servers dead, nobody can record
server->client traffic any more. We do not "sniff and replay"; we "provoke the client and
reconstruct the replies".

### What went better than planned

The plan treated the binary as a secondary source - in practice it became the main one. The
`.rdata` section holds complete TDF metadata tables: the protocol tag sits in memory right next to
the field name.

The path to it:

1. `dump_strings.py` showed 511 strings containing "Blaze" and the full set of TDF type names
   (`Blaze::GameManager::CreateGameRequest` etc.).
2. Field names (`mBlazeId`) had ~75 pointers each from `.rdata` - so they lived in tables, not in
   code.
3. A dump of the neighbourhood showed records with a 24-byte stride: 8 bytes of metadata, a
   pointer to the name, a tail.
4. Applying BlazeSDK's known tag encoding (4 characters of 6 bits) to metadata bytes 1..3 gave the
   pairs `BID `->`mBlazeId`, `MAIL`->`mEmail`, `PASS`->`mPassword`. The semantic match rules out
   coincidence.
5. `extract_tdf_meta.py` pulled out 2,864 pairs and 1,152 unique tags.

Result: we read captured packets with field names instead of guessing.

### Dead end: static code analysis

An attempt to map TDF classes to their field tables by scanning for `lea r64, [rip+disp32]`
returned 15 hits in 19 MB of code - i.e. nothing.

The reason: **the `.text` section is encrypted**. Entropy 1.000, a perfectly uniform byte
distribution, none of the typical x64 patterns. The same goes for `.data`, `typeinfo` and
`fieldinf`. There is an unusual `ctr` section - probably the protector itself. Both files are
affected (`NFS14.exe` and `NFS14_x86.exe`).

`.rdata` stayed readable, so the metadata work holds.

Conclusions:

- mapping class -> fields needs a memory dump of the process after decryption; postponed,
  because live traffic could give the same more cheaply (later done from memory dumps -
  `tools/dump_image.py`),
- patching the exe (plan B for SSL) is expensive - all the more reason to bet on a stand-in
  certificate, which leaves the binary alone.

### Surprise: NAT can be emulated

The binary has the literal format of the request to the demangler:

```
http://%s:%d/getPeerAddress?myIP=%s&myPort=%d&version=1.0
```

So EA's NAT punch-through is a plain HTTP API. Phase 5 (working without a VPN) is clearly cheaper
than the plan assumed - no need for our own UDP relay, recreating this service is enough.

### Decisions

- **Order of questions**: first whether the client connects at all, then which SSL version, only
  then framing and commands. Each step is cheaper than the one before if the earlier one fails.
- **`hosts` instead of DNS**: simple, reversible, needs no infrastructure. The script keeps its
  entries in a marked block and makes a backup.
- **Redirect only `gosredirector.online.ea.com` at first**. Every extra entry is one more variable
  when diagnosing. (The game turned out to use `gosredirector.ea.com`.)

---

## 2026-09-06 - phase 1, the redirector's SSL handshake

### The probe confirmed the redirector is alive

`ssl_probe.py` against `159.153.51.18:42127` gets a full `ServerHello -> Certificate ->
ServerHelloDone` for both SSLv3 and TLS 1.2. We need not wait for the client to learn the SSL
parameters - the server gives them away. That settles open questions 2 and 3.

### Key point: the certificate is of a weak class

Taking the certificate apart (`strings` + `openssl x509`):

- **md5WithRSAEncryption** signature, **1024-bit** key - OID `1.2.840.113549.1.1.4` in the hex
  dump and a 129-byte signature (`03 81 81 00`),
- issuer: EA's internal **OTG3 Certificate Authority**,
- subject CN: **`gosredirector.ea.com`** (not `...online.`), one certificate for the whole
  environment table,
- valid until 2035-05-02, so still valid by date.

A configuration where old ProtoSSL does not verify the chain up to a trusted CA. **Conclusion for
the strategy: we do not need EA's private key.** Our stand-in server presents its own **stand-in
certificate** with CN `gosredirector.ea.com` - the identity of our server, not an impersonation of
a working service (EA's service has been off since 2025-10-07). The approach does not touch the
encrypted binary. (Section 8 of protocol.md: ProtoSSL does check the signature after all - the OID
bug gets past it.)

### Naming (decision)

We do not write "forged/cloned certificate" - misleading framing. We use **"stand-in
certificate"** / **"stand-in server"**: we run our own server replacing a service that was
switched off, and our own, legally purchased client connects to it. No breaking of protections,
no redistribution of game files.

### Track A - the proxy confirmed the client side

`tcp_proxy.py` between the game and EA (session `120822-003`): **the client connects and completes
a full handshake** (open question 1 - YES). It offers TLS 1.1 in an SSLv3 record, RC4+AES ciphers;
`AES_256_CBC_SHA` gets negotiated. Right after the handshake it sent encrypted `ApplicationData`
(256 B) - the first Blaze packet, which a passive proxy cannot read. Terminator goal: **TLS 1.1,
RSA kx, AES-256-CBC-SHA**.

### What is left

- ~~Read the chosen cipher from `.bin`.~~ Done: `TLS_RSA_WITH_AES_256_CBC_SHA` (RSA kx,
  AES-256-CBC, HMAC-SHA1). With RSA kx a stand-in certificate is enough to decrypt the premaster.
- ~~Check whether the client initiates a connection.~~ Done in Track A: yes.
- Build a **stand-in certificate** (`make_stub_cert.py`) and a TLS-terminating server, then give
  it to the live client (open question 3, the final test) - that yields the first decrypted Blaze
  packet.

---

## 2026-09-06 - phase 1, Track B: TLS terminator built and tested

### Research changed two assumptions

1. **Self-signed is not enough - the OID needs patching.** We assumed old ProtoSSL does not verify
   the signature. Wrong: the parser does a `memcmp` over the hash. The
   [Aim4kill/Bug_OldProtoSSL](https://github.com/Aim4kill/Bug_OldProtoSSL) bug: signature OID =
   `rsaEncryption` -> `default` branch -> `iHashSize = 0` -> `memcmp(...,0)==0` -> verification
   passes. `make_stub_cert.py` patches the DER (both occurrences of the `sha256WithRSA` OID ->
   `rsaEncryption`, length unchanged) and writes `pki/server.der`. Confirmed: `openssl x509 -text`
   shows `Signature Algorithm: rsaEncryption`.
2. **RC4 instead of AES.** The client offered `RC4_128_SHA`; our server picks it. RC4 (no IV or
   padding) reduces record protection to RC4 + HMAC-SHA1. jacobtread/blaze-ssl does the same.
   AES-CBC not needed.

### Implementation decision: pure Python, no `cryptography`

The plan assumed `cryptography` for RSA-decrypt, but it was not in the environment. Instead of
adding a dependency, RSA-decrypt (PKCS#1 v1.5), RC4 and the PRF are pure Python, consistent with
the rest of proto-lab (ssl_probe also builds TLS by hand). The key `(n, d)` extracted once with
`openssl rsa -text`. The terminator reuses `hexdump`/`parse_records` from `tcp_proxy.py`.
(Since 29.09 the certificate is generated with `cryptography` and the key read by our own DER
parser, so the packaged launcher needs no `openssl`.)

### The smoke test passed

Our own test client (a pure-Python mirror of the handshake) against `tls_terminator.py`:
**Finished `verify_data` OK in both directions**, `ApplicationData` decrypted 1:1. The whole
cryptographic path (premaster RSA-decrypt, TLS 1.0/1.1 PRF, key block, RC4, MAC, CCS sequencing)
confirmed without a live client.

### What is left: the one test that cannot be done without the game

Whether the REAL Rivals ProtoSSL accepts the patched certificate and uses this crypto - open
question 3, settled only by giving the certificate to the live client (`hosts` -> `127.0.0.1`,
start the terminator, start the game). Success = a `blaze-first-*.bin` with a readable first Blaze
packet. (It did - see protocol.md section 8.)

---

## 2026-09-10 - QoS: a wrong format hypothesis, fixed by disassembly

### Symptom

The game went through the whole login sequence (redirector -> preAuth with CONF+QOSS -> ping ->
login -> UserSessions notifications -> postAuth) and **by itself** called our ping site over HTTP:
`GET /qos/qos?vers=1&qtyp=1&prpt=3659`. It read the reply in full (130 B, visible in the `recv`
hooks), but **did not send a single UDP probe** - only `Util.ping` afterwards, the screen stuck
on "Connecting".

### What was wrong

The keys `.numprobes`, `.probesize`, `.qosport`, `.requestid`, `.reqsecret` taken from the binary's
strings are real, but we read them as `key=value` pairs in TagField format
(`qos.numprobes=1 qos.probesize=64 ...`). That was a guess from a function name, not from code.

Disassembly settled it: the function taken for `TagFieldFind` (`0xfee910`) is **`XmlFind`** from
DirtySDK's `xmlparse`. The proof is in the code itself: it scans to the `<` character, skips
`<?..?>` and `<!..>`, stops at `</`, and the mask of allowed name terminators is
`0x40008001FFFFFFFF` = `{0x00-0x20, '/', '>'}` - **it has no `=`**, so it matches ELEMENT names,
not assignment keys or attributes. Its companion `0xfee6a0` is `XmlContentGetInteger` (after `<`
it jumps to `>`).

Our reply had not a single `<`, so all three `XmlFind` calls (`"firewall"`, `"firetype"`, `"qos"`)
returned NULL and `_QosApiParseResponse` @`0xfdb070` ended with code `-2`, doing nothing. Hence the
silence on UDP with a correctly read reply.

### Lesson on method

Twice in a row (the `QosConfigInfo` layout taken from BF3, now the QoS reply format) a guess by
analogy cost us. A memory dump with decrypted `.text` + capstone gives the answer in minutes -
**when there is code to read, we do not guess**. The same rule also gave the UserSessions command
numbers from the `getCommandName` jump table (`updateNetworkInfo` = `0x14`), instead of waiting for
the command to show up in the log as "no handler".

### Changes

- `_qos_body` in `tls_terminator.py` now answers with XML for `/qos/qos`, `/qos/firetype`,
  `/qos/firewall`; `Content-Type: text/xml`. A/B flags: `--qos-numprobes`, `--qos-probesize`,
  `--qos-firetype`.
- `hook_origin.js`: a hook on `0xfdb070` prints the reply buffer and the return code
  (`0` / `-1` / `-2`) and the QoS state it read - diagnosis without guesses.
- `_dispatch_blaze`: empty acknowledgements for `0x7802` cmd `0x14` (updateNetworkInfo), `0x08`
  (updateHardwareFlags), `0x1A` (setUserInfoAttribute).
- Format, validation rules, UDP probe layout and the command table: `docs/protocol.md` section 9.

### What this change does not settle

The UDP responder stays a plain echo - the code suggests that is enough (receiving a probe compares
`requestid`/`reqsecret`/`numprobes` read from the packet, and an echo returns them unchanged), but
**it has not been tested live yet**. The meaning of `<firetype>` (NAT type) also stays unknown:
the value goes to `[conn+0x1b0]`, and `== 5` disables the callback, so 5 is an "unknown" sentinel;
by default we send 1.

### Addendum the same day - the UDP probe is not an echo either

With the XML accepted the game **sent UDP probes** (`QosApiParseResponse = 0`, confirmed by the
hook), but sent four identical probes ~1 s apart and repeated `GET /qos/qos` - i.e. it rejected
our replies. The cause is in the same receiver: `0xfdb777` requires **`len >= 0x1e` (30 B)**, while
we echoed the 20 B probe. Further on, the code reads from the reply the client's external IP
(`+0x14`) and port (`+0x18`) and a tail length (`+0x1a`) - fields an echo physically does not have.

Correcting the earlier entry: "a byte-for-byte echo meets every condition" held only for the
bandwidth path (`ntohl(+0x04) >= 2`), where the code compares requestid/reqsecret and counts bytes.
The latency path, which the game uses with `qtyp=0`, needs a built reply. The lesson to keep:
**before I call an echo sufficient, read the WHOLE receive path, not just the place where the
fields I know get compared.**

---

## 2026-09-12 - the blocker moved to the EA activation gate (ActivationUI)

### Symptom

Until 2026-09-11 the game went through the whole login chain to our Blaze (redirector -> preAuth
-> login with a token from the EA App -> notifications -> postAuth -> QoS), and the only open
problem was a disconnect + access violation right after our postAuth reply. In the 2026-09-12
13:24 run the game stopped reaching the menu at all: after "Play" in Steam, `EASteamLauncher` ->
`Core/ActivationUI.exe` starts (the EA activation gate, Qt, using
`Core/Activation.dll`/`Activation64.dll`) and shows a login/activation window. `NFS14.exe` starts
(Frida catches the process, the token hook `0xec3c80` goes in), but it waits behind the gate - the
terminator sees no Blaze connection.

### Cause (from an ActivationUI dump)

A memory dump of the idle activation window contains the launch environment block that the EA
launcher passes to the game - with `EAAuthCode=NeedsAFreshAuthCode` in it. The EA App did not get a
fresh auth code (the `accounts.ea.com` service is alive, unlike `gos.ea.com`), so ActivationUI
cannot verify the entitlement and falls back to the login window. This is BEFORE the whole Origin
SDK / LSX, so the token injection we built (a hook in NFS14.exe) cannot work until the game starts.
`hosts` only redirects `gosredirector.ea.com`, so it is not us blocking accounts.ea.com.

### Conclusion for further work - the game itself does NOT validate the entitlement

Of the whole EA* variable block, `NFS14.exe` contains AS A STRING only `EALaunchOfflineMode`
(`tools/xref.py --str`, no `lea` references - used through a pointer/table). The rest
(`EALaunchUserAuthToken`, `EALicenseToken`, `EAAuthCode`, `EASecureLaunchTokenTemp`) is consumed by
the LAUNCHER, not the game. So ActivationUI validates the entitlement, not NFS14.exe. Hence
Track B: start `NFS14.exe` directly with a reconstructed EA* environment (with the EA App running,
for LSX 3216), skipping ActivationUI - the game should go straight to LSX, where the `0xec3c80` hook
swaps the token. Prototype: `proto-lab/launch_direct.py` (+ the template
`ea_launch_env.example.txt`; `ea_launch_env.txt` with the secrets is gitignored).

### Changes in this session

- `proto-lab/frida_run.py`: default `--settle` = 8 s. In the 13:24 run several hooks failed with
  "unable to intercept function" (`0xebd140`, `0xebd800`, `0xf66220`, `0xf8a0d0`) - the game's
  `.text` is encrypted and had not been unpacked yet when Frida attached right after the process
  started. The `replace` on `0xec3c80` (token) and `0xec1880` (IsCoreConnected) loaded anyway.
- `proto-lab/launch_direct.py`: the new Track B launcher (described above).

### Secrets - a deliberate decision

The ActivationUI dumps contain a LIVE EA account JWT (`EALaunchUserAuthToken`) and session tokens.
The repo is meant to be public, so `docs/` gets the architecture and the variable NAMES, while the
secret values are redacted (placeholder `<...>`). Both dump files deleted after the findings were
extracted.

---

## 2026-09-13 - Blaze dropped: time values in CONF without units

### Symptom

Ever since CONF in preAuth became non-empty (2026-09-09), the client dropped the Blaze connection
with error `0x800e0000` within seconds: in run-13 right after postAuth, in run-14 (three tries)
already after preAuth, before it could send login. The state hook showed `[conn+0x2fc]=0` every
time, i.e. the idle threshold. On 2026-09-07, with an empty CONF, the same connection lived 50
minutes on pings alone.

### Cause (disassembly of a dump)

The drop condition in `0xf3a580` is "silence > `[conn+0x2fc]` ms". Only the constructor (40000) and
the config reader `0xf419b0` (`value/1000`) write that field. The reader takes the value through the
getter `0xf39dc0`, which goes through the TimeValue parser `0xf79d60`, which requires a unit
(`90s`, `15000ms`, `1m`). We were sending `"90"`: the parser returns false and stores nothing, the
getter ignores that result and reports "found", so the reader stores 0. The same applied to
`defaultRequestTimeout="30"` (RPC timeout 0 ms). The format is described in `protocol.md`,
section 11.

### False leads on the way

- "A keepalive from the server" (2026-09-12): the client was not waiting for traffic, it had a 0 ms
  threshold, so no ping would have made it.
- "The client does not find the key, the map format is wrong": the map is fine and the key is
  found. The VALUE format was wrong. Our encoder/decoder round trip cannot catch that, because it
  only checks our own format, not the semantics at the consumer.

### Changes

- `blaze.DEFAULT_CLIENT_CONFIG`: `connIdleTimeout=90s`, `defaultRequestTimeout=30s`,
  `pingPeriod=15s`.
- `hook_origin.js`: hooks on the getter `0xf39dc0` (key, result in us), the parser `0xf79d60`
  (text -> OK/ERROR) and a snapshot of the connection fields in `0xf3a580` (logs changes only).

### Open

The hook on entry to `0xf419b0` printed nothing in run-14, although it is the only write of zero to
`[conn+0x2fc]` besides the constructor. The getter and parser hooks will show directly whether and
when the reader runs.

The lesson to keep: **values sent to the client are checked at the consumer (the parser in the
code), not only by a round trip through our encoder.**

### Result - run-15 (12:53), fix CONFIRMED

- The parser accepted the values: `'15s' -> 15000000 us`, `'30s' -> 30000000 us`,
  `'90s' -> 90000000 us`. The getter reads the keys in the order pingPeriod ->
  defaultRequestTimeout -> connIdleTimeout (exactly as `0xf419b0`), and the connection snapshot
  shows `idle[+0x2fc]=90000ms req[+0x1c4]=30000ms`.
- The second Blaze connection went preAuth -> ping -> login 1/152 -> notifications -> postAuth 9/8,
  and the client **decoded our postAuth reply for the first time** (`PostAuthResponse` `0xf211e0`)
  and did NOT close the connection. Then pings 9/2 about every 15 s, the connection ESTABLISHED,
  zero exceptions, no crash entry in the Event Log.
- The first connection in this run dropped anyway (`0x800e0000`, `threshold=90000`). The game had
  not been restarted after run-14, and the snapshot at the start showed `idle=0ms` - the connection
  object held the old zero threshold until the new config arrived. Most likely a leftover; to be
  checked on a fresh process.
- The hook on entry to `0xf419b0` again printed nothing, although the reader clearly works (the key
  sequence from the getter). Cause unknown, no longer relevant to the diagnosis.
- On a fresh game process (13:00) the FIRST connection already passes login and postAuth and lives
  (idle 40000 -> 90000 ms after preAuth). The first try's drop above was a leftover from run-14.

### Crash at 12:59:58 - that was Frida, not the game

The Event Log points at `frida-agent.dll`, code `0xc0000409` (fail-fast 7 = `abort()`), offset
`0xfc891d`. The death at 01:58:36 (the run-12 process) has an identical signature. The WER minidumps
(`%LOCALAPPDATA%\CrashDumps\NFS14.exe.<PID>.dmp`) show Frida's agent thread aborting itself: only
`frida-agent.dll` and a thread start on the stack, zero game frames, and no original exception
record (`0xc0000005` etc.) on any stack. Both deaths came while restarting `frida_run.py` on a
running game that had Frida attached more than once. A correlation, not proof.

Consequences:
- The per-frame hook `0xf3a580` (connection snapshot) is off by default (`CONN_SNAPSHOT=false`) -
  it did its job, and this lowers the risk when detaching.
- A run ends by **closing the game first**, then Frida and the terminator.
- On every crash check the module in the Event Log first (id 1000): `frida-agent.dll` is a tool
  artefact, `NFS14.exe`/`unknown` is a real game error.

---

## 2026-09-13 (afternoon) - "Logging in": the game got a user with ID=0

### Symptom

After the config fix (run-15..19) login and postAuth passed and the Blaze session lived, but the
screen stayed on "Logging in", and after postAuth the game sent only pings.

### How we took it apart

- A watcher on the game's online manager state (`0xa1bb00`, state in `[obj+0x20]`) showed
  2 -> 5 -> 6 and never 9.
- Event hooks showed the game's online object is `BlazeStateEventHandler` (vtable `0x15cc938`:
  dtor, onConnected -> 6, onDisconnected, onAuthenticated -> 9, onDeAuthenticated,
  onIncompatibleServerVersion). State 6 is "connected" (onConnected after preAuth), and
  onAuthenticated never came.
- The UserAdded notification (`0x7802/2`) has the fields `DATA mExtendedData` and `USER mUserInfo`.
  The binary has a UserIdentification class (`@0x1416d78c0`: AID ALOC EXBB EXID ID NAME ORIG PIDI).
  We were sending UserSessionLoginInfo tags in USER (BUID DSNM KEY ...), of which only ALOC matched -
  the game created a local user with `ID=0`.

### Change and result (run-20)

`USER` = UserIdentification with `ID` = the BlazeId from login. Result: onAuthenticated, the game's
online state 9 -> 10, ByteVault initialisation and a series of new RPCs (userSettingsLoad, getLists,
Stats, component 2050).

### False leads on the way (so we do not return to them)

- The empty UserAuthenticated notification (cmd 8) - we filled it in per the class in the binary
  (`@0x141a2f160`), but on its own it changed nothing.
- `0xf40570` is `Game::setGameState` (GameManager; the values 1, 4, 7, 8, 130, 131 are the GameState
  enum), not the login state. The dispatcher thunk slots (`0xf6c5f0`, `0xefde70`) are generic - the
  slot number says nothing about which listener interface it is.
- ByteVault and the `bytevault*` keys - they did not block login (read only after state 9).

### A bug found on the way - maps must be sorted

The config lookup (`0xf39cb0`) searches for the key by binary search in a sorted vector. The
`bytevault*` keys appended at the end of CONF were therefore not found, and ByteVault went to the
default host `bytevault.test.gameservices.ea.com`. `blaze.f_map_str` now sorts the keys.

### Tool changes

- `tls_terminator.py`: an RPC without a handler gets an empty acknowledgement by default (err=0),
  so the game's request completes; `--no-ack-unknown` turns that off. A/B flags:
  `--legacy-user-added`, `--empty-user-auth`, `--no-bytevault`.
- `hook_origin.js`: the game's online state watcher, listener event hooks, the config lookup and
  getter, DNS through `gethostbyname`, ByteVault init.

## 2026-09-13 (evening) - run-23: driving on our server

### Result

After the reply to `GameManager.createGame` (a reply with `GID` + `NotifyGameSetup` with the player
as host) the game went on by itself: `updateMeshConnection` -> `finalizeGameCreation` ->
`advanceGameState` PRE_GAME (130) -> IN_GAME (131). Driving in the open world, no crash, no Frida.
ByteVault (REST over HTTPS on the Blaze port) got replies and accepted them. Switching games along
the way (`leaveGameByGroup` -> new `createGame` -> `removePlayer` of the old game) also worked,
although we answer those commands with a bare acknowledgement.

### What arrived while driving

- 429 `GameReporting` reports (component 28, cmd 2) in about 2 minutes: Collectables,
  DistanceDriven*, Racer_Completed_Objective_*, CarCustomization, LicensesPart1/2. That is the
  player's progress state - a candidate for saving on the server side.
- `Util.filterForProfanity`, `NFS.getInGameSpeedWalls`, `UserSessions.lookupUsers`,
  `Authentication.listUserEntitlements2`, `NFS.getSpecialGuestInfo`,
  `NFS.getOverwatchStatsConfig`, `NFS.getAutologPlaylist`, `NFS.getInGameRecommendations`.
- The game uses two identifiers: the BlazeId from login and a second id (the persona) in
  `listUserEntitlements2`, `lookupUsers` and ByteVault's `X-USER-ID` header. Where it takes the
  second one from - not established. (Settled on 2026-09-30: the EA App's LSX `GetProfile`; it also
  names the career save the game loads - protocol.md section 13.)

### Command names from the binary

Emulating 13 `getCommandName` functions on the memory dump gives complete number -> name tables
(Authentication, GameManager, Stats, Util, AssociationLists, NFS 2050, UserSessions, ByteVault,
Messaging, Playgroups and notifications). They are in `blaze._RPC_TABLES` and reach the log through
`blaze.rpc_name()`. Component 28 has no name table; the GameReporting name comes from the layout of
the request class `{FNSH PRVT RPRT}` (`@0x141a32ad0`).

### Tool changes

- `tls_terminator.py`: command names in the log; known RPCs without a handler without a hex dump;
  reports 28 on one line + an acknowledgement (raw frames stay in the capture);
  `filterForProfanity` returns the texts with result `FILTER_RESULT_PASSED` (enum from `.rdata`, the
  client sends `UNPROCESSED` = 2); the HTTP session ends after `Connection: Close`.
- Verified offline on run-23 frames, not live.

## 2026-09-13 (evening) - saving player progress from GameReporting reports

### Decision

After run-24 (login, world, career change - everything works) we chose progress saving before
multiplayer, because it can be built and checked alone.

### What is in the reports

The decoder got the `variable` type (presence byte, class id, fields). All 473 reports from run-24
break down the same way: `RPRT.GTYP` = category + 8 hex characters, and in `RPRT.GAME` a map
`player -> {ENTI, STAI, STAF, STAS}` (object id and int/float/string stat maps).

Reports carry **state**, not deltas - successive `PlayerStats` reports repeat the same numbers (cars
bought, gold medals, credits, ranks, shotlist progress). So we save the last value of each stat,
plus a full log of the reports next to it, so the state can be rebuilt if this model proves wrong.

The category names (except `MetaData` and `VehicleStatisticsData`) do not appear in the code - they
come from game data. The hex suffixes are most likely hashes (`0xaaa040`: sprintf of the name + a
djb2a hash).

### Where and how

`proto-lab/player_store.py`, data in `%LOCALAPPDATA%\TurboRivals\data` - outside the repo and
outside OneDrive (replacing a file several times a second in a synced folder risks a file lock).
A parsing or write error does not hold up the game: the report acknowledgement goes out before the
write.

### Open

Reading back: the game asks Stats only for the `MetaData` and `PlayerStats` groups. Before we start
sending values back, we must establish from the code how the client maps `EntityStats.STAT` values
to names - no guessing. The speed wall ids in `getInGameSpeedWalls` match `ENTI` in the reports, so
one's own results can be served from the saved state.

### Fix after run-25: the data folder

Saving worked (465/465), but there were no files under `%LOCALAPPDATA%\TurboRivals`. Python from the
Microsoft Store (`WindowsApps\python.exe`) virtualises writes to AppData\Local and redirects them to
`Packages\PythonSoftwareFoundation.Python.*\LocalCache`. The default folder is now
`~\TurboRivals\data` (the home folder is not virtualised), and the terminator prints it at start-up.

## 2026-09-13 (evening) - speed walls from saved results

### How we established the layout

Automatically binding field tables to class names failed (no pointers in the data, no `lea` to the
names in the same functions). What worked were the `Class::mField` strings in the binary, e.g.
`InGameSpeedWallResponseRow::mStatsFlt` - the field names point at a single table:

- `InGameSpeedWallResponseRow` = `{BLUS mBlazeUser, STAF mStatsFlt, STAI mStatsInt, STAS mStatsStr}`
- `InGameSpeedWallResponseSpeedWall` = `{ROWS mSpeedWall, SWID mSpeedWallId}`
- `{RILI, SPWA}`, earlier taken for the speed wall reply, is `InGameRecommendationsResponse`.

A speed wall row has exactly the same maps as a player's entry in a GameReporting report, and the
speed wall id is the `ENTI` from the report: the server sent back the saved stats of the object
(speed camera - `speed`, speed zone - `AverageSpeed`).

### Uncertainty we work around

`InGameSpeedWallResponse::mSpeedwalls` fits two tables: a list under the `ROWS` tag or `SPWA`. We
send both fields with the same list - the client's decoder skips tags unknown to its class.

### Changes

`blaze.build_in_game_speed_walls_response`, int/float maps, `PlayerStore.rows_for_entity`, the
2050/20 handler in the terminator (`--no-speed-walls` goes back to a bare acknowledgement). Checked
offline on 46 requests from run-25: 9 speed walls get rows, values consistent with the saved state.

## 2026-09-13 (evening) - public game: matchmaking creates a game

### Symptom (run-26)

"Search for session" in the game ended in pings only. The game sent
`GameManager.leaveGameByGroup`, then `GameManager.startMatchmaking` with `MODE=3` (find or create),
a session time of 6000 ms and the rule `gameMembershipRule = Public`. We answered both with an empty
acknowledgement. The server delivers the matchmaking result as a notification, so the game waited
forever.

### What we took from the binary

- `StartMatchmakingRequest` (the `StartMatchmakingRequest::m...` strings) - the request layout.
- The `MatchmakingResult` enum from a `{name, value}` table: `SUCCESS_CREATED_GAME=0` ...
  `SESSION_TIMED_OUT=3` ... `SESSION_ERROR_GAME_SETUP_FAILED=6`.
- `MatchmakingSetupContext {FIT MAXF MSID RSLT USID}` as variant 3 of the game setup reason union
  (the order of member tables; variant 0 has worked since run-23 with `createGame`).
- `NotifyMatchmakingFailed {MAXF MSID RSLT USID}`.

### Decision

There are no other players on the server, so we do what the server in "find or create" mode does
when there are no games: create a new game with the player as host. Reply `{MSID}`, then
`NotifyGameSetup` with the matchmaking context and result `SUCCESS_CREATED_GAME`. The game
parameters are copied from the request, and the `Public` rule is stored as a game attribute (the
attribute name taken from `createGame`), so a second player could find the game later. `--mm-fail`
sends a `SESSION_TIMED_OUT` failure instead - for comparison, in case the game did not accept the
created game.

### Open

A real "find" (joining other players' games) needs a shared game list across connections - that is
multiplayer. The old game after `leaveGameByGroup` gets no `NotifyPlayerRemoved`/`NotifyGameRemoved`.

### Result (run-27)

The public game works: the game sent `startMatchmaking` right after entering, accepted the created
game and went to IN_GAME (with a matchmaking game the client skips `updateMeshConnection` and
`finalizeGameCreation`). Speed walls with saved results (speed camera, zone, jump) also accepted.
At the end of the run the game crashed (execution from a stack address) - the server log cut off
with the connection open, so most likely the same game problem on losing the server connection,
just with a different signature; the WER minidump has no NFS14 frames, so the dump alone cannot
confirm it. The user later confirmed they had closed the terminal before the game.

## 2026-09-13 (evening) - a server for several players

### Why now

Single-player works end to end, and the user is testing with a friend on the same network. The
server assumed one player: a fixed identity, games as counters without a player list,
notifications only to the player's own connection, and `127.0.0.1` as the external address from QoS.

### Decisions

- **The registry in a separate module** (`proto-lab/lobby.py`): sessions and games under one lock,
  and each session with its own send lock. `Wire.send_record` changes the RC4 state and the MAC
  counter, and player A's thread sends notifications to player B - without a lock the records would
  interleave.
- **Identity by IP address.** The login carries only the Origin token, which we do not verify and
  from which we cannot read the full id. On a LAN the address tells machines apart; the local player
  keeps the BlazeId from the EA App under which its progress is saved. The server learns the second
  player's EA nickname from the name of the game the client creates, and remembers it. (Both
  replaced on 2026-09-30: identity by career save id, names from the player's launcher.)
- **Matchmaking first finds, then creates** - like the server in `MODE=3`.
- **The local player's external address = the machine's network address** (`--public-ip`, detected
  by default). Without it the host reports `127.0.0.1` and the friend would connect to himself. The
  game topology is direct connections; EA's relay does not exist.
- **The leave notification only for the remaining players.** In run-23..27 the client left a game
  without that notification and was fine; sending it about its own leaving risks tearing the game
  down twice.
- **No host migration:** when the host leaves (also when switching career), the game disappears and
  the others get `NotifyGameRemoved`. (Host migration came later and works - 2026-09-30.)
- **DLC licences skipped:** the Steam Complete Edition has the DLC locally, and the binary has no
  licence tags that could be sent back.

### Verification

Offline on run-27 frames: two simulated sessions (local and LAN) - creating a public game, a second
player joining with a two-player roster, the join completing after `updateMeshConnection`, leaving,
the host disconnecting, solo `createGame` unchanged, per-client QoS addresses. Regression of
progress saving and speed walls. The live test with a second machine in progress.

## 2026-09-16 - multiplayer live: run-38 to run-40

### Run-38 (20:51) - the first successful join

For the first time a second player got into the first one's game. The joiner's `startMatchmaking`
hit `find_public_game`, the mesh came up both ways (`STAT=2`), `addAdminPlayer` went out, and the
host's UI showed the friend's icon "in the garage". Before (run-36/37) the joiner's client did not
matchmake at all - it sent `resetDedicatedServer` (4/25), which had no handler.

The session fell apart on the move from the garage to the world: the client sent a second
`startMatchmaking`, got a NEW game, and the `removePlayer` from the old one came a frame later. The
effect: two games instead of one and two lonely players.

### Run-39 (21:21) - roles swapped and the cause found

The key change of method: **Frida on the JOINER's machine** (until then it ran on the host, which
lost nothing). Only that showed the mechanism:

```
19:19:52.711  [mm-status] edx=2  SUCCESS_JOINED_EXISTING_GAME, game object 0xd3ab4680
19:19:59.542  [game-lost] rdx=0xd3ab4680 tracked=0xd3ab4680 r8=0x80
19:19:59.610  [mm-retry] counter=1
19:20:01.210  [mm-status] edx=0  -> its own new game
```

**6.83 s** from joining to the destruction of the game object on the client side. In that whole
window the joiner sent 11 requests - it did not poll, did not retry, it waited. That rules out a
missing REPLY to an RPC. The repeated matchmaking and leaving the game are the EFFECT of losing the
object, not the cause.

A dead end on the way: `--mm-delay` (deferring the matchmaking decision so that `removePlayer` could
arrive). It could not work - the client sends `removePlayer` only AFTER it gets the matchmaking
result. The code stays with the default `0`; it will be useful if the client ever leaves a game
before searching. On the way a `cancelMatchmaking` (4/14) handler was added, previously unhandled.

### Cause

The server set the joiner to `ACTIVE_CONNECTED` only in its own registry and sent
`NotifyPlayerJoinCompleted` (4/30). These are **two different notifications**: 30 says "joining
complete", while the player's state travels in `NotifyGamePlayerStateChange` (4/116), which we had
never sent. The player object on the joiner's side stayed `ACTIVE_CONNECTING`, and a timeout checked
after the world loaded deleted the game.

### What we took from the binary

`NotifyGamePlayerStateChange` @0x141a30660 `{GID mGameId, PID mPlayerId, STAT mPlayerState}` - the
class isolated from `tdf_members.json` between `{GID, PID}` and `{GID, PID, ROLE, SLOT}`. The classes
lie in the same order as the notification numbers (116 GamePlayerStateChange,
117 GamePlayerTeamRoleSlotChange), which completes the identification. The `meta[0]` -> TDF type
mapping derived from `build_in_game_speed_walls_response`, verified on the client earlier:
4/21/22/23/24 -> int, 5 -> string, 2 -> list, 1 -> map, 10 -> struct.

### Decision

`Lobby.mesh()` sends to every player of the game, when a player moves to `ACTIVE_CONNECTED`, **116
before 30**. `--no-player-state-notify` goes back to the behaviour up to and including run-39 (A/B).

### Result (run-40, 21:52)

| | run-39 | run-40 |
|---|---|---|
| time in game | 6.83 s | **14 min 42 s** |
| `[game-lost]` | 2x | **0** |
| `[mm-retry]` | counter=1 | no retry |
| games in the registry | 2 (fell apart) | **1** |

`cmd=116` went to both players, nobody left, zero tracebacks, the disconnect at the end by the user.
Multiplayer on a LAN works.

### Open

- **Not tested live:** the host leaving mid-session (the `remove_player` fix from 15.09: only
  `NotifyGameRemoved`, no `NotifyPlayerRemoved`), 3+ players, the timer path `--mm-delay > 0`.
  (The first two since done - host migration and 3-6 players, 2026-09-30.)
- **RPCs without a handler seen only in longer sessions:** `UserSessions.lookupUsers` (14x),
  `NFS.getInGameRecommendations` (4x), `NFS.getAutologPlaylist` (4x). Still without a handler:
  `getSpecialGuestInfo` (42x, reply layout recovered @0x141a2c0d0 - `BLIS mSpecialGuests`,
  `STAI mSpecialGuestRealNames`, `SPGT`, `SPGN`, `SPLA`), `getOverwatchStatsConfig`, `getAccount`,
  `createWalUserSession`.
- **Not established:** the meaning of `r8` in `[game-lost]` (`0x80` on the first loss, `0x40` on the
  second) - for disassembly of `0xa1b770`, should a similar symptom come back. TDF type `0x70`
  (`blaze.py:1423`) still unknown to the decoder.

## 2026-09-30 - a second machine, guest career saves, names, pictures, host migration

A day of live tests: desktop (host) and laptop (guest), over a LAN and over Radmin VPN, later a
third player. Launcher versions 1.0.2 to 1.0.6 came out of it.

### Joining from another PC: a stale line in `hosts` (1.0.2)

**Symptom.** Joining the other machine failed in both directions, over LAN and Radmin alike. The
host's log showed nothing about the join, the guest's game said it could not connect. Yet the
guest's launcher DID reach the host: its `identify` request on TCP 17502 appeared in the host's log.

**Cause.** On the desktop, `127.0.0.1 gosredirector.ea.com` sat in `hosts` OUTSIDE the launcher's
block - left over from the manual step in the old readme (`Add-Content` appended a line). Windows
returns every matching line in file order, and the game takes the first, so it connected to itself.
`hosts_status()` read only the inside of the block and showed green.

**Decision.** `hosts_switch.strip_redirects` removes every line mapping the redirector names outside
the block too (backup first), for both `on` and `off`, in the launcher and on the console, and the
uninstaller's `--hosts-off`. The HOSTS row turns red on such a line. *REDIRECT AND PLAY* resolves the
name the way the game does (`getaddrinfo`) and refuses to start the game when it does not point at
the host. The readme's manual step removes old lines first. The `identify` error now tells a refusal
(the server is not running) from a timeout (the machines do not see each other).

**Result.** The laptop joined the desktop.

**Lesson.** The launcher reaching the host proves nothing about the game: the launcher goes by IP,
the game by name.

### A guest's progress: the save the game loads (1.0.3, 1.0.4)

**Symptom.** The guest's custom paint job was gone after rejoining. The guest had logged in as
`1004043460810` - its EA App user id, which `ea_identity` fell back to because it found no save with
the account's suffix other than that id.

**First fix (1.0.3).** The EA App writes the LSX `GetProfile` reply into its own log:
`<GetProfileResponse UserId=".." PersonaId=".." Persona="nick">`. On the desktop the PersonaId was
`1006431274704` - exactly the save confirmed that morning as the one the game loads.

**Not enough.** On the laptop EVERY such entry was masked (`UserId="####" PersonaId="####"`), so
1.0.3 still guessed. The laptop's save folder (the user ran a read-only command and sent the output)
held `1802434674.sav`: 10 digits, no `60810` suffix, written on 15.09 while the game ran without our
login, i.e. under its own PersonaId. The rest were our synthetic ids and the user-id file. The
captures confirm the game never sends the PersonaId to Blaze (not as text, heat2 or BE32), so the
launcher is the only source.

**Decision (1.0.4).** `ea_identity.resolve`: the unmasked log entry -> a save with the account's
suffix -> **the only EA save on the machine** (not synthetic, not a user id, not in another local
account's family) -> a guess, shown orange in the launcher. The server accepts a reported id when
the EA App user id reported with it carries the token's suffix (older accounts do not share it),
keeps that `user` in the entry so a later login without the launcher still finds the player, and
merges the stale `ea:<user id>` entry into the right one (`Lobby._settle_user`, name and results
move over). `learn_persona` now updates an entry instead of replacing it (it would drop `user`).

**Result.** The laptop logs in as `1802434674` and a paint change stuck. The first cyan paint job
was lost: it went to `1004043460810.sav`, a later session overwrote that file, and the only backup
predates it.

**Open.** Several EA accounts that played Rivals on one PC, or Rivals never played there -> orange.
For the second case, playing once without TurboRivals most likely creates the persona's save (one
data point: the laptop's 15.09 file).

### Names from the player's own launcher

**Symptom.** The host's list mapped `test2` to `26.213.228.176`, but the laptop connected from
`26.48.21.54`, so it became `Player_54`.

**Why the server cannot learn names from the game.** `GNAM` in `createGame`/`startMatchmaking` only
echoes the `DSNM` from our login - the old "learn the name from GNAM" never learned anything.

**Decision.** *YOUR NAME* in *JOIN A SESSION*, prefilled with the EA nickname (the `Persona` in the
EA App's log is never masked), sent with `identify`. Order: the player's own name > the host's list
> stored > `Player_<octet>`. Stored under `ea:<id>`, so it survives a new address and a restart.
Names are folded to printable ASCII, at most 32 characters. An offline test caught that a character
outside the console codepage raised in the server's `print()` (and the thread handling it also
answers the game's QoS). The server's stdout is now UTF-8 with replacement: `app.py --run-server`
reconfigures it, and `PYTHONIOENCODING` covers a server run from source.

### Pictures and ONLINE NOW (1.0.5)

**Decision.** A launcher channel on TCP 17502, which every player reaches anyway: `POST
/turborivals/avatar` (whose picture follows from the SENDER's address, `Lobby.uid_for`, so nobody
can replace someone else's), `GET /turborivals/players`, `GET /turborivals/avatar/<uid>`. The UI
crops and scales the photo in a canvas, so no PIL is needed. The picker sits next to *YOUR NAME*,
because the header is a pywebview drag region (`DRAG_REGION_DIRECT_TARGET_ONLY=False`) and a click
there starts a window drag. The picture lives in `%LOCALAPPDATA%\TurboRivals`, because `DATA_DIR`
is the repository itself when run from source. The offline test caught a name clash:
`Lobby.roster(g)` already existed, so the new method is `online()`.

### Profile pictures in the game (1.0.6)

**Symptom.** The user expected the pictures in the game (they were launcher-only by design).

**Found.** The old logs show the game asking our ByteVault for
`GET /1.0/contexts/nfs-rivals-common/categories/Pictures/records/<uid>` for each player it shows
(37 times in log-29, 28 in log-32) and getting `{}`. The binary links libjpeg. The record classes
are known, but not the JSON keys, so this was set up as a research stage: every write from the game
is kept, and the launcher's JPEG is served in a switchable shape (`--bytevault-pictures
raw|json|off`).

**Result.** It worked on the first try with `raw`: the bare JPEG bytes (256x256, 8,205 B,
`Content-Type: image/jpeg`), one GET per player, and the picture showed in the game. A solo test was
enough, because the game also asks for its own player's picture (log-66, 16.09).

**Open.** Other players' pictures in a shared session (the same path); the upload format of a
picture set in the game itself.

### Host migration and 3-6 players

Tested live by the user: host migration works, and sessions of 3 to 6 players work. That closes the
first two "Open" items of 2026-09-16. Roadmap phase 4 is done. The migration mechanics are in
protocol.md section 12.

### Tooling notes

- `build.ps1` under Windows PowerShell 5.1: PyInstaller's deprecation warning on stderr becomes a
  terminating error under `$ErrorActionPreference = 'Stop'` once the output is redirected. Run
  `powershell -File build.ps1` from bash, or do not redirect stderr.
- The launcher keeps the server log only in its window. For a test that needs the log, run the
  server from the repo with the same arguments and redirect it to a file.

## 2026-10-01 - launcher 1.1: a new window, and what testing it turned up

A rework of the launcher: a new interface in three steps (prepare this PC, the session, play), the
checks moved off the one blocking call, and tests that drive the real server. The full list of what
the review of 1.0.6 found is in [launcher.md](launcher.md); the server-side findings are here.

### A taken port gave half a server

**Symptom.** With TCP 17502 held by another program, the server printed its banner, then nothing:
no `listening on TCP 0.0.0.0:17502 (QoS HTTP)` and no error. The launcher said "server up"; guests'
`identify`, pictures and ONLINE NOW failed, and so did the game's QoS HTTP.

**Cause.** `_bind_exclusive` called `sys.exit()` on a failed bind. Only the redirector binds on the
main thread; in a listener thread `SystemExit` ends that thread and `threading` swallows it.

**Decision.** Write the message and end the process (`os._exit(1)`). The launcher checks the server's
ports before starting it - the same exclusive bind - and names the program in the way (`netstat
-ano` + `tasklist`), telling a port still in TIME_WAIT after the last session apart from another
program. Outside Windows the TCP listeners set `SO_REUSEADDR` (there it only allows a restart over
TIME_WAIT); a quick restart used to fail on Linux.

**Result.** Reproduced and fixed on Linux and on a Windows CI runner (`test_port_taken.py`).

### Lines from different threads ran together

**Symptom.** `listening on TCP 0.0.0.0:17502 (QoS HTTP)[identity] local player: ...`, with the
line ends arriving later as blank lines.

**Cause.** `print()` writes the text and the line end in two writes, so two threads interleave.

**Decision.** `main()` installs a `print` that writes each line once, under a lock; every module
the server prints from goes through it. The launcher reads the log line by line (levels, the
hints), so a glued line was not just ugly.

### The silent failed join, said out loud

The most common failed join - the EA App not running on that machine, so the game stops after
`Util.preAuth`/`Util.ping` without `Authentication.originLogin` - used to need someone reading the
log. A Blaze connection that ends that way now leaves a `[hint]` line naming the address, and the
launcher shows it under *Session events* and as a toast.

### How the launcher is tested now

- `tests/fake_game.py` stands in for the game's Blaze client: the TLS 1.0 handshake with RC4-SHA and
  RSA key exchange, built from `tls_terminator`'s own primitives, and Fire2 requests over it. With it
  the real server is driven through preAuth and login without the game - from `127.0.0.2` and up,
  which the server treats as other players.
- `launcher/dev/preview.py` serves the interface with a stand-in backend for working on it in a
  browser; the real launcher also runs on Linux with pywebview's GTK backend, which is how the
  host and join flows were driven end to end (with `/etc/hosts`, so the DNS check is real).
- GitHub Actions runs the tests on `windows-latest` too: the job object, `tasklist`, `ipconfig`,
  `netsh` and `netstat` are checked on a real Windows.

### Tooling notes

- The launcher now keeps every server run in `%LOCALAPPDATA%\TurboRivals\logs` (the newest 10), so
  the note above about running the server by hand to keep its log no longer applies.

## 2026-10-02 - launcher 1.1, second pass: a calm window, measured, and a bug hunt

### The look

**Why.** The first 1.1 window kept 1.0.6's HUD style - cyan on navy, glow, gradient buttons, capitals,
skewed shapes. It read as a game overlay rather than a tool you set up once and leave running, and
the request was a window "as modern as you would expect".

**Decision.** Built like a current desktop app: a title bar of its own, a sidebar (*Host a session*,
*Join a session*, *Server log*, *Settings*, *Report a problem*), a page of cards next to it. Neutral
dark surfaces with hairline borders, one blue accent for what can be done, green/amber/red only for
state; Segoe UI Variable on Windows, Inter (bundled) elsewhere; sentence case. The log and the
settings got pages of their own. Nothing moves on its own except a spinner while something is
pending. [launcher.md](launcher.md) describes the layout; the PR has before/after pictures, from the
preview and from the installed build on a Windows runner.

### Measured, not guessed

Every change below came with a number before and after (the tables are in
[launcher.md](launcher.md#measured)). Two of them were on Windows only, so CI now builds the
installer, installs it, and times the window there (`tests/smoke_build.py`, `app.py --self-test`):

- **The window came out 16x39 px short** (1084x641 for 1100x680; 1.0.6 too). pywebview sizes a
  frameless form while it still has its frame and then removes the frame, keeping the client area.
  The size is set again on `before_show`.
- **pywebview's private mode** made a throw-away WebView2 profile in `%TEMP%` on every start, and on
  closing waited for the browser process and deleted it; the page came through pywebview's own HTTP
  server. The profile now stays in `%LOCALAPPDATA%\TurboRivals\webview` and the page is a file URL
  (outside private mode that server would sit on the fixed port 42001). Page loaded 0.64 -> 0.26 s,
  window drawn 2.33 -> 2.02 s.
- **Closing** still takes about 2.1 s until the process is gone - but the window is gone after
  0.12 s, and the rest is the same with `TerminateProcess` instead of `os._exit`: Windows tearing the
  process down, not code of the launcher (likely WebView2's windows, which belong to its browser
  process). Left as it is.
- **10 MB for one file.** `cryptography` (9.4 MB of native code) was in the build only to make the
  certificate, once per machine. `make_stub_cert.py` now builds keys, DER and signatures in plain
  Python (129 ms); `tests/test_stub_cert.py` builds the certificate the old way too, from the same
  keys, time and serials, and the bytes are the same - which matters, because ProtoSSL takes it
  only for its exact bytes. Build 35.3 -> 25.5 MB, installer 14.3 -> 11.8 MB.
- My first reading of the closing time was wrong twice: waiting for the output measured the browser
  processes holding the inherited pipe, and the window was hidden before pywebview's wait, not left
  on screen. Measuring the process handle and printing when `main()` returns settled it.

### What the bug hunt found

Server (`proto-lab`), each reproduced or tested:

- QoS HTTP answered one connection after the other: a client that connected and said nothing held
  up every launcher request for its 5 s timeout (4.8 s -> 0.001 s). A thread per connection, at most 32.
- A failed `accept()` (a connection reset before it was accepted, a full descriptor table) ended the
  listener for the rest of the session. `_accept_forever` keeps listening.
- On Windows the QoS UDP responder ended on the `WSAECONNRESET` that follows a reply to a closed
  port - one game closing its probe socket ended QoS for everyone. Reproduced on `windows-latest`
  with the old code (a burst of probes from a socket that closes at once); fixed.
- A stats file cut short dropped the asking player's connection on every speed wall query, and their
  progress stopped being saved: it is now rebuilt from the journal. A broken `players.json` was
  replaced by an empty one on the next save; it is now kept aside first.
- A capture file per Blaze message by default - hundreds per session, forever. The launcher now
  starts the server with `--no-capture` unless *Protocol captures* is on.

Launcher:

- A missing `hosts` file (some clean-up tools delete it; Windows reads it as empty) gave a red error
  and the redirect could not be turned on. It now counts as empty and *Turn on* creates it.
- The EA App check started `tasklist.exe` (and a console host) every 8 s; it reads the process
  list from Windows itself now.
- The page polled and redrew while minimized; uncaught script errors vanished (the packaged
  launcher has no developer tools) - they go into the launcher log and the bug report now.

### Tooling notes

- The Windows job builds with `requirements.txt`, the same pins a local build uses. The runner's
  artifact quota can be full; the upload is allowed to fail, the job summary has the results.
- Temporary branches ran one-off Windows experiments (an A/B of the WebView2 setup, the exit
  timing, the old QoS code) and were deleted afterwards.
