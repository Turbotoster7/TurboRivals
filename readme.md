# TurboRivals

Private multiplayer servers for **Need for Speed Rivals**.

EA shut the game's online services down on 7 October 2025. Rivals still runs offline, but
AllDrive — the shared open world for up to six players — died with the servers. This project
puts a replacement server in its place.

**Status: AllDrive works.** Two players, one shared session, driving together, progress saved —
over a LAN and over a VPN.

This project ships no game files, assets or executables, and circumvents no copy protection.
Every player uses their own legally purchased copy; we only provide a server that stands in for
a service the publisher switched off. [MIT licensed](LICENSE).

## What you need

- **Need for Speed Rivals** (Steam or EA App) — each player needs their own copy
- **EA App** running in the background
- **Python 3.10+** — only on the machine hosting the server
- **Radmin VPN** or Hamachi if you are playing over the internet (not needed on a shared LAN)

Frida, memory dumps and `launch_direct.py` exist purely for protocol analysis. **They are not
needed to play** — launch the game normally through Steam.

## How to play

### The machine running the server (host)

```powershell
# 1. point the EA backend at yourself (run PowerShell as Administrator)
python tools/hosts_switch.py on

# 2. generate the stand-in certificate (once)
python proto-lab/make_stub_cert.py

# 3. start the server; --public-ip is YOUR address as the other players see it
python -u proto-lab/tls_terminator.py --public-ip <YOUR_ADDRESS> --entitlements online
```

`--public-ip` must name the adapter the other players reach you through. On Radmin that is your
Radmin address (`26.x.x.x`), **not** your LAN address. Get this wrong and the server hands
players an address they cannot see, which is the single most common way to break a session.
Without the flag the server guesses from the default route.

Firewall rules (once, as Administrator):

```powershell
netsh advfirewall firewall add rule name="TurboRivals" dir=in action=allow protocol=TCP localport=42127,14219,17502
netsh advfirewall firewall add rule name="TurboRivals QoS" dir=in action=allow protocol=UDP localport=17502-17503
netsh advfirewall firewall add rule name="NFS Rivals P2P" dir=in action=allow protocol=UDP localport=3659
```

### Everyone else

The only step is a `hosts` entry pointing at the server (PowerShell as Administrator):

```powershell
$h = "$env:SystemRoot\System32\drivers\etc\hosts"
Add-Content -Path $h -Value "<SERVER_ADDRESS>`tgosredirector.ea.com" -Encoding ASCII
ipconfig /flushdns
```

Plus one rule for player-to-player traffic — the game connects players directly, not through
the server:

```powershell
netsh advfirewall firewall add rule name="NFS Rivals P2P" dir=in action=allow protocol=UDP localport=3659
```

Remove the `hosts` line when you are done, otherwise the game will keep looking for that server
on every launch.

### In game

The first player to pick "Search for session" becomes the host; everyone else joins the same
way. There is no session browser — the server drops joining players into the existing public
game by itself.

### Player names

The server has no way to learn your EA name: at login the client sends nothing but an opaque
Origin token, which only EA's own service could resolve. So names are supplied by hand:

```
--local-persona "YourName"              name of the player at the server (stored permanently)
--player 26.0.0.2=FriendName      name for an address (pass on every start)
```

## What works

- login, session setup, client configuration, QoS
- public games and matchmaking (find-or-create)
- a shared AllDrive session for two players, with direct connections between them
- progress saved from GameReporting reports (`~/TurboRivals/data`)
- speed walls served from saved results

## What is missing

- **host migration** — when the host leaves, the game ends and everyone else gets
  `NotifyGameRemoved`
- **internet play without a VPN** — the game connects players directly and EA's relay is gone
- sessions with three or more players are untested
- a launcher to handle `hosts`, firewall rules and names for the user
- a few RPCs still answered with an empty acknowledgement: `UserSessions.lookupUsers`,
  `NFS.getSpecialGuestInfo`, `getInGameRecommendations`, `getAutologPlaylist`

## Repository layout

```
tools/       recon tooling (binary analysis, hosts switcher)
proto-lab/   the server and the protocol decoders
docs/        protocol notes, decision log, raw recon output
```

Protocol details: [docs/protocol.md](docs/protocol.md).
Work log, including the reasoning and the dead ends: [docs/decisions.md](docs/decisions.md).

Both documents are currently written in Polish.

## Recon tooling

```bash
python tools/dump_strings.py "<path>/NFS14.exe" --all --tags   # strings from the binary
python tools/extract_tdf_meta.py "<path>/NFS14.exe"            # TDF tag <-> field pairs
python tools/pe_probe.py "<path>/NFS14.exe" info               # PE probe
python proto-lab/tcp_tap.py -p 42127                           # passive listener
python proto-lab/frida_run.py                                  # diagnostic hook
```

## Roadmap

| phase | scope | state |
| --- | --- | --- |
| 0 | binary and endpoint recon | done |
| 1 | working out the protocol | done |
| 2 | prototype server, first shared session | done |
| 3 | launcher: hosts, firewall and names without a console | |
| 4 | host migration, sessions for 3-6 players | |
| 5 | internet play without a VPN (NAT traversal) | |
