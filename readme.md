# TurboRivals

Private multiplayer servers for **Need for Speed Rivals**.

Discord: https://discord.gg/efckqjhR2z 

EA shut the game's online services down on 7 October 2025. Rivals still runs offline, but
AllDrive — the shared open world for up to six players — died with the servers. This project
puts a replacement server in its place.

**Status: AllDrive works.** Up to six players in one shared session, host migration when the host
leaves, career progress that survives a restart, player names and profile pictures. It works over a
LAN and over a VPN.

This project ships no game files, assets or executables, and circumvents no copy protection.
Every player uses their own legally purchased copy; we only provide a server that stands in for
a service the publisher switched off. [MIT licensed](LICENSE).

## What you need

- **Need for Speed Rivals** (Steam or EA App) — each player needs their own copy
- **EA App** running in the background — the game is launched through it, not through Steam
- **Edge WebView2 Runtime** for the launcher — built into Windows 11, a free download on older Windows 10
- **Python 3.10+** — only if you run from source; the packaged launcher needs nothing installed
- **Radmin VPN** or Hamachi if you are playing over the internet (not needed on a shared LAN)

Frida, memory dumps and `launch_direct.py` exist purely for protocol analysis. **They are not
needed to play**. Start the game the normal way, through the EA App, or let the launcher do it.

## The launcher

![The TurboRivals launcher](docs/launcher.png)

`launcher/` is a windowed launcher. It handles the `hosts` entry (including cleaning out old
ones), the firewall rules, your name and picture, and finding the career save your game loads.
It also shows who is online and streams the server log. It is the easy path; the console
commands below still work and remain the reference.

It is laid out like any current desktop app: a sidebar with *Host a session*, *Join a session*,
*Server log*, *Settings* and *Report a problem*, and the page next to it. A session page holds:

- **Setup** — one row per check (administrator rights, EA App, certificate, `hosts` redirect,
  firewall rules, server ports), each with its own fix button, and *Fix all*. The checks fill in
  as they finish and run again when you come back to the window, so starting the EA App or a VPN
  later is noticed. A port another program holds is named, with the program. With everything
  green the card folds to a progress bar, and it opens again when something breaks.
- **You** — your name (with how the others will see it: the game shows plain ASCII) and picture;
  as the host, the address the others connect to, with *Copy*; as a joining player, the host's
  address (tested as you type), recent hosts and your career save.
- **Server** or **Connection** — your server's address, uptime and log, with the reasons it
  cannot start yet; or the checklist of what *Connect & play* does. The button itself sits at the
  top right, next to *Launch game*.
- **Online now** with pictures, and **Activity** — who joined or left, and the server's hints,
  such as a player whose game never logged in.

*Server log* (`Ctrl+L`) filters the log to key events, the usual traffic, everything, or only
problems, searches it, and has a second tab listing every change the launcher made. Every server
run is also saved to `%LOCALAPPDATA%\TurboRivals\logs` (the last ten). *Report a problem* gathers
a ready-made bug report. *Settings* say what to do with the redirect when you close the launcher
and whether the server keeps protocol captures (off by default: a session used to leave hundreds of
files behind).

```powershell
venv\Scripts\pythonw.exe launcher\app.py      # pythonw = no console window
```

How the launcher is built, and how to work on it without Windows (a browser preview with a
stand-in backend, and the tests): [docs/launcher.md](docs/launcher.md).

### Building the standalone version

No Python, no repository and no `openssl` on the target machine — for handing to the people
you play with.

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
winget install JRSoftware.InnoSetup      # once, for the installer
.\build.ps1
```

Two things come out of `dist\`:

| | |
| --- | --- |
| `TurboRivals\` | 25 MB folder — a local copy; see the warning below before zipping it |
| `TurboRivalsSetup-<version>.exe` | 12 MB installer — Start Menu entry, uninstaller, no UAC prompt |

**Hand people the installer, not a zip of the folder.** Every file extracted from a
downloaded archive inherits Mark-of-the-Web, and .NET then refuses to load
`pythonnet\runtime\Python.Runtime.dll`, which pywebview needs — the launcher dies with
`Failed to resolve Python.Runtime.Loader.Initialize`. Inno Setup writes the files fresh, so
an installed copy never hits this. A zip works only if the recipient unblocks it first
(`Get-ChildItem -Recurse <folder> | Unblock-File`).

The installer is per-user: it lands in `%LOCALAPPDATA%\Programs\TurboRivals` and needs no
administrator rights, because the launcher asks for them itself when it touches `hosts` or
the firewall. Uninstalling takes the `hosts` redirect and the firewall rules down first —
otherwise you would be left with an entry that breaks the EA App and no tool to remove it.
Your data in `%LOCALAPPDATA%\TurboRivals` (config, `pki/`, save backups, your picture) survives.
The installed launcher does not save raw server frames (`--no-capture`): they include the EA
auth code from every login. It also deletes any that a version before 1.0.7 left in `capture\`.

[TurboRivals.spec](TurboRivals.spec) and [installer/TurboRivals.iss](installer/TurboRivals.iss)
document what goes in and why.

GitHub Actions builds the installer the same way on every push (`windows build + installer`),
installs it silently and runs [tests/smoke_build.py](tests/smoke_build.py) against the installed
exe: the certificate, the server with a stand-in game logging in, `--hosts-off`, and
`--self-test`, which opens the window and checks that the page and both directions of the bridge
work. Then it uninstalls again. The job summary lists the window's start and close times and the
package size.

**One folder, not one file.** A one-file build unpacks ~30 MB into `%TEMP%` on every start
and deletes it on exit; when anything still holds a file there, it reports
`Failed to remove temporary directory`, which looks like a crash but is only failed cleanup.
One folder never touches `%TEMP%` and starts instantly.

Two more things make this work, and both matter if you change the code:

- **The exe runs the server by re-invoking itself.** Frozen, `sys.executable` is the launcher,
  not a Python interpreter, so `commands.build_command` emits `TurboRivals.exe --run-server …`
  and `app.py` dispatches on that flag before it imports the GUI. `--make-cert` and
  `--cleanup` (`hosts` + firewall; `--hosts-off` for `hosts` only) do the same for the
  certificate and for the uninstaller, and `--self-test` opens the window, checks it and closes
  it again - that is how the packaged build gets tested without anyone clicking through it. The
  server mode switches its output to
  line buffering, or the log panel would sit empty while a session runs.
- **Nothing needs `openssl` or `cryptography`.** `make_stub_cert.py` builds the RSA keys, the
  certificate and its patched signature in plain Python - byte for byte what the earlier
  `cryptography` version made, which a test checks - and `tls_terminator.load_rsa_priv` reads the
  key with its own DER parser instead of shelling out to `openssl rsa -text` on every start.
  Leaving the library out took the build from 35 to 25 MB (the installer from 14 to 12 MB).

Everything the program writes goes to `%LOCALAPPDATA%\TurboRivals`, never next to the exe,
so an installed copy and the portable one share the same config, certificate and progress.

## How to play

### With the launcher

Every player installs the same version and runs the launcher (it asks for administrator rights
when it needs them).

**Host:** *Host a session* in the sidebar.
1. *Fix all* under *Setup* (restart as administrator when it asks).
2. Your name and picture; pick the address the others reach you on (the Radmin `26.x.x.x` one
   over a VPN) and send it to them with *Copy*.
3. The firewall rules open the ports on the chosen address only, not on every network the PC is
   on. After you switch to another address, *Setup* shows them as outdated: *Update* fixes it.
   When all rules are in place, *Remove* closes the ports again when you are done playing.
4. *Start server*, then start the game.

**Everyone else:** *Join a session*.
1. The host's address, your name and a picture. The launcher tells you straight away whether a
   TurboRivals server answers there.
2. Check that *Career save* is not orange (*Guessed*).
3. *Connect & play*.

*Connect & play* fixes up `hosts`, checks that the name now really leads to the host, tells the
host which save your game loads and what you are called, sends your picture and starts the game -
each step ticked off or explained in the checklist. *Online now* shows who is in.

The rest of this section is the same thing done by hand from a console.

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

Other server flags worth knowing:

- `--bind-ip 127.0.0.1,<ADDRESS>` listens on those addresses only (default: all). Keep
  `127.0.0.1` in the list on the host. Its own game must connect from there to stay the local
  player whose save the server detects.
- `--no-capture` stops saving raw frames to `docs/recon/capture`. Run from source the server
  keeps them for debugging; they include the EA auth code from the login, so never share them.
- `--handshake-timeout <s>` (default 10) closes connections that never finish the TLS handshake.
- `--session-bps <bit/s>` (default 10,000,000) is the bandwidth every player is shown to the
  others with. Up to 1.0.8 it was 100 kbit/s; `--session-bps 100000` brings that back. It is an
  experiment: does a "slow" player explain name tags that show only up close?

- `--speedwall-relation <n>` (default 2) is how the other players' speed wall results are
  marked for you: 2 = friend, 3 = recently played, 0 = not set (up to 1.0.11). Your own row is
  always "local player". The numbers are taken from the order of the names in the game, not
  read from a table, so `3` is the switch to try when a wall shows no rival.
- `--no-resume` turns off taking a dropped session back (see below).

**A dropped connection.** If the host's server restarts or a PC sleeps, the game comes back by
itself with the session key of its login (`resumeSession`). Since 1.0.12 the server takes it
back, and you see `[player] ... resumeSession` in the log. Then use *Search for session* to
meet up again. Up to 1.0.11 the game got an empty answer, gave up, and needed a restart. A game
that dropped out also asks matchmaking to avoid the game it was in. Since 1.0.12.1 the server
still puts you back into that game when it is the only one around (`--strict-avoid` turns that
off). Before that, the player ended up alone in a new session.

"Find a new session" (from the menu or Esc / Page Up) leaves your game, and since 1.0.12.2 it
never puts you straight back into it. A rejoin within the first minute looped on the loading
screen: the host's game was still closing the old connection. With no other session around,
you get a new one of your own, as in the original game, and the host can join it with their own
"find a new session". A lost connection, such as a PC asleep, is not leaving: that player
still goes back into the host's game.

**Autolog rivals (1.0.12.2, experimental).** The game asks the server for its Autolog rivals
(`NFS.getInGameRecommendations`), and their results are what speed walls compare you against.
The server answers with every other player it knows and their speed walls, and logs it as
`[autolog] You: 2 rival(s) (Friend: you lead 18, they lead 3, 3 "beat you"; ...)`.

Since 1.0.12.3 it also lists the "X beat you" recommendations: every wall where a rival is
ahead, newest first, up to 20 per rival. Special Guest and the Autolog playlist now get proper
empty answers, because there are no Special Guests left and the playlist format is unknown. The
recommendation type and title are read from the game's own names but not confirmed in play, so
`--autolog-beat-type 1` / `2` are there to try. `--no-autolog` turns all of Autolog off.

Since 1.0.12.5 races and other events get "X beat you" entries too: up to 10 per rival, listed
first, with cameras, zones and jumps filling the rest up to 20.

One difference from the original game remains. A rival with nothing to beat is left off the
Autolog rival list, though that rival's results still show on the speed walls. The game
crashes on such a rival even without mods: that crashed one player after every race on
1.0.12.3. `--autolog-empty-rivals` is for testing only. If the game ever crashes right after an
event, `--autolog-world-only` keeps the entries off events, as 1.0.12.4 did. A player with no
rival at all, such as someone new or playing alone, gets the plain empty answer the game got
before Autolog (since 1.0.12.6).

**A player whose identity is not confirmed is left out of the others' Autolog while online
(1.0.12.7): off the rival list and off the speed walls.** That is someone who joined without the
launcher, or whose *YOUR CAREER SAVE* is orange. Your game cannot tie such a player's car to
them, so the results they set in your session leave their rows empty in your game:
- On 1.0.12.6 the host clicked such a player in the rival list, right after that player drove
  through one of their own "beat you" cameras, and the host's game crashed.
- The cameras that player had just driven ahead of the host showed no Autolog rival at all.

Offline such a player was never shown anyway. `--autolog-unconfirmed-rivals` brings them back
(tests only). Should the crash ever come back with a confirmed player,
`--autolog-no-session-rivals` keeps everyone in your session off the list. The log says who was
left out (`not listed: ... (identity not confirmed)`, and on a wall `not shown, identity not
confirmed: ...`).

Also since 1.0.12.7, the rival card no longer shows "String not on Autolog Yet" or
"INVALID SPEEDWALL: 12": the entries carry the game's own story texts, and Speedlists, which
the card cannot name, get no "beat you" entries.

**Speed walls** show the other players' results when they drove the same camera, zone or jump.
The log lists who drove what (`[speed wall] ...: you 45.9 AverageSpeed, Friend 50.1 ...`). The
original Autolog compared you with your platform friends, and the game still takes those from
the EA App. If a wall shows nobody, add each other as friends in the EA App. A cop's career
has no results on the racers' speed cameras.

The launcher passes extra flags from `"server_args"` in its `config.json`
(`%LOCALAPPDATA%\TurboRivals\config.json`, i.e. `C:\Users\<you>\AppData\Local\TurboRivals\config.json`).
Close the launcher, open the file in Notepad and replace the line `"server_args": []`, for example:

```json
"server_args": ["--speedwall-relation", "3"]
"server_args": ["--speedwall-relation", "3", "--no-autolog"]
```

Each flag and each value is its own quoted item. Save, start the launcher, and the log shows the
whole command on its first line. Put `[]` back after the test. Flags for A/B tests:
`--speedwall-relation N`, `--no-autolog`, `--strict-avoid`, `--no-resume`, `--no-lookup-users`,
`--session-bps N`, `--autolog-no-session-rivals`.

Firewall rules (once, as Administrator):

```powershell
netsh advfirewall firewall add rule name="TurboRivals" dir=in action=allow protocol=TCP localport=42127,14219,17502
netsh advfirewall firewall add rule name="TurboRivals QoS" dir=in action=allow protocol=UDP localport=17502-17503
netsh advfirewall firewall add rule name="NFS Rivals P2P" dir=in action=allow protocol=UDP localport=3659
```

Adding `localip=<YOUR_ADDRESS>` to each rule limits it to that adapter, which is what the
launcher does.

### Everyone else

The only step is a `hosts` entry pointing at the server: **the host's address** (its Radmin,
ZeroTier or LAN address), never `127.0.0.1`. That one is only for the host's own machine; on
yours it sends the game back to itself. The file is `C:\Windows\System32\drivers\etc\hosts`,
named exactly `hosts` with no extension. `hosts.ics` next to it is never read for names. Some
Windows installs have no `hosts` file at all. The launcher creates it (since 1.0.11), or save
one from Notepad run as administrator ("Save as type: All files"). From a console, PowerShell
as Administrator:

```powershell
$h = "$env:SystemRoot\System32\drivers\etc\hosts"
# drop any older entry first - with two lines the first one wins, not the newest
(Get-Content $h) | Where-Object { $_ -notmatch 'gosredirector\.ea\.com' } | Set-Content $h -Encoding ASCII
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
Origin token, which only EA's own service could resolve. So every player names themselves in
their own launcher, in *Name in the session*. The field starts out with your EA nickname when
the EA App has it. A joining player's launcher sends the name to the host on *Connect & play*, and the
server keeps it with that player's career save id, so it stays the same over LAN or a VPN and
across restarts.

Next to the name is your picture. Click it and pick any photo. The launcher shrinks it to
a small PNG and sends it to the host's server, and every launcher in the session shows who is
logged in under *Online now*, with pictures. The host keeps them in `avatars\` next to
`players.json`. The game shows the picture too. It asks the server for each player's profile
picture (ByteVault `GET .../categories/Pictures/records/<id>`), and the server answers with the
launcher's 256 px JPEG as raw bytes (`Content-Type: image/jpeg`). Confirmed on 30.09 with the
player's own picture. A picture set before 1.0.6 has no JPEG copy, so pick it once more.

Up to 1.0.9, a detailed photo could get a player dropped a few seconds after joining a session.
The game's copy could be up to 64 KB, and the server sent it as a single TLS record, above the
16 KB that TLS allows. Since 1.0.10 the server splits it, and the launcher keeps the game's
copy within 16 KB. **If that happened to you, pick your picture once more.** If a picture
does not get through ("picture not sent"), the launcher sends it again whenever *ONLINE NOW*
shows you without one. The host's log names the reason (`[avatar] ... refused`). Right-click
the picture to remove it, here and on the host. Uninstalling asks whether to remove the
pictures, settings and logs too. Your career saves and their backups stay.

The host's player list (`--player <address>=<name>`) is only for someone joining without the
launcher, and it goes by address, so it has to be the address the host actually sees them
connect from. From the console:

```
--local-persona "YourName"        name of the player at the server (stored permanently)
--player 26.0.0.2=FriendName      name for an address, for a player without the launcher
```

### Career saves

Rivals keeps your career on your own PC, in
`Documents\Ghost Games\Need for Speed(TM) Rivals\settings\<id>.sav`. The game loads your
account's own save from the EA era, but it writes to the file named after the id the server
gives it at login. If the two ids differ, every change (a new paint job, an unlocked car) goes
to a file the game never reads, and it is gone after a restart.

So the server logs every player in under the id of the save their game loads. That id is the
persona id the EA App gives the game on start. The launcher takes it from the EA App's log
(`%LOCALAPPDATA%\Electronic Arts\EA Desktop\Logs\EADesktopVerbose.log`) when the id is written
there in full. The EA App usually masks it as `####`, so the launcher falls back to the save
files: a save ending in the same five digits as the EA account, or else the only EA save on the
PC. If none of that works, the id is only a guess and *Career save* turns orange. That
happens when Rivals has never been played on that PC, or when several EA accounts played it
there. For the first case, start Rivals once through the EA App without TurboRivals, play until
it saves, close it, then connect. The game then makes its own save, which the launcher finds.

Confirmed on 30.09 on two kinds of accounts. Newer ones share the suffix: user `…74704`, save
`1006431274704`. Older ones do not: user `1004043460810`, save `1802434674`, found as the only EA
save. In both cases a changed paint job stuck.

- **the host** — found automatically through the EA App on the server's machine
  (`--local-id <id>` overrides it);
- **everyone else** — their launcher sends it to the host on *Connect & play* (*Join a
  session* shows it under *Career save*). Without the launcher, the host passes
  `--player-id <their address>=<id>`.

The server checks each id against the login token, so nobody can load someone else's save.
The launcher backs the save folder up once a day before a session, to
`%LOCALAPPDATA%\TurboRivals\save-backups` (last 5 kept). To see which id this PC would use,
run `python proto-lab/ea_identity.py`.

## What works

- login, session setup, client configuration, QoS
- public games and matchmaking (find-or-create)
- a shared AllDrive session for up to six players, with direct connections between them.
  Sessions of 3 to 6 players have been tested.
- host migration: when the host leaves, another player takes over and the session goes on
- progress saved from GameReporting reports (`~/TurboRivals/data`), and career progress that
  survives a game restart (see *Career saves*)
- speed walls served from saved results
- player names and profile pictures, in the launcher and in the game

## Known issues that are not bugs

Two warnings come up on a fresh machine and neither means anything is wrong:

- **"Windows protected your PC" (SmartScreen).** The build is not code-signed, so Windows
  has no reputation for it. Choose *More info* -> *Run anyway*.
- **The launcher fails with `Failed to resolve Python.Runtime.Loader.Initialize`.** That
  happens when the program was run out of a folder extracted from a downloaded archive:
  those files carry Mark-of-the-Web and .NET refuses to load them. Install with
  `TurboRivalsSetup-<version>.exe` instead, or unblock the folder first
  (`Get-ChildItem -Recurse <folder> | Unblock-File`).

One more that looks like a network problem and is not: **a joining player's game says it cannot
connect and the host's log shows nothing from that machine.** Check `hosts` on the joining machine
for a second `gosredirector.ea.com` line, one written by hand or by an older setup:

```powershell
Select-String gosredirector "$env:SystemRoot\System32\drivers\etc\hosts"
```

Windows returns the first matching line, so a stale `127.0.0.1` above the launcher's block sends
the game back to its own machine. The launcher flags such a line on the *Hosts redirect* row and
removes it on *Fix* and *Connect & play*.

**Another player looks like an ordinary racer: icon and name only up close.** The game ties
every car to a player by the owner's EA career save id. A player logged in under some other id
(no launcher, or an orange *YOUR CAREER SAVE*) leaves the other games unable to match their car.
That was the "names disappear after a session change" bug of 1.0.0. Since 1.0.8 the server
answers the game's question about such a car (`[lookup]` in the server log). A
`[lookup] WARNING` names a player whose save id is wrong; fix that player's save in their
launcher.

## Reporting a problem

[Open an issue](https://github.com/Turbotoster7/TurboRivals/issues/new/choose). The form asks
for the launcher version, which side hit the problem, how the players are connected, and the
checks under *Setup*. *Report a problem* in the launcher's sidebar gathers all of that into one
text to paste - including your career save and the last lines of the server log, with
paths shortened so your Windows user name stays out of it.

What helps most is the **server log**, in particular the lines naming a component and a
command (`Fire2 comp=… cmd=…`): they say exactly how far the client got. Every server run is
saved whole, one file per run, in `%LOCALAPPDATA%\TurboRivals\logs` (the last 20, since 1.0.9),
starting with the version and the command line; attach the newest file. The *Everything* view
of *Server log* shows the same lines. A session that stops after `Util.preAuth` without an
`Authentication.login` almost always means the EA App was not running on that machine - the
server says so itself, with a `[hint]` line that the launcher shows under *Activity*. If
progress does not stick, include what *Career save* showed, and the `[identity]` lines from the
host's log.

Read the section above first — the three most common reports are not bugs.

## What is missing

- **internet play without a VPN** — the game connects players directly and EA's relay is gone
  (the game has UPnP code of its own, a lead for phase 5)
- other players' profile pictures in the game: served the same way as your own, not yet
  confirmed in a shared session
- the Autolog playlist (its entries' layout is unknown, so it stays empty) and Autolog's HOT and
  POPULAR recommendations
- a few RPCs still answered with an empty acknowledgement: `NFS.getOverwatchStatsConfig`,
  `Authentication.getAccount`, `Authentication.createWalUserSession`,
  `GameManager.setPlayerAttributes`

## Repository layout

```
launcher/     the windowed launcher (pywebview UI + the system plumbing)
tools/       recon tooling (binary analysis, hosts switcher)
proto-lab/   the server and the protocol decoders
tests/       launcher and server tests, with a fake game client (python -m unittest discover -s tests):
             matchmaking, Autolog, the server on loopback, hosts file, firewall rules, the
             launcher's server command line; smoke_build.py for a built exe
docs/        protocol notes, decision log, raw recon output
```

The tests need only `cryptography` and never touch the real `hosts` file, the firewall or the
game. GitHub Actions runs them on every push:

```powershell
python -m unittest discover -s tests -v
```

Protocol details: [docs/protocol.md](docs/protocol.md).
Work log, including the reasoning and the dead ends: [docs/decisions.md](docs/decisions.md).

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
| 3 | launcher: hosts, firewall and names without a console | done |
| 4 | host migration, sessions for 3-6 players | done |
| 5 | internet play without a VPN (NAT traversal) | |
