# The launcher

How `launcher/` is put together, how to work on it (also without Windows), and what the 1.1
rework changed and why.

## Files

| file | what it is |
| --- | --- |
| `launcher/app.py` | the window (pywebview) and `Api`, the only bridge between the page and Python. Also the command-line modes of the packaged exe: `--run-server`, `--make-cert`, `--cleanup` (the uninstaller's: `hosts` and the firewall rules), `--hosts-off`, `--self-test` |
| `launcher/commands.py` | everything that touches the system: hosts, firewall, ports, processes, addresses, the server process, the career save, pictures, config, diagnostics |
| `launcher/web/index.html`, `css/style.css` | the interface: title bar, sidebar, the session, log and settings pages, dialogs |
| `launcher/web/js/core.js` | interface logic that needs no page: log levels, the IPv4 and name rules, the readiness list, what blocks the big button, the bug report text. Tested under Node |
| `launcher/web/js/app.js` | the page: state, rendering, actions, the log viewer, dialogs |
| `launcher/dev/` | a browser preview with a stand-in backend - not bundled |
| `tools/hosts_switch.py` | the `hosts` block, shared by the launcher and the console tool |
| `tests/` | Python tests (`unittest`), the Node tests for `core.js`, and `smoke_build.py` for a built exe |

## How the window gets its state

Nothing waits for the slowest check. On start the page asks for `get_snapshot()` - everything
that is quick to know (config, `hosts`, certificate, server status, picture) - and paints. Then
`refresh()` runs the slow probes in parallel threads and pushes each result as it lands:

| probe | source | when |
| --- | --- | --- |
| `processes` | the process list straight from Windows (`CreateToolhelp32Snapshot`, `tasklist` as the fallback), for the EA App and the game | start, every 8 s while the window is visible, window focus |
| `addresses` | one `ipconfig` (link-local 169.254.x.x left out) | start, window focus |
| `save` | `ea_identity.resolve()`, cached until one of its files changes | start |
| `firewall` | `netsh advfirewall firewall show rule`, per rule, read for the values (the labels are translated) | start, mode change |
| `ports` | a bind test like the server's own; the owner from `netstat -ano` + the process list | start, before a server start |

Events from Python to the page go through `window.TR.on(event, payload)`:

| event | payload |
| --- | --- |
| `probe` | `{name, value}` |
| `log` | a batch of server log lines, at most ten batches a second (see `ServerProcess`) |
| `server-exit` | `{code, requested}` - a stop from the launcher exits non-zero too (`TerminateProcess` leaves 1), so only an exit nobody asked for is a crash |
| `window` | `{hidden}` - minimized or restored: the page stops polling and drawing while nobody looks |

`Api._emit` sends nothing once the window is closing and waits at most 5 s for the page, and the
process ends with `os._exit` after the window is gone: pywebview answers every call on a
non-daemon thread, and one finishing during teardown could otherwise keep the process alive.

The player list for guests without the launcher lives in Python (saved on every add/remove);
`save_config` from the page only carries the fields typed there. `server_args` in config.json -
extra server flags for A/B tests, written by hand (readme) - is kept through every save and goes
last on the server's command line.

## What it keeps where

| | |
| --- | --- |
| `%LOCALAPPDATA%\TurboRivals\config.json` | settings (from the repo: `launcher/config.json`). Written atomically; a broken or hand-edited file falls back to defaults field by field |
| `%LOCALAPPDATA%\TurboRivals\pki\` | the stand-in certificate (from the repo: `proto-lab/pki/`) |
| `%LOCALAPPDATA%\TurboRivals\logs\server-<date>-<pid>.log` | every server run, the newest 20; it starts with the version and the command line |
| `%LOCALAPPDATA%\TurboRivals\save-backups\` | the game's save folder, once a day before a session, the newest 5 |
| `%LOCALAPPDATA%\TurboRivals\avatar.png`, `.jpg` | your picture, for the launchers and for the game |
| `%LOCALAPPDATA%\TurboRivals\webview\` | the WebView2 profile. It stays: a new one on every start and its deletion on closing cost 2.5 s each time (see *Measured* below) |
| `%LOCALAPPDATA%\TurboRivals\capture\` | one file per Blaze message - only with *Protocol captures* on in *Settings*: on by default when run from source, off in the packaged launcher (the frames hold the EA auth code of every login; an installed launcher clears old ones on each start) |
| `drivers\etc\hosts.turborivals-<date>.bak` | a copy before every change to `hosts`, the newest 5 |

The server is tied to the launcher with a Windows job object: when the launcher ends - closed,
crashed or killed - Windows ends the server too, so no stray server keeps the ports.

## Packaging

`build.ps1` runs PyInstaller on `TurboRivals.spec` (one folder, `dist\TurboRivals\`) and then
Inno Setup on `installer\TurboRivals.iss` (`dist\TurboRivalsSetup-<version>.exe`); the readme's
*Building the standalone version* says why it is one folder and why people get the installer, not
a zip. For the launcher this means:

- `launcher/web` is bundled whole (`js/core.js` included); `launcher/dev` and `tests` are not.
- The exe is also the server: `TurboRivals.exe --run-server ...`, started by `build_command` and
  tied to the launcher by the job object. `--make-cert` and `--cleanup` (the uninstaller's) work
  without opening the window; `--self-test` opens it, waits until the page is drawn and every check
  has come back, prints one JSON line (with the page's performance marks) and exits 0 or 1.
- `requirements.txt` pins what the build uses. CI (`windows build + installer`) runs `build.ps1`,
  installs the result silently, runs `tests/smoke_build.py` against the installed exe and
  uninstalls it again.
- `VERSION` is the one place the version lives: the window, the exe's version resource and the
  setup's file name all read it.

The spec's Windows version resource needs Windows; the rest of the build (the bundle, the frozen
launcher, its server and command-line modes) was also checked on Linux with that part left out.

## The interface

Built like a current desktop app rather than a game HUD: a title bar of its own (the window is
frameless), a sidebar, and a page next to it.

| page | what is on it |
| --- | --- |
| *Host a session* / *Join a session* | the page header with the main button (*Start server* / *Connect & play*, next to *Launch game*) and a banner naming what stops it; then two columns of cards: *Setup*, *Online now*, *Activity* on the left, *You* and *Server* / *Connection* on the right |
| *Server log* (`Ctrl+L`) | the server log or the launcher's own activity, filtered (key events, standard, everything, problems), searchable, following new lines on request; copy, open the log folder, clear |
| *Settings* | the redirect on closing (ask, remove, keep), protocol captures, the folders, help links |
| *Report a problem* | a dialog with the bug report, ready to paste |

The sidebar's foot shows your picture and the live state (*Server live · 3 online*, *2 to fix*).
*Setup* folds to a progress bar once every check is green and stays folded while a session runs
unless a check turns red. While the server runs, the address and guest list on *You* (fixed by
then) give way to the session.

All colours and sizes are custom properties at the top of `css/style.css`, in the TurboRivals
colours of the 1.0 launcher and turbotoster.dev: navy surfaces (`--bg` #0b1026, `--card`,
`--border`), one cyan accent for what can be done (`--accent` #00f0ff, with `--accent-ink` for text
on it - white on cyan is unreadable), and green, amber and red only for state. Titles and the
mark are Rajdhani (`--font-display`), the rest Segoe UI Variable on Windows, Inter (bundled, SIL
OFL) elsewhere; the log is Cascadia Mono or Consolas.

The window opens on the 1.0 launcher's boot screen - a HUD ring, three boot lines in Share Tech
Mono and a bar. It no longer covers a blocking call: the bar creeps towards 90 % while the page
waits for the bridge and the first snapshot, jumps to 100 % when that is in and fades (at least
600 ms, so it does not flash; at most 4 s, so a bridge or snapshot that never comes traps no one -
the page then shows what it has). Apart from it nothing moves on its own except a spinner while
something is pending, and `prefers-reduced-motion` turns transitions off. Below 1000 px the sidebar folds to
icons, below 820 px the page becomes one column.

Work is kept to what can be seen: renders are batched per animation frame, the log is classified
as it arrives but only drawn while its page is open, and nothing polls while the window is
minimized (Python pushes the `window` event) or hidden.

## Working on it

### Without Windows

```bash
python launcher/dev/preview.py          # http://127.0.0.1:8765/?scenario=hosting
```

The preview serves `launcher/web` and slips in `dev/mock-api.js`, which answers every `Api`
method with canned data, so the interface can be built and screenshotted in a browser.
Scenarios: `fresh` (first start), `ready`, `issues` (a stale hosts line, a missing certificate, a
port taken by another program, an outdated firewall rule), `hosting`, `joining`, `unreachable`;
add `&mode=client` or `&latency=<ms>`.

The real launcher also runs on Linux (pywebview with GTK/WebKit): the Windows checks report
"Windows only" or "can't check", the rest works - the server, `ONLINE NOW`, the log.

```bash
TURBORIVALS_HOME=/tmp/tr TURBORIVALS_HOSTS=/tmp/tr/hosts python launcher/app.py
```

`TURBORIVALS_HOME` keeps everything the launcher writes in one separate folder;
`TURBORIVALS_HOSTS` points it at a hosts file of your own. Both work on Windows too, for a
second setup next to the real one.

### Tests

```bash
python -m unittest discover -s tests -v      # `cryptography` only for test_stub_cert's reference
node --test tests/js/core.test.mjs
```

- `test_commands.py` - parsing of `ipconfig`, `netsh`, `netstat` and `tasklist` output (English
  and localised samples), hosts writes, ports, config, players, names, pictures, the server
  process. On Windows also the real tools and the job object.
- `test_hosts_switch.py` - the hosts block, encodings, backups, address rules.
- `test_server.py` - the real server, started the way the launcher starts it, driven by the
  launcher's own functions and by `fake_game.py`: a stand-in for the game's Blaze client (the
  TLS 1.0/RC4 handshake and Fire2 requests). A game that never logs in gets the `[hint]`; a
  logged-in one shows up in `ONLINE NOW`.
- `test_port_taken.py` - a server without one of its ports stops and names it; printed lines
  stay whole across threads.
- `test_server_units.py` - the server's listener loops (a refused or reset connection, a full
  descriptor table, a Windows UDP reset), a broken stats file rebuilt from its journal, a broken
  `players.json`.
- `test_stub_cert.py` - the stand-in certificate, built in plain Python, compared byte for byte
  with what `cryptography` builds from the same keys and times.
- `test_app.py` - the `Api` without a window (needs pywebview).
- `tests/js/core.test.mjs` - `core.js`, including the same name and address rules as Python.

`.github/workflows/tests.yml` runs both on `windows-latest` and `ubuntu-latest`, and builds,
installs and smoke-tests the installer on `windows-latest`:

```bash
python tests/smoke_build.py --exe "<installed>/TurboRivals.exe"   # or without --exe: the source
```

## Measured

Before and after this rework, each measured the same way on the same machine.

**Linux VM** (software rendering, pywebview 6.2.1 with WebKitGTK; the real launcher, a real server,
a stand-in game logged in):

| | before | after |
| --- | --- | --- |
| CPU with the window idle and visible, CPU-seconds per 30 s | 1.0.6: 100.9, first 1.1: 67.6 | 1.65 |
| CPU while hosting, window visible | 87.6 (first 1.1) | 1.58 |
| CPU while hosting, minimized | 0.32 | 0.04 |
| start until the window is drawn with its state, median of 5 | 0.505 s | 0.438 s |
| a launcher request behind a client that connected and said nothing (QoS HTTP) | 4.806 s | 0.001 s |
| capture files after a short session, as the launcher starts the server | 23 | 0 |

The idle CPU was the animations: the old splash kept its endless sweep running after it was
hidden, and the live server card had moving stripes and pulsing dots.

**Windows** (GitHub's `windows-latest`, the installed exe, `tests/smoke_build.py`; the old and the
new setup alternated on one runner, median of three warm starts):

| | before | after |
| --- | --- | --- |
| reading the process list (every 8 s) | `tasklist` 363.7 ms | Toolhelp 2.5 ms |
| page loaded, from the start of navigation | 0.64 s | 0.26 s |
| window drawn with its state, from the process start | 2.33 s | 2.02 s |
| every check in | 2.62 s | 2.28 s |
| closing, until the process is gone | 2.49 s | 2.20 s |
| window size (asked: 1100x680) | 1084x641 | 1100x680 |

Of the 2.20 s of closing, the window is gone after 0.12 s; the rest is Windows tearing the process
down - the same with `TerminateProcess` instead of `os._exit`, so nothing the launcher still does.
The very first start on a fresh runner takes 4-6 s until drawn (WebView2 starting cold).

The build: `dist\TurboRivals\` 35.3 MB in 111 files before, 25.5 MB in 99 files now; the installer
14.3 MB before, 11.8 MB now - `cryptography` (9.4 MB of it) is no longer needed for the certificate.
(1.0.6, built with the same packages: 35.2 MB.) The interface's fonts went from 96 KB to 72 KB.

## 1.1: what the review of 1.0.6 found

The 1.0.6 launcher worked, but reading it closely and driving it end to end turned up these.

**Bugs**

- **A half-started server.** Every listener except the redirector binds in its own thread, and a
  failed bind called `sys.exit()` - which ends only that thread, silently. With TCP 17502 taken,
  the server ran without QoS HTTP and without the launcher channel (identify, pictures, ONLINE
  NOW), and its log said nothing. It now stops and names the port, and the launcher checks the
  ports before starting it and names the program in the way.
- **Log lines running together.** `print()` writes the text and the line end separately, so
  threads printing at once produced `...(QoS HTTP)[identity] local player...`. The server now
  writes one line per call.
- **Every stop was a crash.** A server stopped from the launcher exits with 1, and the window said
  "server died (code 1)".
- **The firewall row never knew.** It turned green only after *ADD* in the same session, and *ADD*
  deleted and re-added every rule each time. The rules are now read from `netsh`, and only a
  missing or outdated one is (re)added.
- **hosts.** A file saved in a legacy codepage lost its non-ASCII comments on every rewrite
  (decoded as UTF-8 with replacement); whatever was typed as the address went into the system
  file unchecked; every toggle left one more backup in `drivers\etc`, forever; a failed write was
  not rolled back.
- **Leftovers.** A crashed launcher left its server holding the ports (the next one was refused);
  a launcher closed while a call was in flight could linger as a process.

**Experience**

- Two fixed columns at 1000x620: the session setup was cut off, the player list and ONLINE NOW
  needed scrolling, the log took half the window - and stayed empty for every joining player.
- A fake boot screen covered the window while one blocking call ran `tasklist`, `ipconfig` twice
  and the EA App log scan.
- No sense of what to do next: five dots, some grey for "unknown", no single fix.
- The log: mostly keepalive pings, no filter, no search, gone when the window closed.
- Toasts over the action buttons; no way to tell a refused connection from a timeout from a typo;
  no help with the issue form.

The new window answers these with a sidebar and pages instead of everything at once, *Setup* with
a fix button per row and *Fix all*, a live connect checklist, a log page with filters, search and
log files, *Activity* with the server's hints, and *Report a problem*.
