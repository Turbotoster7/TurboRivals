"""Which EA account is playing on this machine, and which career save its game loads.

Rivals keeps the career locally, in
    Documents\\Ghost Games\\Need for Speed(TM) Rivals\\settings\\<id>.sav
and the server only ever sees a copy of it in GameReporting reports. The game WRITES to the file
named after the uid our Authentication.login reply hands it, but on start it LOADS the account's
own save from the EA era. A player given a synthetic uid (lobby.py pools) therefore saves into a
file the game never reads: every session starts from the same old state, and a colour change or
an unlocked car is gone after a restart. Confirmed 30.09 on the host: a login under the id of the
save the game loads made a colour change survive a restart, and that .sav got written again for
the first time since 16.09.

So the server must log each player in under that id. Nothing in the login says what it is (the
Origin token is opaque), but this machine does: the EA App tells the game its persona id over LSX
(GetProfile) and writes the answer into its own log (ea_profile) - that id IS the save. Without the
log entry the .sav files and the EA App's user_*.ini give a guess. Shared by the server (the local
player) and the launcher (a guest reports its id and nickname to the host before launching the
game).

Account ids come in families: the EA App user id (1012917074704), the game's persona id
(1006431274704) and the Origin token (...:74704:...) of one account all end in the same five
digits. That suffix is the fallback for picking the .sav, and what the server checks the token
against.
"""
from __future__ import annotations

import base64
import binascii
import html
import os
import re
from pathlib import Path

import lobby

SAVE_SUBDIR = Path("Ghost Games") / "Need for Speed(TM) Rivals" / "settings"
EA_DESKTOP_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "Electronic Arts" / "EA Desktop"
EA_LOGS_DIR = EA_DESKTOP_DIR / "Logs"
LOG_FILES = ("EADesktopVerbose.log", "EADesktopVerbose.bak")     # newest first
PROFILE_RE = re.compile(r"<GetProfileResponse\b([^>]*)>")
ATTR_RE = re.compile(r'(\w+)="([^"]*)"')
SOURCE_PROFILE = "EA App profile"        # resolve(): where the save id came from
SOURCE_SAVES = "save files"
SOURCE_ONLY_SAVE = "the only EA save file"
SOURCE_GUESS = "EA App user id (guess)"
SOURCE_CHOSEN = "chosen in the launcher"
SUFFIX_LEN = 5
POOL_SIZE = 1_000_000_000            # lobby.py draws a synthetic uid as base + crc32 % POOL_SIZE


def documents_dir() -> Path:
    """The real Documents folder. Not ~/Documents: OneDrive moves it (here it is
    OneDrive\\Dokumenty), and only the shell knows where it went."""
    try:
        import ctypes
        from ctypes import wintypes

        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        # CSIDL_PERSONAL = 5, SHGFP_TYPE_CURRENT = 0
        if ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf) == 0 and buf.value:
            return Path(buf.value)
    except (AttributeError, OSError):
        pass
    return Path.home() / "Documents"


def saves_dir() -> Path:
    return documents_dir() / SAVE_SUBDIR


def save_ids(folder: Path | None = None) -> list[int]:
    """Ids of the career saves in the game's settings folder, oldest file first."""
    folder = folder or saves_dir()
    try:
        files = [p for p in folder.glob("*.sav") if p.stem.isdigit()]
        files.sort(key=lambda p: p.stat().st_mtime)
    except OSError:
        return []
    return [int(p.stem) for p in files]


def save_files(folder: Path | None = None, users: list[int] | None = None) -> list[dict]:
    """Every <id>.sav in the game's settings folder, newest file first, as {"id", "written"
    (mtime, epoch seconds), "kind"}: "career" - a save the game may load; "server" - an id one
    of our servers made up (lobby.py pools); "account" - an EA App user id, the file the game
    wrote while the launcher guessed that id. The game never loads the last two (02.10: a guest
    took 1100944155289 for his save - our synthetic uid from an earlier session)."""
    folder = folder or saves_dir()
    accounts = set(ea_user_ids() if users is None else users)
    found = []
    try:
        for p in folder.glob("*.sav"):
            if p.stem.isdigit():
                found.append((int(p.stem), p.stat().st_mtime))
    except OSError:
        return []
    found.sort(key=lambda f: f[1], reverse=True)
    return [{"id": uid, "written": int(written),
             "kind": "server" if is_synthetic(uid) else "account" if uid in accounts else "career"}
            for uid, written in found]


def ea_user_ids(folder: Path = EA_DESKTOP_DIR) -> list[int]:
    """user.userid of every account that ever signed in to the EA App on this machine, newest
    user_*.ini first. There can be a friend's too."""
    try:
        inis = sorted(folder.glob("user_*.ini"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return []
    ids = []
    for ini in inis:
        try:
            m = re.search(r"^user\.userid=(\d+)", ini.read_text(encoding="utf-8", errors="replace"), re.M)
        except OSError:
            continue
        if m and int(m.group(1)) not in ids:
            ids.append(int(m.group(1)))
    return ids


def ea_user_id(folder: Path = EA_DESKTOP_DIR) -> int | None:
    """user.userid of the account last signed in to the EA App (newest user_*.ini)."""
    ids = ea_user_ids(folder)
    return ids[0] if ids else None


def is_synthetic(uid: int) -> bool:
    """A uid lobby.py made up (it bumps past collisions, hence the margin), not an EA id."""
    return any(base <= uid < base + POOL_SIZE + 1000
               for base in (lobby.LOCAL_UID_BASE, lobby.REMOTE_UID_BASE))


def same_account(uid: int, suffix: str) -> bool:
    return bool(suffix) and str(uid).endswith(suffix)


def ea_profile(user: int | None = None, log_dir: Path = EA_LOGS_DIR) -> dict | None:
    """The profile the EA App last handed the game over LSX, for `user` (default: the account
    signed in to the EA App): {"user", "persona_id", "persona"}. None when the log has none.

    The game asks for it with GetProfile on every start, and EADesktopVerbose.log records the
    answer: <GetProfileResponse ... UserId="..." PersonaId="..." Persona="PayTonkaaa" .../>.
    PersonaId names the save the game loads (confirmed 30.09: 1006431274704 on the host), and
    Persona is the player's EA nickname. The log rotates into .bak, so both are read, newest
    entry first. An account whose game has not run on this machine since the log last rotated is
    not in it.

    The EA App usually MASKS the ids (UserId="####" PersonaId="####") and only now and then
    logs them in full - on the guest's laptop on 30.09 every entry was masked. The nickname is
    never masked, so a masked entry still gives it: then persona_id is None."""
    user = ea_user_id() if user is None else user
    nickname = ""
    for name in LOG_FILES:
        try:
            text = (log_dir / name).read_bytes().decode("utf-8", errors="replace")
        except OSError:
            continue
        for tag in reversed(PROFILE_RE.findall(text)):
            attrs = dict(ATTR_RE.findall(tag))
            uid, persona_id = attrs.get("UserId", ""), attrs.get("PersonaId", "")
            if uid.isdigit() and user and uid != str(user):
                continue                            # another account
            persona = html.unescape(attrs.get("Persona", "")).strip()
            if persona_id.isdigit():
                return {"user": int(uid) if uid.isdigit() else None,
                        "persona_id": int(persona_id), "persona": nickname or persona}
            nickname = nickname or persona          # masked - the newest name still counts
    return {"user": user, "persona_id": None, "persona": nickname} if nickname else None


def _kind(uid: int, accounts: set[int]) -> str:
    return "server" if is_synthetic(uid) else "account" if uid in accounts else "career"


def resolve(saves: list[int] | None = None, user: int | None = None,
            log_dir: Path = EA_LOGS_DIR, users: list[int] | None = None,
            chosen: int = 0) -> dict:
    """Which save the game loads for the account signed in to the EA App, and how we know:
    {"id", "source", "user", "persona", "saves", "files", "auto"}. `users`: every EA App account
    on this machine. `saves` (tests) stands in for the folder; `files` then carries no times.

    0. `chosen` - the save the player picked in the launcher, when it is a "career" file on disk
       (save_files). Two EA-era saves defeat rules 2 and 3 (a friend's PC on 02.10:
       1803135129 from 2013 and 1803135130), and only the player can tell which one the game
       loads. A pick that is gone from the folder falls back to the rules below and is
       reported as "chosen_missing". "auto" always holds what the rules alone give.
    1. The EA App's own answer (ea_profile) - no guessing, when the log has the id unmasked.
    2. The account's EA-era save: a .sav with the account's suffix that is not the user id
       itself (the persona id differs from it). Several - more than one persona - the lowest id,
       i.e. the oldest; not the oldest file, because once we log in under the right id that file
       is written every session.
    3. The only EA-era save on the machine: not one of ours (synthetic), not an EA App user id,
       not in the family of another account signed in here. The suffix rule does not hold for
       every account - the guest's laptop on 30.09: user 1004043460810, save 1802434674 (written
       on 15.09 while the game ran without our login, so under its own persona id).
    4. Otherwise the user id, a guess - that is what lost the guest's progress on 30.09.
    No EA App: id None, the caller keeps its old uid.

    Each entry of "files" (save_files) also says why it may be the one: "profile" (the EA App
    named it), "suffix" (it carries the account's suffix), "newest" (the career save written
    last) - or why not: "other" (it carries another EA App account's suffix)."""
    user = ea_user_id() if user is None else user
    accounts = set(ea_user_ids() if users is None else users) | ({user} if user else set())
    if saves is None:
        files = save_files(users=list(accounts))
        saves = [f["id"] for f in reversed(files)]          # oldest first, as save_ids()
    else:
        files = [{"id": s, "written": 0, "kind": _kind(s, accounts)} for s in reversed(saves)]
    out = {"id": None, "source": "", "user": user, "persona": "", "saves": saves,
           "files": files, "auto": {"id": None, "source": ""}}
    if not user:
        return out
    profile = ea_profile(user, log_dir)
    out["persona"] = profile["persona"] if profile else ""
    auto = _auto(saves, user, accounts, profile)
    suffix = str(user)[-SUFFIX_LEN:]
    others = {str(u)[-SUFFIX_LEN:] for u in accounts if u != user}
    newest = next((f["id"] for f in files if f["kind"] == "career"), None)
    for f in files:
        career = f["kind"] == "career"
        f["profile"] = auto["source"] == SOURCE_PROFILE and f["id"] == auto["id"]
        f["suffix"] = career and same_account(f["id"], suffix)
        f["other"] = career and any(same_account(f["id"], o) for o in others)
        f["newest"] = f["id"] == newest
    out.update(auto, auto=dict(auto))
    if chosen:
        if any(f["id"] == chosen and f["kind"] == "career" for f in files):
            out.update(id=chosen, source=SOURCE_CHOSEN)
        else:
            out["chosen_missing"] = chosen
    return out


def _auto(saves: list[int], user: int, accounts: set[int], profile: dict | None) -> dict:
    """Rules 1-4 of resolve: {"id", "source"}."""
    if profile and profile["persona_id"]:
        return {"id": profile["persona_id"], "source": SOURCE_PROFILE}
    suffix = str(user)[-SUFFIX_LEN:]
    own = [s for s in saves if not is_synthetic(s) and s != user and same_account(s, suffix)]
    if own:
        return {"id": min(own), "source": SOURCE_SAVES}
    others = {str(u)[-SUFFIX_LEN:] for u in accounts if u != user}
    only = [s for s in saves if not is_synthetic(s) and s not in accounts
            and not any(same_account(s, f) for f in others)]
    if len(only) == 1:
        return {"id": only[0], "source": SOURCE_ONLY_SAVE}
    return {"id": user, "source": SOURCE_GUESS}


def profile_id(saves: list[int] | None = None, user: int | None = None,
               log_dir: Path = EA_LOGS_DIR) -> int | None:
    """Id of the save the game loads - see resolve."""
    return resolve(saves, user, log_dir)["id"]


def token_suffix(auth: str | bytes | None) -> str:
    """The account suffix inside an Origin login token (Authentication.login AUTH), e.g.
    AT1:3.0:3.0:240:<random>:74704:sepqt -> "74704". "" when it does not look like one."""
    if not auth:
        return ""
    if isinstance(auth, bytes):
        auth = auth.decode("ascii", errors="replace")
    try:
        text = base64.b64decode(auth + "=" * (-len(auth) % 4))
        parts = text.decode("ascii", errors="replace").split(":")
    except (binascii.Error, ValueError):
        return ""
    return parts[5] if len(parts) > 5 and parts[5].isdigit() else ""


if __name__ == "__main__":
    import time

    found = resolve()
    print(f"saves folder : {saves_dir()}")
    print(f"ea_user_id   : {found['user']}")
    print(f"profile_id   : {found['id']} ({found['source'] or '-'})")
    print(f"EA nickname  : {found['persona'] or '-'}")
    print("save files   :" + ("" if found["files"] else " -"))
    for f in found["files"]:
        notes = [n for n in ("profile", "suffix", "other", "newest") if f.get(n)]
        print(f"  {f['id']:>15}  {time.strftime('%Y-%m-%d %H:%M', time.localtime(f['written']))}"
              f"  {f['kind']:<7} {' '.join(notes)}")
