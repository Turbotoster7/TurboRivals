"""Shared server state for all connections: player sessions and games (multiplayer).

Up to run-27 the server assumed ONE player: a hardcoded identity, games as global
counters without a player list, notifications only to the player's own connection. This registry
lets a second player find the first one's public game and send notifications to ANOTHER connection.

Threads: the terminator handles every connection in a separate thread. The registry has one lock
(RLock), and every session has its own send lock - Wire.send_record is not thread-safe (RC4 state
and the record number in the MAC), and notifications to player B are sent by player A's thread.

Operations that change game state return a list of (session, frame) - the terminator sends them.

Identity: every player gets a permanent uid stored in players.json, and a name. The game never
tells the server its EA nickname (GNAM only echoes the name our login gave it), so the name comes
from the player's own launcher (register - it offers the EA nickname from the EA App's log), else
from the host's --player IP=NICK list, else a Player_<octet> placeholder.

The uid is NOT arbitrary. The client accepts whatever originLogin tells it, but the game names its
career save after that uid while loading the account's EA-era save on start - so under any other
uid progress goes into a file the game never reads (ea_identity.py; confirmed 30.09). The uid
must be that save's id: for the player at the server it comes from --local-id or this machine's
EA App (ea_identity.profile_id), for a remote player from its launcher (register) or --player-id,
checked against the account suffix in the login token. Such a player is stored under "ea:<id>",
so it stays one player whichever address it connects from (LAN, Radmin).

Only when that id is unknown does a player fall back to the old scheme: a uid from a synthetic
pool keyed by IP address (local and remote pools are disjoint). Progress then lasts only as long
as one session.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import threading
import time
import zlib
from pathlib import Path

import blaze

LOCAL_IPS = {"127.0.0.1", "::1"}
LOCAL_KEY = "local"                  # key of the local player in players.json (instead of an IP address)
EA_KEY = "ea:"                       # key prefix of a remote player known by its EA save id
SYNTHETIC = "synthetic pool"         # id source of a player whose EA save id is unknown
LOCAL_UID_BASE = 1_000_000_000_000   # uid pool for the player at the server machine
REMOTE_UID_BASE = 1_100_000_000_000  # uid pool for players from other addresses
DEFAULT_ADDR = (0x7F000001, 3659, 0x7F000001, 3659, 0)   # exip, export, inip, inport, maci
# A player who LEFT a game itself (PLAYER_LEFT, GROUP_LEFT) is not put straight back into it,
# avoided or not, for this long: on 01.10 a rejoin right after "find a new session" never got
# the host's mesh connection (the host's game was still closing the old one) and looped.
REJOIN_GRACE_S = 60


class Session:
    """One Blaze connection. The identity (uid, persona) is assigned by Lobby.login on 1/152."""

    def __init__(self, ip: str, send_raw) -> None:
        self.ip = ip
        self.uid = 0
        self.persona = ""
        self.key = ""                    # players.json key: LOCAL_KEY, "ea:<id>" or the IP address
        self.id_source = ""              # where the uid came from, for the log
        self.id_check = ""               # uid vs the login token's account suffix, for the log
        self.persona_id = 0              # EA persona id (BUID from listUserEntitlements2)
        self.addr = DEFAULT_ADDR         # network address reported by the client
        self.games: set[int] = set()
        self.pending = None              # dispatch decision (createGame/resetDedicated) for _after_reply
        self.outbox: list = []           # notifications (session, frame) to send after the reply
        self.mm_timer = None             # threading.Timer with a deferred matchmaking decision
        self.resumed = False             # resumeSession just took an identity: login notes follow
        self.alive = True
        self._send_raw = send_raw
        self._lock = threading.Lock()
        self._notify_seq = 0

    @property
    def is_local(self) -> bool:
        return self.ip in LOCAL_IPS

    def send(self, frame: bytes) -> None:
        with self._lock:
            self._send_raw(frame)

    def notify(self, frame: bytes) -> int:
        """Notification with this session's own increasing msgId. Returns the assigned msgId."""
        with self._lock:
            seq = self._notify_seq
            self._notify_seq += 1
            self._send_raw(blaze.reseq(frame, seq))
            return seq

    def __repr__(self) -> str:
        return f"{self.persona or '?'}({self.uid}@{self.ip})"


class Game:
    def __init__(self, gid: int, host_uid: int, params: dict) -> None:
        self.gid = gid
        self.host_uid = host_uid
        self.params = params             # game arguments for blaze.build_notify_game_setup
        self.state = blaze.GAME_STATE["INITIALIZING"]
        self.players: dict[int, dict] = {}   # uid -> {"slot", "state"}
        self.migrating_from = 0              # old host uid while a host migration is running
        self.pre_migration_state = self.state
        self.creator_uid = host_uid          # OGHI mGameCreatorId - survives host migrations
        # ReplicatedGameData.mAdminPlayerList. The creator starts as the only admin; the host's
        # game then promotes every joiner with addAdminPlayer (4/106).
        self.admins: list[int] = [host_uid]
        # Set once the game has gone through a host migration. Test 62 (C and D): the migrated
        # host's game never starts game traffic to a player who joins afterwards - only tunnel
        # keepalives - and the joiner abandons the session after ~50 s. So nobody joins it.
        self.migrated = False
        self.migration_pending: set[int] = set()   # HostMigrationType parts not yet reported

    @property
    def public(self) -> bool:
        return self.params.get("attributes", {}).get("gameMembershipRequirements") == "Public"


class Lobby:
    def __init__(self, players_file: Path | str | None = None,
                 forced: dict[str, str] | None = None,
                 player_state_notify: bool = True,
                 local_id: int = 0, local_persona: str = "",
                 local_id_source: str = "--local-id",
                 player_ids: dict[str, int] | None = None,
                 host_migration: bool = True,
                 migration_player_removed: bool = True,
                 migration_type: int = 2, platform_host_init: bool = True,
                 admin_tracking: bool = True, join_migrated: bool = False) -> None:
        # --join-migrated-games (A/B): let matchmaking put players into a game after a host
        # migration - behaviour up to test 62, where such a joiner waited ~50 s and left
        self.join_migrated = join_migrated
        # --no-admin-tracking (A/B): keep no admin list - ADMN = [host] and no admin notifications
        # when an admin leaves, as up to test 59
        self.admin_tracking = admin_tracking
        self.player_state_notify = player_state_notify   # --no-player-state-notify (A/B)
        self.host_migration = host_migration             # --no-host-migration (A/B)
        # --migration-type: HOST_MIGRATION_TYPE value sent in 4/70. The Rivals host is both the
        # topology and the platform host, so the default migrates both (2); test 53 used 0.
        self.migration_type = int(migration_type)
        self.platform_host_init = platform_host_init     # --no-platform-host-init (A/B)
        # --migration-skip-player-removed (A/B): whether the old host's NotifyPlayerRemoved
        # follows NotifyHostMigrationStart
        self.migration_player_removed = migration_player_removed
        self.migrations_started: list[int] = []          # gids, collected by the terminator
        self.local_id = int(local_id or 0)               # --local-id or local-auto: overrides the generated uid
        self.local_id_source = local_id_source
        self.local_persona = str(local_persona or "")    # --local-persona: overrides the nickname from GNAM
        # ip -> (EA save id, source): from a guest's launcher (register) or --player-id IP=ID
        self.registered: dict[str, tuple[int, str]] = {
            ip: (int(uid), "--player-id") for ip, uid in (player_ids or {}).items()}
        self.registered_user: dict[str, int] = {}        # ip -> EA App user id its launcher reported
        self.names: dict[str, str] = {}                  # ip -> nickname its launcher reported
        self.guessed: set[str] = set()                   # ips whose launcher only guessed the save id
        self.aliases: dict[int, int] = {}                # id a game asked about (lookupUsers) -> uid
        self.left_at: dict[tuple[int, int], float] = {}  # (uid, gid) -> monotonic time it left itself
        self._key_ip: dict[str, str] = {}                # players.json key -> address of its last login
        self.lock = threading.RLock()
        self.sessions: dict[int, Session] = {}
        self.games: dict[int, Game] = {}
        self.next_gid = 0x10000001
        self.next_msid = 1
        self.players_file = Path(players_file) if players_file else None
        self.forced = dict(forced or {})          # --player IP=NICK
        self.players: dict[str, dict] = {}        # ip -> {"uid", "persona"}
        if self.players_file and self.players_file.exists():
            try:
                self.players = json.loads(self.players_file.read_text(encoding="utf-8"))
                if not isinstance(self.players, dict):
                    raise ValueError("not a JSON object")
            except (OSError, ValueError) as e:
                # Start a new one, but never over the old: the next save used to overwrite it,
                # and with it every player's uid and name.
                kept = self.players_file.with_name(f"{self.players_file.name}.corrupt-{int(time.time())}")
                try:
                    os.replace(self.players_file, kept)
                except OSError:
                    kept = self.players_file
                print(f"  [lobby] {self.players_file.name} was unreadable ({e}) - starting a new "
                      f"one, the old file kept as {kept.name}")
                self.players = {}

    # ------------------------------------------------------------ identity
    def _save_players(self) -> None:
        if not self.players_file:
            return
        try:
            self.players_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.players_file.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.players, indent=1, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.players_file)
        except OSError as e:
            print(f"  [lobby] could not write {self.players_file}: {e}")

    def register(self, ip: str, uid: int, source: str = "launcher", name: str = "",
                 user: int = 0, guess: bool = False) -> None:
        """The EA save id (and nickname, EA App user id) a player's launcher reported before
        starting the game. Used on that address's next login, once the token confirms the id
        (_identity); the nickname then goes into players.json under the player's id. guess: the
        launcher found no save and sent the EA App user id instead (shown orange there)."""
        with self.lock:
            self.registered[ip] = (int(uid), source)
            if guess:
                self.guessed.add(ip)
            else:
                self.guessed.discard(ip)
            if user:
                self.registered_user[ip] = int(user)
            if name:
                self.names[ip] = name

    def _adopt_stats(self, old: int, new: int) -> None:
        """A player moving to a new uid keeps its speed wall results: stats/<old>.json is copied
        once, unless the new uid already has results of its own."""
        if not self.players_file or not old or old == new:
            return
        stats = self.players_file.parent / "stats"
        src, dst = stats / f"{old}.json", stats / f"{new}.json"
        if src.exists() and not dst.exists():
            try:
                shutil.copy2(src, dst)
                print(f"  [identity] results copied: stats/{old}.json -> stats/{new}.json")
            except OSError as e:
                print(f"  [identity] could not copy stats/{old}.json: {e}")

    def _ea_key(self, ip: str, suffix: str) -> tuple[str, str]:
        """players.json key of a remote player known by its EA save id, and where that id came
        from - or ("", "") when it is unknown or fails the check.

        Candidates: the id registered for this address (launcher, --player-id), then the only
        known "ea:" player whose id carries the token's account suffix - that one needs no
        launcher, so a server restart or a switch from LAN to Radmin keeps the player. Every
        candidate must carry the suffix - or, for a registered id, the EA App user id reported
        with it must, since the launcher read the pair from the EA App's own profile: better the
        old synthetic uid than someone else's save. With no suffix to check, a registered id is
        still taken, unless another address is logged in under it."""
        candidates = []
        if ip in self.registered:
            candidates.append(self.registered[ip])
        if suffix:
            # by the id itself, or by the EA App user id stored with it (an older account's
            # persona id does not share the suffix - _vouched)
            known = [int(k[len(EA_KEY):]) for k, e in self.players.items()
                     if k.startswith(EA_KEY)
                     and (k.endswith(suffix) or str(e.get("user", "")).endswith(suffix))]
            if len(known) == 1:
                candidates.append((known[0], "token suffix"))
        for uid, source in candidates:
            vouched = self._vouched(ip, uid, source, suffix)
            if suffix and not str(uid).endswith(suffix) and not vouched:
                print(f"  [identity] WARNING {ip}: id {uid} ({source}) is not this account's "
                      f"(token ...{suffix}) - ignored, falling back to the address's uid")
                continue
            live = self.sessions.get(uid)
            if not suffix and live is not None and live.alive and live.ip != ip:
                print(f"  [identity] WARNING {ip}: id {uid} ({source}) is already logged in from "
                      f"{live.ip} - ignored, falling back to the address's uid")
                continue
            key = f"{EA_KEY}{uid}"
            if key not in self.players:
                old = self.players.get(ip, {})
                self.players[key] = {
                    "uid": uid, "persona": old.get("persona") or f"Player_{ip.rsplit('.', 1)[-1]}"}
                self._save_players()
                print(f"  [identity] {ip}: uid {old.get('uid', '-')} -> {uid} ({source})")
                self._adopt_stats(int(old.get("uid", 0)), uid)
            if vouched:
                self._settle_user(key, uid, self.registered_user.get(ip, 0))
            return key, source
        return "", ""

    def _vouched(self, ip: str, uid: int, source: str, suffix: str) -> bool:
        """Whether the EA App user id paired with `uid` carries the token's suffix: reported by
        this address's launcher along with that id, or stored with it in players.json."""
        if not suffix:
            return False
        if (uid, source) == self.registered.get(ip):
            user = self.registered_user.get(ip, "")
        else:
            user = self.players.get(f"{EA_KEY}{uid}", {}).get("user", "")
        return str(user).endswith(suffix)

    def _settle_user(self, key: str, uid: int, user: int) -> None:
        """Stores the EA App user id with the player (found by the token suffix from then on, even
        without its launcher), and folds in an entry made earlier under that user id itself - a
        launcher before 1.0.4 sent it when it could not find the save (guest, 30.09): its name
        and results move over, the stale entry goes."""
        entry = self.players[key]
        if user and entry.get("user") != user:
            entry["user"] = user
            self._save_players()
        stale = f"{EA_KEY}{user}"
        if not user or user == uid or stale not in self.players:
            return
        gone = self.players.pop(stale)
        if gone.get("persona") and str(entry.get("persona", "")).startswith("Player_"):
            entry["persona"] = gone["persona"]
        self._adopt_stats(int(gone.get("uid", 0)), uid)
        self._save_players()
        print(f"  [identity] {stale} was a guess of this player's save id - merged into {key}")

    def _identity(self, ip: str, suffix: str = "") -> tuple[str, str]:
        """players.json key for a login from an address, and where its uid came from; creates
        the entry on the first login. The local player lives under LOCAL_KEY, because its
        address (127.0.0.1) tells nothing apart; a remote player under "ea:<id>" when its EA
        save id is known (_ea_key), otherwise under its address."""
        local = ip in LOCAL_IPS
        if local:
            key = LOCAL_KEY
            source = (self.local_id_source if self.local_id else
                      "players.json" if key in self.players else SYNTHETIC)
        else:
            key, source = self._ea_key(ip, suffix)
            if not key:
                key, source = ip, SYNTHETIC
        entry = self.players.get(key)
        if local and entry and self.local_persona and entry.get("persona") != self.local_persona:
            # --local-persona overrides the stored nickname, not only when creating a new entry:
            # otherwise a once-stored "Player" would stay forever and the flag would look broken.
            entry["persona"] = self.local_persona
            self._save_players()
        if local and entry and self.local_id and int(entry.get("uid", 0)) != self.local_id:
            # Same for the local id: the game names its save file after this uid, so an id that
            # only applied to a brand-new entry could never move an existing player onto the
            # save the game actually loads.
            print(f"  [identity] local: {entry.get('uid')} -> {self.local_id} "
                  f"({self.local_id_source})")
            self._adopt_stats(int(entry.get("uid", 0)), self.local_id)
            entry["uid"] = self.local_id
            self._save_players()
        if not entry:
            used = {e.get("uid") for e in self.players.values()}
            if local:
                # The computer name, not the address: 127.0.0.1 is the same for everyone, and we
                # want a uid that is stable across runs and different across installations.
                uid = self.local_id or LOCAL_UID_BASE + zlib.crc32(
                    socket.gethostname().encode()) % 1_000_000_000
                name = self.local_persona or "Player"
            else:
                uid = REMOTE_UID_BASE + zlib.crc32(ip.encode()) % 1_000_000_000
                name = f"Player_{ip.rsplit('.', 1)[-1]}"
            while uid in used:
                uid += 1
            entry = {"uid": uid, "persona": name}
            self.players[key] = entry
            self._save_players()
            print(f"  [lobby] new player {key}: uid {uid}, progress in stats/{uid}.json")
        return key, source

    def login(self, sess: Session, suffix: str = "") -> list:
        """Assigns an identity to the session. `suffix` = the account suffix from the login
        token (ea_identity.token_suffix), "" if unknown. When the same player already had a
        connection (re-login), the old one leaves its games - returns notifications for the
        other players."""
        with self.lock:
            sess.key, sess.id_source = self._identity(sess.ip, suffix)
            entry = self.players[sess.key]
            sess.uid = int(entry["uid"])
            # The nickname a player typed into its own launcher, then the host's --player list
            # (guests without the launcher), then the stored one. The first is stored under the
            # player's key, so it survives a new address and a server restart.
            reported = self.names.get(sess.ip, "")
            if reported and entry.get("persona") != reported:
                entry["persona"] = reported
                self._save_players()
            sess.persona = reported or self.forced.get(sess.ip) or str(entry["persona"])
            self._key_ip[sess.key] = sess.ip
            # A mismatch on a remote player never gets this far (_ea_key falls back); on the local
            # player it is only reported - the operator's own flag or EA App decides there.
            sess.id_check = ("suffix unknown" if not suffix else
                             f"token ...{suffix}" if sess.id_source == SYNTHETIC else
                             "suffix OK" if str(sess.uid).endswith(suffix) else
                             f"suffix MISMATCH (token ...{suffix})")
            old = self.sessions.get(sess.uid)
            out = []
            if old is not None and old is not sess:
                old.alive = False
                out = self._leave_all(old, blaze.PLAYER_REMOVED_REASON["PLAYER_CONN_LOST"])
            self.sessions[sess.uid] = sess
            return out

    def resume(self, sess: Session, uid: int) -> list | None:
        """UserSessions.resumeSession: a game coming back on a new connection with the session
        key of its earlier login - after the server restarted, or the PC slept (01.10, log
        server-20261001-203209: the guest's game resumed straight on the Blaze port, got an empty
        acknowledgement and gave up). The key names the uid; that player must be known here
        (the local player from 127.0.0.1, ea:<uid>, or an address entry with that uid), and no one
        else may be logged in under it from another address. None = refuse, the game logs in anew.
        Otherwise the session takes the identity as a login would, and the player's previous,
        perhaps half-open connection leaves its games - the notifications are returned."""
        with self.lock:
            if sess.is_local:
                local = self.players.get(LOCAL_KEY, {})
                key = LOCAL_KEY if uid in (self.local_id, int(local.get("uid", 0) or 0)) else ""
            elif f"{EA_KEY}{uid}" in self.players:
                key = f"{EA_KEY}{uid}"
            else:
                key = sess.ip if int(self.players.get(sess.ip, {}).get("uid", 0) or 0) == uid else ""
            live = self.sessions.get(uid)
            known = bool(key) and (key in self.players or key == LOCAL_KEY)
            taken = live is not None and live.alive and live.ip != sess.ip
            if not known or taken:
                return None
            entry = self.players.setdefault(key, {"uid": uid, "persona": self.local_persona or "Player"})
            sess.key, sess.uid = key, uid
            sess.persona = (self.names.get(sess.ip) or self.forced.get(sess.ip)
                            or (self.local_persona if sess.is_local else "")
                            or str(entry.get("persona", uid)))
            sess.id_source, sess.id_check = "resumeSession", "session key"
            self._key_ip[key] = sess.ip
            out = []
            if live is not None and live is not sess:
                live.alive = False
                out = self._leave_all(live, blaze.PLAYER_REMOVED_REASON["PLAYER_CONN_LOST"])
            self.sessions[uid] = sess
            return out

    def logout(self, sess: Session) -> list:
        with self.lock:
            sess.alive = False
            out = self._leave_all(sess, blaze.PLAYER_REMOVED_REASON["PLAYER_CONN_LOST"])
            if self.sessions.get(sess.uid) is sess:
                del self.sessions[sess.uid]
            return out

    def learn_persona(self, sess: Session, name: str) -> bool:
        """EA nickname from the game (GNAM) - remembered for later logins. Also works for the
        local player: it is the only source of their real nickname, which was hardcoded up to
        run-40 (LSX from the EA App only provides the UserId in SetPresence, i.e. after our
        originLogin)."""
        name = (name or "").strip()
        with self.lock:
            if (not name or sess.ip in self.names or sess.ip in self.forced
                    or name == sess.persona):
                return False
            sess.persona = name
            key = sess.key or (LOCAL_KEY if sess.is_local else sess.ip)
            self.players.setdefault(key, {}).update(uid=sess.uid, persona=name)
            self._save_players()
            return True

    def online(self) -> list[dict]:
        """Players logged in right now, for the launchers' ONLINE NOW list (roster() is one
        game's players)."""
        with self.lock:
            return [{"uid": s.uid, "name": s.persona, "local": s.is_local}
                    for s in self.sessions.values() if s.alive]

    def ranked_uids(self) -> set[int]:
        """Whose results the speed walls show: players with a known career save (local, ea:<id>)
        and whoever is logged in right now. stats/ also holds results under ids those same people
        had before (an old synthetic uid, an EA App user id taken for a save id) - shown, they
        would be rivals who are really the player himself."""
        with self.lock:
            known = {int(e.get("uid", 0) or 0) for k, e in self.players.items()
                     if k == LOCAL_KEY or k.startswith(EA_KEY)}
            return known | {s.uid for s in self.sessions.values() if s.alive}

    def uid_for(self, ip: str) -> int:
        """The uid of the player at an address - who a launcher's request speaks for: the live
        session from there, else the id its launcher registered, else (local) the id the local
        player logs in under. 0 when unknown."""
        with self.lock:
            for s in self.sessions.values():
                if s.alive and s.ip == ip:
                    return s.uid
            if ip in LOCAL_IPS:
                return self.local_id or int(self.players.get(LOCAL_KEY, {}).get("uid", 0))
            return self.registered.get(ip, (0, ""))[0]

    def persona_of(self, uid: int) -> str:
        with self.lock:
            s = self.sessions.get(uid)
            if s is not None:
                return s.persona
            for key, e in self.players.items():
                if e.get("uid") == uid:
                    # Same order as login(): after a disconnect the session is gone, and the
                    # migration log used to name the old host by its stored placeholder.
                    ip = self._key_ip.get(key) or ("127.0.0.1" if key == LOCAL_KEY else key)
                    return (self.names.get(ip) or self.forced.get(ip)
                            or str(e.get("persona", uid)))
            return str(uid)

    def unconfirmed_uids(self) -> set[int]:
        """Players online whose uid may not be the PersonaId their game goes by (_unconfirmed):
        the other games cannot tie such a player's car to its Blaze user."""
        with self.lock:
            return {s.uid for s in self.sessions.values() if s.alive and self._unconfirmed(s)}

    def game_mates(self, uid: int) -> set[int]:
        """Everyone in a game together with this player, the player left out."""
        with self.lock:
            s = self.sessions.get(uid)
            if s is None:
                return set()
            return {u for gid in s.games for u in getattr(self.games.get(gid), "players", {})} - {uid}

    def _unconfirmed(self, s: Session) -> bool:
        """Whether a player's uid may not be the PersonaId its game goes by: a synthetic uid, an
        id its launcher only guessed, or a listUserEntitlements2 BUID that differs from it."""
        return (s.id_source == SYNTHETIC
                or (s.ip in self.guessed and self.registered.get(s.ip, (0, ""))[0] == s.uid)
                or bool(s.persona_id and s.persona_id != s.uid))

    def resolve(self, requester: Session, blaze_id: int) -> dict | None:
        """The player behind a BlazeId a game asks about (UserSessions.lookupUsers), as
        {id, persona, addr, how} with id = the asked id, or None.

        A game names each car in its world by its owner's PersonaId (from the EA App) and looks
        for the Blaze user with that id. When the owner logged in under another uid it asks -
        log-40: the guest asked about the host's PersonaId while the host was logged in under its
        EA App user id - and a car nobody answers for stays an ordinary racer, icon and name only
        up close. In order: a live uid, an alias learned before, a player whose
        listUserEntitlements2 BUID is that id, a stored player, and finally the only other player
        in a game shared with the asker whose uid is unconfirmed. The asker itself is no candidate:
        it asks about the cars it sees, and its own lookup (solo, before 1.0.4) is covered by its
        BUID - otherwise an unconfirmed asker would lend its name to a car with a wrong id."""
        with self.lock:
            def found(s: Session, how: str) -> dict:
                if s.uid != blaze_id:
                    self.aliases[blaze_id] = s.uid
                return {"id": blaze_id, "persona": s.persona, "addr": s.addr, "how": how}

            s = self.sessions.get(blaze_id)
            if s is not None and s.alive:
                return found(s, "uid")
            s = self.sessions.get(self.aliases.get(blaze_id, 0))
            if s is not None and s.alive:
                return found(s, "alias")
            for s in self.sessions.values():
                if s.alive and s.persona_id == blaze_id:
                    return found(s, "listUserEntitlements2 BUID")
            if any(e.get("uid") == blaze_id for e in self.players.values()):
                return {"id": blaze_id, "persona": self.persona_of(blaze_id), "addr": None,
                        "how": "players.json (offline)"}
            shared = {uid for gid in requester.games
                      for uid in getattr(self.games.get(gid), "players", {})}
            # A player has one PersonaId: one whose id is already known is no longer a candidate.
            placed = set(self.aliases.values())
            candidates = [s for s in self.sessions.values()
                          if s.alive and s is not requester and s.uid in shared
                          and s.uid not in placed and self._unconfirmed(s)]
            if len(candidates) == 1:
                return found(candidates[0], "the only player with an unconfirmed id")
            return None

    # ------------------------------------------------------------ games
    def new_msid(self) -> int:
        with self.lock:
            msid = self.next_msid
            self.next_msid += 1
            return msid

    def game(self, gid: int) -> Game | None:
        with self.lock:
            return self.games.get(gid)

    def create_game(self, host: Session, params: dict, host_state: int) -> Game:
        with self.lock:
            g = Game(self.next_gid, host.uid, params)
            self.next_gid += 1
            g.players[host.uid] = {"slot": 0, "state": host_state}
            self.games[g.gid] = g
            host.games.add(g.gid)
            return g

    def migrated_games_skipped(self, sess: Session) -> list[int]:
        """Public games of other players that matchmaking passed over only because they went
        through a host migration - for the log, so nobody wonders why a friend's game was not
        joined."""
        with self.lock:
            if self.join_migrated:
                return []
            return [g.gid for g in self.games.values()
                    if g.migrated and g.public and sess.uid not in g.players]

    def find_public_game(self, sess: Session, avoid: set[int], strict: bool = False) -> Game | None:
        """Another player's public game that can be joined: host connected, game already running
        (PRE_GAME/IN_GAME), a free slot available, and no host migration so far (Game.migrated) -
        unless --join-migrated-games. Games on the avoid list (CRIT.AGAM.GIDL) come last, not never:
        a game asks to avoid the one it just dropped out of (01.10, a laptop waking from sleep:
        GIDL = [the host's game]), and with no other game around a strict avoid left that player
        alone in a new one. strict (--strict-avoid) keeps the old behaviour. A game the player
        LEFT itself within REJOIN_GRACE_S is never taken (1.0.12.1 looped on that)."""
        with self.lock:
            joinable = [g for g in sorted(self.games.values(), key=lambda x: x.gid)
                        if g.public and sess.uid not in g.players
                        and (self.join_migrated or not g.migrated)
                        and (host := self.sessions.get(g.host_uid)) is not None and host.alive
                        and g.state in (blaze.GAME_STATE["PRE_GAME"], blaze.GAME_STATE["IN_GAME"])
                        and len(g.players) < int(g.params.get("max_players", 6))
                        # not a game the player itself left a moment ago: that is "find a new
                        # session", and an immediate rejoin loops (REJOIN_GRACE_S). Dropping out
                        # (sleep, a lost connection) is not leaving.
                        and self.left_ago(sess.uid, g.gid) is None]
            preferred = [g for g in joinable if g.gid not in avoid]
            if preferred:
                return preferred[0]
            return None if strict or not joinable else joinable[0]

    def left_ago(self, uid: int, gid: int) -> float | None:
        """Seconds since the player left that game itself, when that was within
        REJOIN_GRACE_S; None otherwise."""
        with self.lock:
            when = self.left_at.get((uid, gid))
            if when is None:
                return None
            ago = time.monotonic() - when
            return ago if ago < REJOIN_GRACE_S else None

    def join(self, sess: Session, g: Game) -> None:
        with self.lock:
            used = {p["slot"] for p in g.players.values()}
            slot = next(i for i in range(len(used) + 1) if i not in used)
            g.players[sess.uid] = {"slot": slot, "state": blaze.PLAYER_STATE["ACTIVE_CONNECTING"]}
            sess.games.add(g.gid)

    def roster(self, g: Game) -> list[dict]:
        """The game's players in the blaze builders' format: {uid, persona, slot, state, addr}."""
        with self.lock:
            out = []
            for uid, p in sorted(g.players.items(), key=lambda kv: kv[1]["slot"]):
                s = self.sessions.get(uid)
                out.append({"uid": uid, "persona": s.persona if s else self.persona_of(uid),
                            "slot": p["slot"], "state": p["state"],
                            "addr": s.addr if s else DEFAULT_ADDR})
            return out

    def members(self, g: Game, exclude: int = 0) -> list[Session]:
        with self.lock:
            return [self.sessions[u] for u in g.players if u != exclude and u in self.sessions]

    def set_state(self, gid: int, state: int) -> Game | None:
        with self.lock:
            g = self.games.get(gid)
            if g is not None:
                g.state = state
            return g

    def remove_player(self, g: Game, uid: int, reason: int) -> list:
        """Removes a player from a game. The notifications go to the REMAINING players - not the
        one leaving: in run-23..27 the client left on its own and worked without one, and a
        notification about its own departure risks the client cleaning up the game twice.

        The host left and someone stayed -> host migration (_start_migration). With
        --no-host-migration: the game is removed and the others get ONLY NotifyGameRemoved. On 15.09
        (log-29, session 4) a player first got the host's NotifyPlayerRemoved, right after it
        NotifyGameRemoved, and the game crashed with a jump to NULL. Hypothesis: the client tears
        down a hostless game already on PlayerRemoved, and GameRemoved hits a deleted object."""
        with self.lock:
            if uid not in g.players:
                return []
            del g.players[uid]
            if reason in (blaze.PLAYER_REMOVED_REASON["PLAYER_LEFT"],
                          blaze.PLAYER_REMOVED_REASON["GROUP_LEFT"]):
                self.left_at[(uid, g.gid)] = time.monotonic()
            s = self.sessions.get(uid)
            if s is not None:
                s.games.discard(g.gid)
            others = self.members(g)
            was_admin = uid in g.admins
            if was_admin and self.admin_tracking:
                g.admins.remove(uid)
            if not g.players:
                self.games.pop(g.gid, None)
                return []
            if uid == g.host_uid and self.host_migration and others:
                return self._start_migration(g, uid, others, reason, was_admin)
            if uid == g.host_uid:
                gone = blaze.build_notify_game_removed(
                    g.gid, blaze.GAME_DESTRUCTION_REASON["HOST_LEAVING"])
                for r in others:
                    r.games.discard(g.gid)
                self.games.pop(g.gid, None)
                return [(r, gone) for r in others]
            note = blaze.build_notify_player_removed(g.gid, uid, reason)
            out = [(r, note) for r in others]
            if was_admin and self.admin_tracking:
                out += self._admin_notes(g, uid, "GM_ADMIN_REMOVED", g.host_uid, others)
            return out

    def _admin_notes(self, g: Game, admin: int, operation: str, updater: int, targets: list) -> list:
        note = blaze.build_notify_admin_list_change(
            g.gid, admin, blaze.GM_ADMIN_OPERATION[operation], updater)
        return [(r, note) for r in targets]

    def set_admin(self, g: Game, pid: int, added: bool) -> None:
        """addAdminPlayer / removeAdminPlayer from a client: keep the list the server replicates
        in NotifyGameSetup and clears when an admin leaves."""
        with self.lock:
            if added and pid not in g.admins:
                g.admins.append(pid)
            elif not added and pid in g.admins:
                g.admins.remove(pid)

    def _start_migration(self, g: Game, old_host: int, others: list, reason: int,
                         was_admin: bool = False) -> list:
        """Host left while others stay: hand the game to the remaining player with the lowest
        slot instead of destroying it. The caller holds the lock.

        Order matters. NotifyHostMigrationStart goes out first and the old host's
        NotifyPlayerRemoved second - on 15.09 (log-29) a client that saw the host removed with no
        migration announced tore the hostless game down and crashed. The game stays MIGRATING,
        which also keeps find_public_game from dropping new players in, until finish_migration."""
        new = min(others, key=lambda s: g.players[s.uid]["slot"])
        slot = g.players[new.uid]["slot"]
        if not g.migrating_from:
            g.pre_migration_state = g.state
        g.migrating_from = old_host
        g.migrated = True
        g.host_uid = new.uid
        g.state = blaze.GAME_STATE["MIGRATING"]
        g.migration_pending = self._migration_parts(self.migration_type)
        self.migrations_started.append(g.gid)
        start = blaze.build_notify_host_migration_start(
            g.gid, new.uid, slot, migration_type=self.migration_type)
        out = [(r, start) for r in others]
        if self.migration_player_removed:
            removed = blaze.build_notify_player_removed(g.gid, old_host, reason)
            out += [(r, removed) for r in others]
        if self.admin_tracking:
            # The old host must leave the admin list on every client. Test 53-59: nobody told the
            # new host, so its game still held the old host as admin - when he came back, it
            # skipped addAdminPlayer, the returning player never became admin, and its game
            # abandoned the join after ~8 s.
            if new.uid not in g.admins:
                g.admins.append(new.uid)
                op = "GM_ADMIN_MIGRATED" if was_admin else "GM_ADMIN_ADDED"
                out += self._admin_notes(g, new.uid, op, old_host, others)
            if was_admin:
                # explicit, whether or not the client already drops the old admin on MIGRATED
                out += self._admin_notes(g, old_host, "GM_ADMIN_REMOVED", new.uid, others)
        return out

    @staticmethod
    def _migration_parts(migration_type: int) -> set[int]:
        """Status reports a migration of this type needs: 2 (topology + platform) is reported by
        the client as two separate updateGameHostMigrationStatus calls, MTYP 1 then MTYP 0
        (test 54)."""
        t = blaze.HOST_MIGRATION_TYPE
        if migration_type == t["TOPOLOGY_PLATFORM_HOST_MIGRATION"]:
            return {t["PLATFORM_HOST_MIGRATION"], t["TOPOLOGY_HOST_MIGRATION"]}
        return {migration_type}

    def _platform_host_initialized(self, g: Game) -> list:
        if not self.platform_host_init or g.host_uid not in g.players:
            return []
        init = blaze.build_notify_platform_host_initialized(
            g.gid, g.host_uid, g.players[g.host_uid]["slot"])
        return [(r, init) for r in self.members(g)]

    def _complete_migration(self, g: Game) -> list:
        g.migrating_from = 0
        g.migration_pending = set()
        g.state = g.pre_migration_state
        done = blaze.build_notify_host_migration_finished(g.gid)
        return [(r, done) for r in self.members(g)]

    def migration_status(self, gid: int, migration_type: int) -> tuple[list, bool]:
        """One updateGameHostMigrationStatus report from the new host. Test 54 showed the client
        reports a topology+platform migration in two steps, platform (1) first and topology (0)
        second - and we used to finish everything on the first one. Now the platform report is
        answered with NotifyPlatformHostInitialized, and NotifyHostMigrationFinished goes out only
        once every part has been reported. Returns (notifications, finished)."""
        t = blaze.HOST_MIGRATION_TYPE
        with self.lock:
            g = self.games.get(gid)
            if g is None or not g.migrating_from:
                return [], False
            parts = self._migration_parts(migration_type)
            if not parts & g.migration_pending:
                return [], False                     # repeated or unexpected report
            out = []
            if t["PLATFORM_HOST_MIGRATION"] in parts & g.migration_pending:
                out += self._platform_host_initialized(g)
            g.migration_pending -= parts
            if g.migration_pending:
                return out, False
            return out + self._complete_migration(g), True

    def finish_migration(self, gid: int) -> list:
        """Forces a running migration to an end (safety timer): whatever the new host never
        reported is sent now - NotifyPlatformHostInitialized if the platform part is still open,
        then NotifyHostMigrationFinished. Idempotent: a second call returns []."""
        with self.lock:
            g = self.games.get(gid)
            if g is None or not g.migrating_from:
                return []
            out = []
            if blaze.HOST_MIGRATION_TYPE["PLATFORM_HOST_MIGRATION"] in g.migration_pending:
                out += self._platform_host_initialized(g)
            return out + self._complete_migration(g)

    def take_migrations_started(self) -> list[int]:
        """Game ids whose migration started since the last call - the terminator arms a safety
        timer for each."""
        with self.lock:
            out, self.migrations_started = self.migrations_started, []
            return out

    def _leave_all(self, sess: Session, reason: int) -> list:
        out = []
        for gid in list(sess.games):
            g = self.games.get(gid)
            if g is not None:
                out += self.remove_player(g, sess.uid, reason)
        sess.games.clear()
        return out

    def mesh(self, gid: int, src_uid: int, tgt_uid: int, status: int) -> list:
        """updateMeshConnection: once the joiner and the host report the connection as CONNECTED,
        the join is complete -> NotifyGamePlayerStateChange (the player's new state) and
        NotifyPlayerJoinCompleted to all players of the game.

        Up to run-39 only notification 30 (JoinCompleted) went out, and the player state was
        changed only in this registry. So the joiner's client kept its player object in
        ACTIVE_CONNECTING and ~7 s after loading the world it dropped the game (frida-40:
        [game-lost] 6.83 s after joining). 116 carries the state to the clients; 30 stays,
        because it worked."""
        with self.lock:
            g = self.games.get(gid)
            if (g is None or src_uid == tgt_uid or status != blaze.MESH_STATUS["CONNECTED"]
                    or g.host_uid not in (src_uid, tgt_uid)):
                return []
            joiner = tgt_uid if src_uid == g.host_uid else src_uid
            p = g.players.get(joiner)
            if p is None or p["state"] == blaze.PLAYER_STATE["ACTIVE_CONNECTED"]:
                return []
            p["state"] = blaze.PLAYER_STATE["ACTIVE_CONNECTED"]
            notes = []
            if self.player_state_notify:
                notes.append(blaze.build_notify_game_player_state_change(gid, joiner, p["state"]))
            notes.append(blaze.build_notify_player_join_completed(gid, joiner))
            return [(r, n) for n in notes for r in self.members(g)]
