"""Shared server state for all connections: player sessions and games (multiplayer).

Up to run-27 the server assumed ONE player: a hardcoded identity, games as global
counters without a player list, notifications only to the player's own connection. This registry
lets a second player find the first one's public game and send notifications to ANOTHER connection.

Threads: the terminator handles every connection in a separate thread. The registry has one lock
(RLock), and every session has its own send lock - Wire.send_record is not thread-safe (RC4 state
and the record number in the MAC), and notifications to player B are sent by player A's thread.

Operations that change game state return a list of (session, frame) - the terminator sends them.

Identity: key = the Blaze client's IP address. Every player - local just like remote - gets a
permanent uid assigned once and stored in players.json, and a temporary name until the server
learns the real EA nickname from the GNAM field (createGame/startMatchmaking); from the next login
on, the nickname is already in the login. Local and remote uids come from disjoint pools, so they
never collide.

The real BlazeId from the EA App is NOT needed for anything - the client accepts whatever
originLogin tells it. Run-40 confirmed this: a remote player went through a whole session and saved
progress under a fully synthetic uid. Up to and including run-40 the local uid was the author's
hardcoded account, so everyone who started the server became that account and wrote progress
under someone else's id.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import zlib
from pathlib import Path

import blaze

LOCAL_IPS = {"127.0.0.1", "::1"}
LOCAL_KEY = "local"                  # key of the local player in players.json (instead of an IP address)
LOCAL_UID_BASE = 1_000_000_000_000   # uid pool for the player at the server machine
REMOTE_UID_BASE = 1_100_000_000_000  # uid pool for players from other addresses
DEFAULT_ADDR = (0x7F000001, 3659, 0x7F000001, 3659, 0)   # exip, export, inip, inport, maci


class Session:
    """One Blaze connection. The identity (uid, persona) is assigned by Lobby.login on 1/152."""

    def __init__(self, ip: str, send_raw) -> None:
        self.ip = ip
        self.uid = 0
        self.persona = ""
        self.persona_id = 0              # EA persona id (BUID from listUserEntitlements2)
        self.addr = DEFAULT_ADDR         # network address reported by the client
        self.games: set[int] = set()
        self.pending = None              # dispatch decision (createGame/resetDedicated) for _after_reply
        self.outbox: list = []           # notifications (session, frame) to send after the reply
        self.mm_timer = None             # threading.Timer with a deferred matchmaking decision
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
        self.local_id = int(local_id or 0)               # --local-id: overrides the generated uid
        self.local_persona = str(local_persona or "")    # --local-persona: overrides the nickname from GNAM
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
            except (OSError, ValueError):
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

    def _identity(self, ip: str) -> tuple[int, str]:
        """Uid and nickname for an address. Assigned once and stored in players.json, so a
        player's progress always lands under the same id. The local player lives under the
        LOCAL_KEY key, because its address (127.0.0.1) tells nothing apart."""
        local = ip in LOCAL_IPS
        key = LOCAL_KEY if local else ip
        entry = self.players.get(key)
        if local and entry and self.local_persona and entry.get("persona") != self.local_persona:
            # --local-persona overrides the stored nickname, not only when creating a new entry:
            # otherwise a once-stored "Player" would stay forever and the flag would look broken.
            entry["persona"] = self.local_persona
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
        return int(entry["uid"]), self.forced.get(ip) or str(entry["persona"])

    def login(self, sess: Session) -> list:
        """Assigns an identity to the session. When the same player already had a connection
        (re-login), the old one leaves its games - returns notifications for the other players."""
        with self.lock:
            sess.uid, sess.persona = self._identity(sess.ip)
            old = self.sessions.get(sess.uid)
            out = []
            if old is not None and old is not sess:
                old.alive = False
                out = self._leave_all(old, blaze.PLAYER_REMOVED_REASON["PLAYER_CONN_LOST"])
            self.sessions[sess.uid] = sess
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
            if not name or sess.ip in self.forced or name == sess.persona:
                return False
            sess.persona = name
            key = LOCAL_KEY if sess.is_local else sess.ip
            self.players[key] = {"uid": sess.uid, "persona": name}
            self._save_players()
            return True

    def persona_of(self, uid: int) -> str:
        with self.lock:
            s = self.sessions.get(uid)
            if s is not None:
                return s.persona
            for key, e in self.players.items():
                if e.get("uid") == uid:
                    # --player IP=NAME wins here too: after a disconnect the session is gone, and
                    # the migration log used to name the old host by its stored placeholder.
                    forced = self.forced.get("127.0.0.1" if key == LOCAL_KEY else key)
                    return forced or str(e.get("persona", uid))
            return str(uid)

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

    def find_public_game(self, sess: Session, avoid: set[int]) -> Game | None:
        """Another player's public game that can be joined: host connected, game already running
        (PRE_GAME/IN_GAME), not on the avoid list (CRIT.AGAM.GIDL), a free slot available, and no
        host migration so far (Game.migrated) - unless --join-migrated-games."""
        with self.lock:
            for g in sorted(self.games.values(), key=lambda x: x.gid):
                host = self.sessions.get(g.host_uid)
                if (g.public and g.gid not in avoid and sess.uid not in g.players
                        and (self.join_migrated or not g.migrated)
                        and host is not None and host.alive
                        and g.state in (blaze.GAME_STATE["PRE_GAME"], blaze.GAME_STATE["IN_GAME"])
                        and len(g.players) < int(g.params.get("max_players", 6))):
                    return g
            return None

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
