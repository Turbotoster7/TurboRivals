"""Wspolny stan serwera dla wszystkich polaczen: sesje graczy i gry (multiplayer).

Do run-27 serwer zakladal JEDNEGO gracza: tozsamosc na sztywno, gry jako globalne
liczniki bez listy graczy, notyfikacje tylko do wlasnego polaczenia. Ten rejestr pozwala drugiemu
graczowi znalezc publiczna gre pierwszego i wysylac notyfikacje do INNEGO polaczenia.

Watki: terminator obsluguje kazde polaczenie w osobnym watku. Rejestr ma jedna blokade (RLock), a
kazda sesja wlasna blokade wysylki - Wire.send_record nie jest bezpieczne miedzy watkami (stan RC4
i numer rekordu w MAC), a notyfikacje do gracza B wysyla watek gracza A.

Operacje zmieniajace stan gier zwracaja liste (sesja, ramka) - wysyla je terminator.

Tozsamosc: klucz = adres IP klienta Blaze. Kazdy gracz - lokalny tak samo jak zdalny - dostaje
staly uid nadany raz i zapisany w players.json, a nazwe tymczasowa do czasu, az serwer pozna
prawdziwy nick EA z pola GNAM (createGame/startMatchmaking); od kolejnego logowania nick jest juz
w loginie. Uid lokalne i zdalne pochodza z rozlacznych pul, wiec nigdy nie koliduja.

Prawdziwe BlazeId z EA App NIE jest do niczego potrzebne - klient przyjmuje to, co powie mu
originLogin. Run-40 to potwierdzil: gracz zdalny przeszedl cala sesje i zapisal postep na uidzie
w pelni syntetycznym. Do run-40 wlacznie uid lokalny byl zahardkodowanym kontem autora, przez co
kazdy, kto odpalil serwer, stawal sie nim i pisal postep pod cudzym id.
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
LOCAL_KEY = "local"                  # klucz gracza lokalnego w players.json (zamiast adresu IP)
LOCAL_UID_BASE = 1_000_000_000_000   # pula uid dla gracza przy serwerze
REMOTE_UID_BASE = 1_100_000_000_000  # pula uid dla graczy z innych adresow
DEFAULT_ADDR = (0x7F000001, 3659, 0x7F000001, 3659, 0)   # exip, export, inip, inport, maci


class Session:
    """Jedno polaczenie Blaze. Tozsamosc (uid, persona) nadaje Lobby.login przy 1/152."""

    def __init__(self, ip: str, send_raw) -> None:
        self.ip = ip
        self.uid = 0
        self.persona = ""
        self.persona_id = 0              # id persony EA (BUID z listUserEntitlements2)
        self.addr = DEFAULT_ADDR         # adres sieciowy zgloszony przez klienta
        self.games: set[int] = set()
        self.pending = None              # decyzja dispatch (createGame/resetDedicated) dla _after_reply
        self.outbox: list = []           # notyfikacje (sesja, ramka) do wyslania po odpowiedzi
        self.mm_timer = None             # threading.Timer z odlozona decyzja matchmakingu
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
        """Notyfikacja z wlasnym, rosnacym msgId tej sesji. Zwraca nadany msgId."""
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
        self.params = params             # argumenty gry dla blaze.build_notify_game_setup
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
        self.local_id = int(local_id or 0)               # --local-id: nadpisuje generowany uid
        self.local_persona = str(local_persona or "")    # --local-persona: nadpisuje nick z GNAM
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

    # ------------------------------------------------------------ tozsamosc
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
        """Uid i nick dla adresu. Nadane raz i zapisane w players.json, zeby postep gracza zawsze
        trafial pod to samo id. Gracz lokalny siedzi pod kluczem LOCAL_KEY, bo jego adres
        (127.0.0.1) nic nie rozroznia."""
        local = ip in LOCAL_IPS
        key = LOCAL_KEY if local else ip
        entry = self.players.get(key)
        if local and entry and self.local_persona and entry.get("persona") != self.local_persona:
            # --local-persona nadpisuje zapisany nick, nie tylko zaklada nowy wpis: inaczej raz
            # zapisany "Gracz" zostawalby na zawsze, a flaga wygladalaby na zepsuta.
            entry["persona"] = self.local_persona
            self._save_players()
        if not entry:
            used = {e.get("uid") for e in self.players.values()}
            if local:
                # Nazwa komputera, a nie adres: 127.0.0.1 jest takie samo u wszystkich, a chcemy
                # uid stabilny miedzy uruchomieniami i rozny miedzy instalacjami.
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
        """Nadaje sesji tozsamosc. Gdy ten sam gracz mial juz polaczenie (ponowne logowanie), stare
        wychodzi ze swoich gier - zwraca notyfikacje dla pozostalych graczy."""
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
        """Nick EA z gry (GNAM) - zapamietany na kolejne logowania. Dziala takze dla gracza
        lokalnego: to jedyne zrodlo jego prawdziwego nicku, ktory do run-40 byl zahardkodowany
        (LSX z EA App podaje UserId dopiero w SetPresence, czyli po naszym originLogin)."""
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

    # ------------------------------------------------------------ gry
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
        """Gra publiczna innego gracza, do ktorej mozna dolaczyc: host polaczony, gra juz trwa
        (PRE_GAME/IN_GAME), nie na liscie unikanych (CRIT.AGAM.GIDL), jest wolne miejsce, i nie
        przeszla migracji hosta (Game.migrated) - chyba ze --join-migrated-games."""
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
        """Gracze gry w formacie builderow blaze: {uid, persona, slot, state, addr}."""
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
        """Usuwa gracza z gry. Notyfikacje dostaja POZOSTALI gracze - nie wychodzacy: w run-23..27
        klient wychodzil sam i dzialal bez niej, a notyfikacja o wlasnym wyjsciu grozi podwojnym
        sprzataniem gry po stronie klienta.

        Wyszedl host, a ktos zostal -> migracja hosta (_start_migration). Z --no-host-migration:
        gra usunieta i pozostali dostaja SAMO NotifyGameRemoved. 15.09 (log-29, sesja 4) gracz dostal najpierw NotifyPlayerRemoved
        hosta, zaraz po nim NotifyGameRemoved, i gra wywalila sie skokiem pod NULL. Hipoteza: klient
        sprzata gre bez hosta juz po PlayerRemoved, a GameRemoved trafia w usuniety obiekt."""
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
        """updateMeshConnection: gdy dolaczajacy i host zglosza polaczenie CONNECTED, dolaczanie jest
        zakonczone -> NotifyGamePlayerStateChange (nowy stan gracza) i NotifyPlayerJoinCompleted
        do wszystkich graczy gry.

        Do run-39 szla sama notyfikacja 30 (JoinCompleted), a stan gracza zmienialismy wylacznie
        w tym rejestrze. Klient dolaczajacego trzymal wiec swoj obiekt gracza w ACTIVE_CONNECTING
        i ~7 s po wczytaniu swiata kasowal gre (frida-40: [gra-utracona] 6,83 s po dolaczeniu).
        116 niesie stan do klientow; 30 zostaje, bo dzialalo."""
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
