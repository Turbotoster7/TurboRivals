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

    @property
    def public(self) -> bool:
        return self.params.get("attributes", {}).get("gameMembershipRequirements") == "Public"


class Lobby:
    def __init__(self, players_file: Path | str | None = None,
                 forced: dict[str, str] | None = None,
                 player_state_notify: bool = True,
                 local_id: int = 0, local_persona: str = "") -> None:
        self.player_state_notify = player_state_notify   # --no-player-state-notify (A/B)
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
            for e in self.players.values():
                if e.get("uid") == uid:
                    return str(e.get("persona", uid))
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

    def find_public_game(self, sess: Session, avoid: set[int]) -> Game | None:
        """Gra publiczna innego gracza, do ktorej mozna dolaczyc: host polaczony, gra juz trwa
        (PRE_GAME/IN_GAME), nie na liscie unikanych (CRIT.AGAM.GIDL), jest wolne miejsce."""
        with self.lock:
            for g in sorted(self.games.values(), key=lambda x: x.gid):
                host = self.sessions.get(g.host_uid)
                if (g.public and g.gid not in avoid and sess.uid not in g.players
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

        Wyszedl host, a ktos zostal -> gra usunieta i pozostali dostaja SAMO NotifyGameRemoved
        (migracji hosta nie robimy). 15.09 (log-29, sesja 4) gracz dostal najpierw NotifyPlayerRemoved
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
            if not g.players:
                self.games.pop(g.gid, None)
                return []
            if uid == g.host_uid:
                gone = blaze.build_notify_game_removed(
                    g.gid, blaze.GAME_DESTRUCTION_REASON["HOST_LEAVING"])
                for r in others:
                    r.games.discard(g.gid)
                self.games.pop(g.gid, None)
                return [(r, gone) for r in others]
            note = blaze.build_notify_player_removed(g.gid, uid, reason)
            return [(r, note) for r in others]

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
