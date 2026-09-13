"""Wspolny stan serwera dla wszystkich polaczen: sesje graczy i gry (multiplayer).

Do run-27 serwer zakladal JEDNEGO gracza: tozsamosc na sztywno (PayTonkaaa), gry jako globalne
liczniki bez listy graczy, notyfikacje tylko do wlasnego polaczenia. Ten rejestr pozwala drugiemu
graczowi znalezc publiczna gre pierwszego i wysylac notyfikacje do INNEGO polaczenia.

Watki: terminator obsluguje kazde polaczenie w osobnym watku. Rejestr ma jedna blokade (RLock), a
kazda sesja wlasna blokade wysylki - Wire.send_record nie jest bezpieczne miedzy watkami (stan RC4
i numer rekordu w MAC), a notyfikacje do gracza B wysyla watek gracza A.

Operacje zmieniajace stan gier zwracaja liste (sesja, ramka) - wysyla je terminator.

Tozsamosc: klucz = adres IP klienta Blaze. Gracz lokalny (127.0.0.1) to zawsze PayTonkaaa z BlazeId
z EA App - pod tym id lezy jego zapisany postep. Gracz z innego adresu dostaje staly uid z puli
rozlacznej z lokalnym i nazwe tymczasowa; prawdziwy nick EA serwer poznaje z pola GNAM
(createGame/startMatchmaking) i zapisuje w players.json - od kolejnego logowania jest w loginie.
"""
from __future__ import annotations

import json
import os
import threading
import zlib
from pathlib import Path

import blaze

LOCAL_IPS = {"127.0.0.1", "::1"}
LOCAL_USER_ID = REDACTED_EA_USER_ID        # BlazeId gracza lokalnego (UserId z LSX EA App)
LOCAL_PERSONA = "PayTonkaaa"
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
        self.pending = None              # decyzja dispatch (gra/matchmaking) dla _after_reply
        self.outbox: list = []           # notyfikacje (sesja, ramka) do wyslania po odpowiedzi
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
                 forced: dict[str, str] | None = None) -> None:
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
            print(f"  [lobby] nie zapisalem {self.players_file}: {e}")

    def _identity(self, ip: str) -> tuple[int, str]:
        if ip in LOCAL_IPS:
            return LOCAL_USER_ID, self.forced.get(ip) or LOCAL_PERSONA
        entry = self.players.get(ip)
        if not entry:
            used = {e.get("uid") for e in self.players.values()} | {LOCAL_USER_ID}
            uid = REMOTE_UID_BASE + zlib.crc32(ip.encode()) % 1_000_000_000
            while uid in used:
                uid += 1
            entry = {"uid": uid, "persona": f"Gracz_{ip.rsplit('.', 1)[-1]}"}
            self.players[ip] = entry
            self._save_players()
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
        """Nick EA z gry (GNAM) dla gracza z innego komputera - zapamietany na kolejne logowania."""
        name = (name or "").strip()
        with self.lock:
            if not name or sess.is_local or sess.ip in self.forced or name == sess.persona:
                return False
            sess.persona = name
            self.players[sess.ip] = {"uid": sess.uid, "persona": name}
            self._save_players()
            return True

    def persona_of(self, uid: int) -> str:
        with self.lock:
            s = self.sessions.get(uid)
            if s is not None:
                return s.persona
            if uid == LOCAL_USER_ID:
                return LOCAL_PERSONA
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
        sprzataniem gry po stronie klienta. Wyszedl host, a ktos zostal -> gra usunieta i
        NotifyGameRemoved dla reszty (migracji hosta nie robimy)."""
        with self.lock:
            if uid not in g.players:
                return []
            del g.players[uid]
            s = self.sessions.get(uid)
            if s is not None:
                s.games.discard(g.gid)
            others = self.members(g)
            note = blaze.build_notify_player_removed(g.gid, uid, reason)
            out = [(r, note) for r in others]
            if not g.players:
                self.games.pop(g.gid, None)
            elif uid == g.host_uid:
                gone = blaze.build_notify_game_removed(
                    g.gid, blaze.GAME_DESTRUCTION_REASON["HOST_LEAVING"])
                for r in others:
                    out.append((r, gone))
                    r.games.discard(g.gid)
                self.games.pop(g.gid, None)
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
        zakonczone -> NotifyPlayerJoinCompleted do wszystkich graczy gry."""
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
            note = blaze.build_notify_player_join_completed(gid, joiner)
            return [(r, note) for r in self.members(g)]
