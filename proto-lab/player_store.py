"""Trwaly zapis postepu gracza z raportow GameReporting (komponent 28).

Co wiemy o raportach (run-24: 473 szt., wszystkie zdekodowane):
    SubmitGameReportRequest {FNSH, PRVT (variable, pusty), RPRT {GAME (variable), GRID, GTYP}}
    RPRT.GAME = obiekt tdfId 0xf3e30e29 { GAME { PLYR map<blazeid, {ENTI STAF STAI STAS}> } }
GTYP to nazwa kategorii + 8 znakow hex (np. 'PlayerStats5d618385', 'Collectables00596a25'),
ENTI - id obiektu w kategorii (znajdzka, auto, event; 0 = kategoria jako calosc), a
STAI/STAF/STAS - mapy nazwa statystyki -> wartosc int/float/string.

Raport niesie STAN, nie przyrost: PlayerStats ma np. CarsPurchasedRacer=2, RacerCredits=156045,
a kolejne raporty powtarzaja te same liczby. Stan = ostatnia wartosc kazdej statystyki.
Wartosc -2147483648 (INT_MIN) wystepuje w czesci raportow (np. WebPlayerStatsc7d870d3
BestBustScore) - znaczenia nie znamy, zapisujemy ja jak kazda inna.

Na dysku (domyslnie ~\\TurboRivals\\data - poza repo i poza OneDrive, ktory potrafi zablokowac
plik podmieniany kilka razy na sekunde):
    stats/<blazeid>.json     stan: kategoria -> ENTI -> {int, float, str, updated, reports}
    reports/<blazeid>.jsonl  dziennik kazdego raportu - nic nie ginie, gdyby model stanu
                             okazal sie zly i trzeba go bylo odtworzyc od nowa
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import blaze

# Nie %LOCALAPPDATA%: Python ze Sklepu Microsoft (python.exe z WindowsApps - tak jest u nas) po
# cichu przekierowuje zapisy z AppData\Local do Packages\PythonSoftwareFoundation.Python.*\
# LocalCache\Local, wiec w run-25 plikow nie bylo tam, gdzie wskazywala sciezka. Katalog domowy
# nie jest wirtualizowany i lezy poza OneDrive.
DATA_DIR = Path.home() / "TurboRivals" / "data"
REPORT_TDF_ID = 0xF3E30E29        # klasa obiektu RPRT.GAME we wszystkich raportach run-24


def _fields(fields) -> dict:
    return {tag.strip(): val for tag, _wtype, val in fields}


def parse_game_report(payload: bytes) -> dict:
    """Payload zadania 28/2 -> {category, finished, grid, tdf_id, players}, gdzie
    players = {blazeid: {entity, int, float, str}}. ValueError/KeyError przy innym ukladzie."""
    top = _fields(blaze.decode_tdf(payload))
    rprt = _fields(top["RPRT"])
    game = rprt.get("GAME")
    if not (isinstance(game, tuple) and game[0] == "variable" and game[1] is not None):
        raise ValueError("RPRT.GAME bez obiektu")
    plyr = _fields(_fields(game[2])["GAME"]).get("PLYR") or {}
    if not isinstance(plyr, dict):
        raise ValueError("PLYR nie jest mapa blazeid -> gracz")
    players = {}
    for pid, pfields in plyr.items():
        pf = _fields(pfields)
        players[int(pid)] = {"entity": int(pf.get("ENTI", 0)),
                             "int": dict(pf.get("STAI") or {}),
                             "float": dict(pf.get("STAF") or {}),
                             "str": dict(pf.get("STAS") or {})}
    return {"category": str(rprt.get("GTYP", "")), "finished": top.get("FNSH", 0),
            "grid": rprt.get("GRID", 0), "tdf_id": game[1], "players": players}


class PlayerStore:
    """Stan statystyk graczy. Jeden obiekt na proces - terminator obsluguje kazde polaczenie
    w osobnym watku, stad blokada wokol odczytu i zapisu."""

    def __init__(self, root: Path | str = DATA_DIR):
        self.root = Path(root)
        self._lock = threading.Lock()
        self._cache: dict[int, dict] = {}

    def _state_path(self, pid: int) -> Path:
        return self.root / "stats" / f"{pid}.json"

    def _load(self, pid: int) -> dict:
        if pid not in self._cache:
            p = self._state_path(pid)
            self._cache[pid] = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        return self._cache[pid]

    def state(self, pid: int) -> dict:
        """Kopia stanu gracza: kategoria (GTYP) -> str(ENTI) -> {int, float, str, ...}."""
        with self._lock:
            return json.loads(json.dumps(self._load(pid)))

    def rows_for_entity(self, entity: int) -> list[dict]:
        """Wiersze speed walla: dla kazdego gracza z zapisanym obiektem ENTI == entity - mapy
        statystyk scalone ze wszystkich kategorii, w ktorych ten obiekt wystepuje (w run-25 zawsze
        jedna: SpeedCameras*, RacerRoadRule* ...). Zwraca [{blaze_id, int, float, str}]."""
        key = str(int(entity))
        rows = []
        with self._lock:
            stats_dir = self.root / "stats"
            pids = {int(p.stem) for p in stats_dir.glob("*.json") if p.stem.isdigit()} \
                if stats_dir.exists() else set()
            for pid in sorted(pids | set(self._cache)):
                merged = {"int": {}, "float": {}, "str": {}}
                found = False
                for ents in self._load(pid).values():
                    slot = ents.get(key)
                    if slot:
                        found = True
                        for kind in merged:
                            merged[kind].update(slot[kind])
                if found:
                    rows.append({"blaze_id": pid, **merged})
        return rows

    def record(self, report: dict) -> list[int]:
        """Dopisuje raport do dziennika i scala go ze stanem. Zwraca blazeid zapisanych graczy."""
        now = int(time.time())
        with self._lock:
            for pid, pdata in report["players"].items():
                journal = self.root / "reports" / f"{pid}.jsonl"
                journal.parent.mkdir(parents=True, exist_ok=True)
                with journal.open("a", encoding="utf-8") as f:
                    f.write(json.dumps({"t": now, "category": report["category"], **pdata}) + "\n")
                state = self._load(pid)
                slot = state.setdefault(report["category"], {}).setdefault(
                    str(pdata["entity"]), {"int": {}, "float": {}, "str": {}, "reports": 0})
                for kind in ("int", "float", "str"):
                    slot[kind].update(pdata[kind])
                slot["updated"] = now
                slot["reports"] += 1
                self._save(pid, state)
            return list(report["players"])

    def _save(self, pid: int, state: dict) -> None:
        p = self._state_path(pid)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")
        for attempt in range(5):
            try:
                os.replace(tmp, p)
                return
            except PermissionError:        # antywirus/indeksowanie trzyma plik - chwila i ponow
                time.sleep(0.05 * (attempt + 1))
        os.replace(tmp, p)
