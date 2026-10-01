"""Persistent storage of player progress from GameReporting reports (component 28).

What we know about the reports (run-24: 473 of them, all decoded):
    SubmitGameReportRequest {FNSH, PRVT (variable, pusty), RPRT {GAME (variable), GRID, GTYP}}
    RPRT.GAME = obiekt tdfId 0xf3e30e29 { GAME { PLYR map<blazeid, {ENTI STAF STAI STAS}> } }
GTYP is the category name + 8 hex characters (e.g. 'PlayerStats5d618385', 'Collectables00596a25'),
ENTI - id of the object within the category (collectible, car, event; 0 = the category as a whole),
and STAI/STAF/STAS - maps of stat name -> int/float/string value.

A report carries STATE, not a delta: PlayerStats has e.g. CarsPurchasedRacer=2, RacerCredits=156045,
and subsequent reports repeat the same numbers. State = the last value of every stat.
The value -2147483648 (INT_MIN) shows up in some reports (e.g. WebPlayerStatsc7d870d3
BestBustScore) - we do not know what it means, we store it like any other.

On disk (by default ~\\TurboRivals\\data - outside the repo and outside OneDrive, which can lock
a file that is replaced several times per second):
    stats/<blazeid>.json     state: category -> ENTI -> {int, float, str, updated, reports}
    reports/<blazeid>.jsonl  journal of every report - nothing is lost, should the state model
                             turn out wrong and need to be rebuilt from scratch
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import blaze

# Not %LOCALAPPDATA%: Python from the Microsoft Store (python.exe from WindowsApps - which is our
# setup) silently redirects writes from AppData\Local to Packages\PythonSoftwareFoundation.Python.*\
# LocalCache\Local, so in run-25 the files were not where the path pointed. The home directory
# is not virtualized and lies outside OneDrive.
DATA_DIR = Path.home() / "TurboRivals" / "data"
REPORT_TDF_ID = 0xF3E30E29        # class of the RPRT.GAME object in all run-24 reports
# Report categories whose objects are speed walls (names carry a hash suffix, e.g.
# SpeedCameras00596c35): the SpeedWallType_* values of the binary, cops' events included.
SPEEDWALL_CATEGORIES = ("SpeedCameras", "RacerRoadRule", "JumpSpots", "Speedlist", "Hunted",
                        "DirectedRaces", "HotPursuit", "RapidResponse", "TimeAttack",
                        "Interceptor", "DriftCorners")
# The speed walls out in the world (cameras, zones, jumps) - the rest are events.
WORLD_SPEEDWALL_CATEGORIES = ("SpeedCameras", "RacerRoadRule", "JumpSpots")

# A speed wall row's main result: (stat, value, lower_is_better). The categories' stat names
# (stats/*.json): SpeedCameras speed, RacerRoadRule AverageSpeed, JumpSpots distance, events
# eventTime - the only one where less is better.
PRIMARY_STATS = (("eventTime", True), ("speed", False), ("AverageSpeed", False), ("distance", False))


def primary_stat(row: dict | None) -> tuple[str, float, bool] | None:
    if not row:
        return None
    for stat, lower in PRIMARY_STATS:
        for kind in ("float", "int"):
            if stat in row.get(kind, {}):
                return stat, float(row[kind][stat]), lower
    return None


def _slot_rank(slot: dict) -> tuple:
    """Order of a player's results on one object: the better main result first, then the newer."""
    main = primary_stat(slot)
    updated = int(slot.get("updated", 0) or 0)
    if not main:
        return 0, 0.0, updated
    return 1, -main[1] if main[2] else main[1], updated


def _fields(fields) -> dict:
    return {tag.strip(): val for tag, _wtype, val in fields}


def parse_game_report(payload: bytes) -> dict:
    """Payload of request 28/2 -> {category, finished, grid, tdf_id, players}, where
    players = {blazeid: {entity, int, float, str}}. ValueError/KeyError on any other layout."""
    top = _fields(blaze.decode_tdf(payload))
    rprt = _fields(top["RPRT"])
    game = rprt.get("GAME")
    if not (isinstance(game, tuple) and game[0] == "variable" and game[1] is not None):
        raise ValueError("RPRT.GAME without an object")
    plyr = _fields(_fields(game[2])["GAME"]).get("PLYR") or {}
    if not isinstance(plyr, dict):
        raise ValueError("PLYR is not a blazeid -> player map")
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
    """Player stats state. One object per process - the terminator handles every connection
    in a separate thread, hence the lock around reads and writes."""

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
        """Copy of a player state: category (GTYP) -> str(ENTI) -> {int, float, str, ...}."""
        with self._lock:
            return json.loads(json.dumps(self._load(pid)))

    def speedwall_ids(self, pid: int, world_only: bool = False) -> set[int]:
        """Ids (ENTI) of the speed walls this player has a result on: the objects of the
        report categories that are speed wall types in the binary (SpeedWallType_SpeedCamera,
        _RoadRule, _Jump, _Speedlist, _Race, _HotPursuit, _RapidResponse, _Interceptor, ...) - the
        cops' events included, unless world_only. ENTI 0 is a category as a whole, not an object."""
        kinds = WORLD_SPEEDWALL_CATEGORIES if world_only else SPEEDWALL_CATEGORIES
        with self._lock:
            state = self._load(pid)
            return {int(e) for cat, ents in state.items() if cat.startswith(kinds)
                    for e in ents if e.isdigit() and e != "0"}

    def rows_for_entity(self, entity: int) -> list[dict]:
        """Speed wall rows: for every player with a stored object ENTI == entity, the stat maps
        of one category. An object can sit in several (an event in DirectedRaces7c5c0574 and
        DirectedRaces7c5c8955: two attempts with their own times); the row is the one with the
        better main result, then the newer - never fields of one attempt mixed with another's.
        Returns [{blaze_id, int, float, str, updated}], updated = that report's time (0 if none)."""
        key = str(int(entity))
        rows = []
        with self._lock:
            stats_dir = self.root / "stats"
            pids = {int(p.stem) for p in stats_dir.glob("*.json") if p.stem.isdigit()} \
                if stats_dir.exists() else set()
            for pid in sorted(pids | set(self._cache)):
                slots = [ents[key] for ents in self._load(pid).values() if ents.get(key)]
                if slots:
                    best = max(slots, key=_slot_rank)
                    rows.append({"blaze_id": pid,
                                 **{kind: dict(best.get(kind, {})) for kind in ("int", "float", "str")},
                                 "updated": int(best.get("updated", 0) or 0)})
        return rows

    def record(self, report: dict) -> list[int]:
        """Appends the report to the journal and merges it into the state. Returns the saved players' blazeids."""
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
            except PermissionError:        # antivirus/indexing holds the file - wait a moment and retry
                time.sleep(0.05 * (attempt + 1))
        os.replace(tmp, p)
