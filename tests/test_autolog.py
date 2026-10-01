"""NFS.getInGameRecommendations (2050/21): Autolog's rivals and their speed walls, from the
stored results. Until 1.0.12.1 the game got an empty acknowledgement and the speed walls showed
no rival. Offline, temporary data, no sockets."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "proto-lab"))

import blaze  # noqa: E402
import lobby  # noqa: E402
import tls_terminator  # noqa: E402

ME, RIVAL, OLD_ME = 1006431274704, 1802434674, 1012917074704


def stat(**values):
    return {"float": values, "int": {"vehicleUsed": 7}, "str": {}}


def fields(raw) -> dict:
    return {t.strip(): v for t, _w, v in raw}


class AutologTests(unittest.TestCase):
    def setUp(self):
        quiet = contextlib.redirect_stdout(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "stats").mkdir()
        mine = {"SpeedCameras00596c35": {"111": stat(speed=60.0), "0": stat()},
                "RacerRoadRule00596c35": {"222": stat(AverageSpeed=40.0)},
                "HotPursuitRacer7c5c8955": {"333": stat(eventTime=100.0)},
                "Collectables00596a25": {"999": stat(collected=1.0)}}      # not a speed wall
        theirs = {"SpeedCameras00596c96": {"111": stat(speed=55.0), "444": stat(speed=70.0)},
                  "RacerRoadRule00596c96": {"222": stat(AverageSpeed=45.0)},
                  "HotPursuitRacer7c5c8955": {"333": stat(eventTime=120.0)}}
        for pid, state in ((ME, mine), (RIVAL, theirs), (OLD_ME, theirs)):
            (root / "stats" / f"{pid}.json").write_text(json.dumps(state))
        (root / "players.json").write_text(json.dumps({
            "local": {"uid": ME, "persona": "Turbotoster"},
            f"ea:{RIVAL}": {"uid": RIVAL, "persona": "CustomNickname2"}}))   # OLD_ME: no entry
        self.lb = lobby.Lobby(root / "players.json", local_id=ME)
        patch = mock.patch.dict(tls_terminator._LOBBY, {"lobby": self.lb})
        patch.start()
        self.addCleanup(patch.stop)
        self.args = SimpleNamespace(reply_msgtype=0x10, data_dir=str(root), speedwall_relation=2,
                                    autolog_beat_type=blaze.RECOMMENDATION_BEAT_YOU,
                                    autolog_world_only=False, autolog_empty_rivals=False)
        self.sess = lobby.Session("127.0.0.1", lambda _frame: None)
        self.lb.login(self.sess)

    def ask(self) -> dict:
        request = blaze.Fire2(2050, 21, blaze.encode_tdf([blaze.f_int("BLID", ME)]), seq=9)
        reply = blaze.Fire2.decode(tls_terminator._autolog_recommendations(request, self.args, self.sess))
        self.assertEqual((reply.component, reply.command, reply.seq, reply.error), (2050, 21, 9, 0))
        return fields(blaze.decode_tdf(reply.payload))

    def test_the_rival_and_who_leads_where(self):
        rivals = [fields(r) for r in self.ask()["RILI"]]
        # one rival: the old id of the same person (no players.json entry) does not count
        self.assertEqual([(r["RIBL"], r["PENA"]) for r in rivals], [(RIVAL, "CustomNickname2")])
        # shared walls: 111 (60 > 55, mine), 222 (40 < 45, theirs), 333 (100 s < 120 s, mine)
        self.assertEqual((rivals[0]["PLSC"], rivals[0]["RISC"]), (2, 1))
        self.assertEqual(fields(rivals[0]["BLUS"])["URTY"], blaze.RELATION_FRIEND)

    def test_the_speed_wall_map_holds_the_rivals_walls(self):
        spwa = self.ask()["SPWA"]
        self.assertEqual(sorted(spwa), [111, 222, 333, 444])                # 444: the rival's own
        wall = fields(spwa[111])
        self.assertEqual(wall["SWID"], 111)
        relations = {fields(fields(r)["BLUS"])["BLIS"]: fields(fields(r)["BLUS"])["URTY"]
                     for r in wall["ROWS"]}
        self.assertEqual(relations, {ME: blaze.RELATION_LOCAL_PLAYER, RIVAL: blaze.RELATION_FRIEND})

    def test_beat_you_only_where_the_rival_leads(self):
        rival = fields(self.ask()["RILI"][0])
        recs = [fields(r) for r in rival["RECM"]]
        self.assertEqual([r["SWID"] for r in recs], [222])                # 45 > 40 AverageSpeed
        rec = recs[0]
        self.assertEqual((rec["RETY"], rec["TITL"], rec["TABL"], rec["TANA"]),
                         (blaze.RECOMMENDATION_BEAT_YOU, "ID_REC_TITLE_BEAT", RIVAL, "CustomNickname2"))
        self.assertEqual(rec["STAF"], {"AverageSpeed": 45.0})              # the score to beat
        self.assertEqual(fields(rec["BLUS"])["BLIS"], RIVAL)

    def rewrite_theirs(self, state: dict) -> None:
        (Path(self.args.data_dir) / "stats" / f"{RIVAL}.json").write_text(json.dumps(state))
        tls_terminator._player_store(self.args)._cache.clear()

    def test_beat_you_on_events_too(self):
        # the rival is ahead on the event 333 too (90 s < 100 s): events come first
        self.rewrite_theirs({"RacerRoadRule00596c96": {"222": stat(AverageSpeed=45.0)},
                             "HotPursuitRacer7c5c8955": {"333": stat(eventTime=90.0)}})
        rival = fields(self.ask()["RILI"][0])
        self.assertEqual(rival["RISC"], 2)
        self.assertEqual([fields(r)["SWID"] for r in rival["RECM"]], [333, 222])
        self.args.autolog_world_only = True                               # the 1.0.12.4 behaviour
        rival = fields(self.ask()["RILI"][0])
        self.assertEqual([fields(r)["SWID"] for r in rival["RECM"]], [222])

    def test_a_player_alone_gets_the_bare_acknowledgement(self):
        (Path(self.args.data_dir) / "stats" / f"{RIVAL}.json").unlink()
        (Path(self.args.data_dir) / "stats" / f"{OLD_ME}.json").unlink()
        tls_terminator._player_store(self.args)._cache.clear()
        self.assertEqual(self.ask(), {})

    def test_ten_events_first_then_speed_walls_up_to_twenty(self):
        def lead_on(cameras: int, events: int):
            root = Path(self.args.data_dir) / "stats"
            mine = {"SpeedCameras00596c35": {str(5000 + n): stat(speed=10.0) for n in range(cameras)},
                    "DirectedRaces7c5c8955": {str(6000 + n): stat(eventTime=200.0) for n in range(events)}}
            theirs = {"SpeedCameras00596c35": {str(5000 + n): {**stat(speed=99.0), "updated": n}
                                               for n in range(cameras)},
                      "DirectedRaces7c5c8955": {str(6000 + n): {**stat(eventTime=100.0), "updated": n}
                                                for n in range(events)}}
            (root / f"{ME}.json").write_text(json.dumps(mine))
            (root / f"{RIVAL}.json").write_text(json.dumps(theirs))
            tls_terminator._player_store(self.args)._cache.clear()
            return [fields(r)["SWID"] for r in fields(self.ask()["RILI"][0])["RECM"]]
        self.assertEqual(lead_on(25, 15), [6000 + n for n in range(14, 4, -1)]      # 10 newest events
                         + [5000 + n for n in range(24, 14, -1)])                    # + 10 newest cameras
        self.assertEqual(lead_on(25, 3), [6002, 6001, 6000] + [5000 + n for n in range(24, 7, -1)])

    def test_a_rival_with_nothing_to_beat_is_left_out(self):
        # I lead on every shared wall: an empty RECM crashes the game (confirmed 02.10)
        self.rewrite_theirs({"SpeedCameras00596c96": {"111": stat(speed=55.0), "444": stat(speed=70.0)},
                             "HotPursuitRacer7c5c8955": {"333": stat(eventTime=120.0)}})
        # no rival left: the bare acknowledgement, not an empty RILI (never seen by the game);
        # the walls still come with getInGameSpeedWalls
        self.assertEqual(self.ask(), {})
        self.args.autolog_empty_rivals = True
        rival = fields(self.ask()["RILI"][0])
        self.assertEqual((rival["RIBL"], rival["PLSC"], rival["RISC"], rival["RECM"]), (RIVAL, 2, 0, []))

    def test_at_most_twenty_newest_beat_you_entries_per_rival(self):
        store = tls_terminator._player_store(self.args)
        root = Path(self.args.data_dir) / "stats"
        many_mine = {"SpeedCameras00596c35": {str(5000 + n): stat(speed=10.0) for n in range(25)}}
        many_theirs = {"SpeedCameras00596c35": {str(5000 + n): {**stat(speed=99.0), "updated": n}
                                                for n in range(25)}}
        (root / f"{ME}.json").write_text(json.dumps(many_mine))
        (root / f"{RIVAL}.json").write_text(json.dumps(many_theirs))
        store._cache.clear()
        rival = fields(self.ask()["RILI"][0])
        self.assertEqual(rival["RISC"], 25)
        swids = [fields(r)["SWID"] for r in rival["RECM"]]
        self.assertEqual(swids, [5000 + n for n in range(24, 4, -1)])     # 20, newest first

    def test_special_guests_and_playlist_are_well_formed_and_empty(self):
        def reply(command, payload):
            fr = blaze.Fire2(2050, command, blaze.encode_tdf(payload), seq=4)
            out = blaze.Fire2.decode(tls_terminator._autolog_other(fr, self.args, self.sess))
            self.assertEqual((out.command, out.seq, out.error), (command, 4, 0))
            return fields(blaze.decode_tdf(out.payload))
        guests = reply(39, [blaze.f_int("BLIS", ME)])
        self.assertEqual((guests["BLIS"], guests["SPGT"], guests["STAI"]), ([], 0, {}))
        playlist = reply(29, [blaze.f_int("BLID", ME)])
        self.assertEqual((playlist["BLID"], playlist["PLAY"], playlist["ROWS"]), (ME, [], []))
        walls = reply(41, [blaze.f_list_int("SWIS", [111, 222])])
        self.assertEqual([fields(w)["SWID"] for w in walls["ROWS"]], [111, 222])

    def test_the_map_stops_before_the_fire2_limit(self):
        rows = [{"blaze_id": n, "persona": "P" * 30, "float": {"speed": 1.0}} for n in range(50)]
        walls = [(1000 + n, rows) for n in range(200)]
        frame, sent = blaze.build_in_game_recommendations_response(1, [], walls, local_id=0)
        self.assertLess(sent, 200)
        self.assertLessEqual(len(frame) - blaze.FIRE2_HDR, blaze.RECOMMENDATIONS_MAX_PAYLOAD)
        self.assertEqual(len(fields(blaze.decode_tdf(blaze.Fire2.decode(frame).payload))["SPWA"]), sent)


if __name__ == "__main__":
    unittest.main()
