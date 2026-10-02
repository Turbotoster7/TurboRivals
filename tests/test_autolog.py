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
        # autolog_everyone: most tests here are about stored rivals; the session-only default
        # (1.1.2) has tests of its own below
        self.args = SimpleNamespace(reply_msgtype=0x10, data_dir=str(root), speedwall_relation=2,
                                    autolog_beat_type=blaze.RECOMMENDATION_BEAT_YOU,
                                    autolog_world_only=False, autolog_empty_rivals=False,
                                    autolog_everyone=True)
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
                         (blaze.RECOMMENDATION_BEAT_YOU, "ID_BEAT_YOU_TITLE", RIVAL, "CustomNickname2"))
        self.assertEqual(rec["STAF"], {"AverageSpeed": 45.0})              # the score to beat
        self.assertEqual(fields(rec["BLUS"])["BLIS"], RIVAL)
        # empty, the card showed "String not on Autolog Yet"
        self.assertEqual((rec["STOT"], rec["STOB"]),
                         ("ID_BEAT_YOU_STORY_ONE_TOP", "ID_BEAT_YOU_STORY_ONE_BOTTOM"))

    def test_title_and_stories_are_story_templates(self):
        # The game looks TITL/STOT/STOB up in its table of Autolog story templates (0x93af50);
        # anything else reads "String not on Autolog Yet" - TITL did at a speed camera (02.10).
        for rec_type in (blaze.RECOMMENDATION_BEAT_YOU, blaze.RECOMMENDATION_HOT,
                         blaze.RECOMMENDATION_POPULAR):
            keys = (blaze.RECOMMENDATION_TITLES[rec_type], *blaze.RECOMMENDATION_STORIES[rec_type])
            for key in keys:
                self.assertIn(key, blaze.AUTOLOG_STORY_TEMPLATES)

    def test_no_beat_you_on_a_speedlist(self):
        # the rival leads on a Speedlist too: it counts in the score, but the card cannot name a
        # Speedlist ("INVALID SPEEDWALL: 12", no route), so it gets no entry
        root = Path(self.args.data_dir) / "stats"
        mine = json.loads((root / f"{ME}.json").read_text())
        mine["Speedlist7c5c8955"] = {"555": stat(eventTime=300.0)}
        (root / f"{ME}.json").write_text(json.dumps(mine))
        self.rewrite_theirs({"RacerRoadRule00596c96": {"222": stat(AverageSpeed=45.0)},
                             "Speedlist7c5c8955": {"555": stat(eventTime=200.0)}})
        rival = fields(self.ask()["RILI"][0])
        self.assertEqual(rival["RISC"], 2)
        self.assertEqual([fields(r)["SWID"] for r in rival["RECM"]], [222])

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

    def test_a_stored_player_can_be_made_a_rival(self):
        # a player under a synthetic uid (players.json key = its address) is no rival offline...
        guest = 1100128479067
        (Path(self.args.data_dir) / "stats" / f"{guest}.json").write_text(json.dumps(
            {"RacerRoadRule00596c96": {"222": stat(AverageSpeed=50.0)}}))
        self.lb.players["26.101.169.15"] = {"uid": guest, "persona": "Player_15"}
        tls_terminator._player_store(self.args)._cache.clear()
        self.assertEqual([fields(r)["RIBL"] for r in self.ask()["RILI"]], [RIVAL])
        # ...unless --autolog-rival puts it there, to reproduce 02.10 without it online
        self.args.autolog_rival = [guest]
        rivals = [fields(r) for r in self.ask()["RILI"]]
        self.assertEqual([(r["RIBL"], r["PENA"]) for r in rivals],
                         [(RIVAL, "CustomNickname2"), (guest, "Player_15")])

    def rival_online(self, source: str) -> lobby.Session:
        guest = lobby.Session("26.101.169.15", lambda _frame: None)
        guest.uid, guest.persona, guest.id_source = RIVAL, "CustomNickname2", source
        self.lb.sessions[RIVAL] = guest
        return guest

    def test_an_unconfirmed_rival_online_is_not_listed(self):
        # 02.10: Player_15 (synthetic uid) drove through one of his cameras in the host's session,
        # the host clicked him in the rival list and the game crashed (no stats on his row)
        self.rival_online(lobby.SYNTHETIC)
        reply = self.ask()
        self.assertEqual(reply, {})                        # no rival left: the bare acknowledgement
        self.args.autolog_unconfirmed_rivals = True        # A/B: as up to 1.0.12.6
        self.assertEqual([fields(r)["RIBL"] for r in self.ask()["RILI"]], [RIVAL])

    def add_xarrek(self):
        (Path(self.args.data_dir) / "stats" / "1473685610.json").write_text(json.dumps(
            {"RacerRoadRule00596c96": {"222": stat(AverageSpeed=50.0)}}))
        self.lb.players["ea:1473685610"] = {"uid": 1473685610, "persona": "XARREK"}
        tls_terminator._player_store(self.args)._cache.clear()

    def test_an_unconfirmed_player_is_off_the_walls_too(self):
        # 02.10: the cameras Player_15 had just driven ahead of the host showed nobody - his rows
        # there were empty in the host's game, and he led most of them
        self.rival_online(lobby.SYNTHETIC)
        self.add_xarrek()
        reply = self.ask()
        self.assertEqual([fields(r)["RIBL"] for r in reply["RILI"]], [1473685610])
        rows = {fields(fields(r)["BLUS"])["BLIS"] for r in fields(reply["SPWA"][222])["ROWS"]}
        self.assertEqual(rows, {ME, 1473685610})
        self.args.autolog_unconfirmed_rivals = True                      # as up to 1.0.12.6
        reply = self.ask()
        rows = {fields(fields(r)["BLUS"])["BLIS"] for r in fields(reply["SPWA"][222])["ROWS"]}
        self.assertEqual(rows, {ME, RIVAL, 1473685610})

    def walls(self, *swids) -> dict:
        """getInGameSpeedWalls (2050/20) for the asker: wall id -> ids of the rows."""
        request = blaze.Fire2(2050, 20, blaze.encode_tdf(
            [blaze.f_int("BLID", ME), blaze.f_list_int("SWIS", list(swids))]), seq=5)
        reply = blaze.Fire2.decode(tls_terminator._speed_walls(request, self.args, self.sess))
        return {fields(w)["SWID"]: {fields(fields(r)["BLUS"])["BLIS"] for r in fields(w)["ROWS"]}
                for w in fields(blaze.decode_tdf(reply.payload))["ROWS"]}

    def test_speed_walls_leave_out_an_unconfirmed_player_online(self):
        self.add_xarrek()
        self.assertEqual(self.walls(222), {222: {ME, RIVAL, 1473685610}})     # RIVAL offline: shown
        self.rival_online(lobby.SYNTHETIC)
        self.assertEqual(self.walls(222), {222: {ME, 1473685610}})
        self.args.autolog_unconfirmed_rivals = True
        self.assertEqual(self.walls(222), {222: {ME, RIVAL, 1473685610}})

    def test_an_unconfirmed_asker_still_sees_its_own_row(self):
        self.sess.id_source = lobby.SYNTHETIC
        self.assertEqual(self.walls(222), {222: {ME, RIVAL}})

    def test_a_confirmed_rival_online_is_listed(self):
        self.rival_online("launcher")
        self.assertEqual([fields(r)["RIBL"] for r in self.ask()["RILI"]], [RIVAL])

    def test_no_session_rivals_leaves_out_who_is_in_my_game(self):
        self.rival_online("launcher")
        game = lobby.Game(0x10000001, ME, {})
        game.players = {ME: {}, RIVAL: {}}
        self.lb.games[game.gid] = game
        self.sess.games.add(game.gid)
        self.assertEqual([fields(r)["RIBL"] for r in self.ask()["RILI"]], [RIVAL])
        self.args.autolog_no_session_rivals = True
        self.assertEqual(self.ask(), {})

    def cars_in_the_reply(self, mode: str) -> tuple[dict, dict, dict]:
        """(the rival's RECM entry on 222, its row on wall 222, my row there) - STAI of each."""
        self.args.autolog_vehicles = mode
        reply = self.ask()
        rec = fields(fields(reply["RILI"][0])["RECM"][0])
        rows = {fields(fields(r)["BLUS"])["BLIS"]: fields(r) for r in fields(reply["SPWA"][222])["ROWS"]}
        return rec["STAI"], rows[RIVAL]["STAI"], rows[ME]["STAI"]

    def test_a_car_the_asker_never_drove(self):
        # I drove car 7 everywhere; the rival's lead on 222 was in car 99 (02.10: Player_15's cars)
        self.rewrite_theirs({"RacerRoadRule00596c96": {"222": {
            "float": {"AverageSpeed": 45.0}, "int": {"vehicleUsed": 99, "attempts": 2}, "str": {}}}})
        store = tls_terminator._player_store(self.args)
        self.assertEqual(store.vehicles(ME), {7: 5})
        self.assertEqual(self.cars_in_the_reply("keep"),
                         ({"vehicleUsed": 99, "attempts": 2}, {"vehicleUsed": 99, "attempts": 2},
                          {"vehicleUsed": 7}))
        self.assertEqual(self.cars_in_the_reply("drop"),
                         ({"attempts": 2}, {"attempts": 2}, {"vehicleUsed": 7}))
        self.assertEqual(self.cars_in_the_reply("swap"),
                         ({"vehicleUsed": 7, "attempts": 2}, {"vehicleUsed": 7, "attempts": 2},
                          {"vehicleUsed": 7}))
        # the stored result itself is untouched
        self.assertEqual(store.state(RIVAL)["RacerRoadRule00596c96"]["222"]["int"]["vehicleUsed"], 99)

    def test_a_car_the_asker_drove_too_stays(self):
        # the default fixture: everybody drove car 7 - nothing to hide in any mode
        for mode in ("keep", "drop", "swap"):
            self.assertEqual(self.cars_in_the_reply(mode), ({"vehicleUsed": 7},) * 3)

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

    def in_my_game(self, *uids):
        game = lobby.Game(0x10000001, ME, {})
        game.players = {uid: {} for uid in (ME, *uids)}
        self.lb.games[game.gid] = game
        self.sess.games.add(game.gid)

    def test_by_default_only_the_players_in_my_game(self):
        # 1.1.2, the players' wish: the walls and the rival list are the session, not everyone
        # who ever played on this server
        self.args.autolog_everyone = False
        self.add_xarrek()                                       # stored, offline
        self.assertEqual(self.ask(), {})                        # nobody in my game: bare ack
        self.assertEqual(self.walls(222), {222: {ME}})
        self.rival_online("launcher")
        self.assertEqual(self.ask(), {})                        # online, but in no game of mine
        self.in_my_game(RIVAL)
        self.assertEqual([fields(r)["RIBL"] for r in self.ask()["RILI"]], [RIVAL])
        self.assertEqual(self.walls(222), {222: {ME, RIVAL}})

    def beat_you(self, rival: int, swids, row: dict) -> dict:
        recs = [{"swid": s, "blaze_id": rival, "persona": f"P{rival}", "type": 0,
                 "title": "ID_BEAT_YOU_TITLE", "row": row} for s in swids]
        return {"blaze_id": rival, "persona": f"P{rival}", "player_score": 0,
                "rival_score": len(recs), "recommendations": recs}

    def decoded(self, frame: bytes) -> dict:
        self.assertLessEqual(len(frame) - blaze.FIRE2_HDR, blaze.RECOMMENDATIONS_MAX_PAYLOAD)
        return fields(blaze.decode_tdf(blaze.Fire2.decode(frame).payload))

    def test_every_beat_you_goes_out_with_its_wall(self):
        # 02.10: ~450 shared walls, the events (high ids) fell out of the map while their entries
        # stayed - 7 of 7 games crashed right after such a reply at the end of an event
        rows = [{"blaze_id": n, "persona": "P" * 30, "float": {"eventTime": 1.0}} for n in range(3)]
        walls = [(1000 + n, rows) for n in range(600)]
        rival = self.beat_you(1, range(1580, 1600), rows[1])        # the 20 highest ids
        report = {}
        frame, sent = blaze.build_in_game_recommendations_response(
            1, [rival], walls, local_id=0, report=report)
        reply = self.decoded(frame)
        self.assertLess(sent, 600)
        recm = [fields(r)["SWID"] for r in fields(reply["RILI"][0])["RECM"]]
        self.assertEqual(recm, list(range(1580, 1600)))
        self.assertLessEqual(set(recm), set(reply["SPWA"]))
        self.assertEqual(report, {"dropped": 0, "rivals_dropped": []})

    def test_an_entry_whose_wall_does_not_fit_is_left_out(self):
        rows = [{"blaze_id": n, "persona": "P" * 30, "float": {"speed": 1.0}} for n in range(60)]
        walls = [(1000 + n, rows) for n in range(40)]                 # ~3 KB a wall: ~19 fit
        report = {}
        frame, sent = blaze.build_in_game_recommendations_response(
            1, [self.beat_you(1, range(1000, 1020), rows[1]), self.beat_you(2, [1035], rows[2])],
            walls, local_id=0, report=report)
        reply = self.decoded(frame)
        spwa = set(reply["SPWA"])
        recm = [fields(e)["SWID"] for r in reply["RILI"] for e in fields(r)["RECM"]]
        self.assertTrue(recm)
        self.assertLessEqual(set(recm), spwa)                         # never a wall it lacks
        self.assertGreater(report["dropped"], 0)
        self.assertEqual(report["rivals_dropped"], ["P2"])            # its only wall did not fit
        self.assertEqual([fields(r)["RIBL"] for r in reply["RILI"]], [1])

    def test_the_map_stops_before_the_fire2_limit(self):
        rows = [{"blaze_id": n, "persona": "P" * 30, "float": {"speed": 1.0}} for n in range(50)]
        walls = [(1000 + n, rows) for n in range(200)]
        frame, sent = blaze.build_in_game_recommendations_response(1, [], walls, local_id=0)
        self.assertLess(sent, 200)
        self.assertLessEqual(len(frame) - blaze.FIRE2_HDR, blaze.RECOMMENDATIONS_MAX_PAYLOAD)
        self.assertEqual(len(fields(blaze.decode_tdf(blaze.Fire2.decode(frame).payload))["SPWA"]), sent)


if __name__ == "__main__":
    unittest.main()
