import support  # noqa: F401  (throw-away TURBORIVALS_HOME and hosts file, set before the import)

import base64
import json
import os
import shutil
import socket
import struct
import sys
import threading
import time
import unittest
import zlib
from pathlib import Path
from unittest import mock

import commands

IPCONFIG_EN = """
Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : fritz.box
   IPv6 Address. . . . . . . . . . . : fd00::1c2d
   IPv4 Address. . . . . . . . . . . : 192.168.1.23
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1

Ethernet adapter Radmin VPN:

   IPv4 Address. . . . . . . . . . . : 26.48.21.54
   Subnet Mask . . . . . . . . . . . : 255.0.0.0

Ethernet adapter vEthernet (WSL):

   IPv4 Address. . . . . . . . . . . : 172.27.96.1

Ethernet adapter Hamachi:

   Autoconfiguration IPv4 Address. . : 169.254.12.7

Wireless LAN adapter WLAN:

   Media State . . . . . . . . . . . : Media disconnected
"""

IPCONFIG_DE = """
Windows-IP-Konfiguration

Ethernet-Adapter Ethernet:

   IPv4-Adresse  . . . . . . . . . . : 192.168.178.20(Bevorzugt)

Drahtlos-LAN-Adapter WLAN:

   IPv4-Adresse  . . . . . . . . . . : 192.168.178.21
"""

IPCONFIG_FR = """
Carte Ethernet Radmin VPN :

   Adresse IPv4. . . . . . . . . . . . . .: 26.11.40.7
"""

NETSH_EN = """
Rule Name:                            TurboRivals
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            42127,14219,17502
RemotePort:                           Any
Action:                               Allow
Ok.
"""

NETSH_DE = """
Regelname:                            TurboRivals QoS
----------------------------------------------------------------------
Aktiviert:                            Ja
Richtung:                             Eingehend
Protokoll:                            UDP
Lokaler Port:                         17502-17503
Aktion:                               Zulassen
OK.
"""

NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1032
  TCP    0.0.0.0:17502          0.0.0.0:0              ABHÖREN         4312
  TCP    192.168.1.23:17502     192.168.1.50:51000     ESTABLISHED     4312
  TCP    192.168.1.23:42127     20.42.65.92:443        ESTABLISHED     7781
  TCP    127.0.0.1:42127        127.0.0.1:51888        TIME_WAIT       0
  TCP    [::]:14219             [::]:0                 LISTENING       5120
  UDP    0.0.0.0:17503          *:*                                    4312
"""

TASKLIST = ('"System Idle Process","0","Services","0","8 K"\n'
            '"EADesktop.exe","6120","Console","1","210,412 K"\n'
            '"SteelSeriesGG.exe","4312","Console","1","98,100 K"\n')


def tiny_png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
    return (commands.PNG_MAGIC + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b""))


class Hosts(unittest.TestCase):
    def setUp(self):
        support.write_hosts("127.0.0.1 gosredirector.ea.com\n" + support.SAMPLE_HOSTS)

    def test_on_points_the_redirector_and_drops_the_stale_line(self):
        result = commands.hosts_on(" 26.48.21.54 ")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["removed"], ["127.0.0.1 gosredirector.ea.com"])
        status = commands.hosts_status()
        self.assertTrue(status["active"])
        self.assertEqual((status["ip"], status["effective_ip"], status["foreign"]),
                         ("26.48.21.54", "26.48.21.54", []))
        self.assertIn("10.0.0.5\tnas.local", support.HOSTS.read_text())

    def test_on_again_with_the_same_address_writes_nothing(self):
        commands.hosts_on("26.48.21.54")
        again = commands.hosts_on("26.48.21.54")
        self.assertTrue(again["ok"])
        self.assertFalse(again["changed"])
        self.assertIsNone(again["backup"])

    def test_off_restores(self):
        commands.hosts_on("26.48.21.54")
        result = commands.hosts_off()
        self.assertTrue(result["ok"], result)
        self.assertEqual(support.HOSTS.read_text(), support.SAMPLE_HOSTS)
        self.assertFalse(commands.hosts_status()["active"])

    def test_a_missing_hosts_file_is_an_empty_one(self):
        # Windows reads a missing hosts file as an empty one; some clean-up tools delete it.
        support.HOSTS.unlink()
        status = commands.hosts_status()
        self.assertIsNone(status["error"])
        self.assertFalse(status["active"])
        self.assertTrue(commands.can_edit_hosts())
        result = commands.hosts_on("26.48.21.54")
        self.assertTrue(result["ok"], result)
        self.assertEqual(commands.hosts_status()["ip"], "26.48.21.54")
        self.assertTrue(commands.hosts_off()["ok"])
        self.assertEqual(support.HOSTS.read_text().strip(), "")

    def test_garbage_never_reaches_the_file(self):
        before = support.HOSTS.read_bytes()
        for bad in ("", "my.host.com", "26.48.21.54:42127", "26.48.21"):
            result = commands.hosts_on(bad)
            self.assertFalse(result["ok"], bad)
        self.assertEqual(support.HOSTS.read_bytes(), before)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can write anything")
    def test_read_only_file_asks_for_admin(self):
        support.HOSTS.chmod(0o444)
        try:
            result = commands.hosts_on("26.48.21.54")
        finally:
            support.HOSTS.chmod(0o644)
        self.assertFalse(result["ok"])
        self.assertTrue(result.get("needs_admin"))


class Parsing(unittest.TestCase):
    def test_ipconfig_english(self):
        found = commands.parse_ipconfig(IPCONFIG_EN)
        self.assertEqual(found, [
            {"ip": "192.168.1.23", "adapter": "Ethernet", "kind": "lan"},
            {"ip": "26.48.21.54", "adapter": "Radmin VPN", "kind": "vpn"},
            {"ip": "172.27.96.1", "adapter": "vEthernet (WSL)", "kind": "virtual"},
        ])  # 169.254.x.x (a VPN adapter that is down) is nobody's way in

    def test_ipconfig_localised(self):
        self.assertEqual([(a["ip"], a["adapter"]) for a in commands.parse_ipconfig(IPCONFIG_DE)],
                         [("192.168.178.20", "Ethernet"), ("192.168.178.21", "WLAN")])
        self.assertEqual(commands.parse_ipconfig(IPCONFIG_FR)[0]["kind"], "vpn")

    def test_suggested_address_skips_virtual_adapters(self):
        addresses = [{"ip": "172.27.96.1", "adapter": "vEthernet (WSL)", "kind": "virtual"},
                     {"ip": "192.168.1.23", "adapter": "Ethernet", "kind": "lan"}]
        self.assertEqual(commands.suggested_public_ip(addresses), "192.168.1.23")
        self.assertEqual(commands.suggested_public_ip(addresses[:1]), "")

    def test_tasklist(self):
        procs = commands.parse_tasklist(TASKLIST)
        self.assertEqual(procs[6120], "EADesktop.exe")
        self.assertEqual(commands.process_status(procs), {"known": True, "ea_app": True, "game": False})
        self.assertEqual(commands.process_status({}), {"known": True, "ea_app": False, "game": False})

    def test_firewall_rule_states(self):
        self.assertEqual(commands.rule_state(NETSH_EN, "TurboRivals", "TCP", "42127,14219,17502"), "ok")
        self.assertEqual(commands.rule_state(NETSH_DE, "TurboRivals QoS", "UDP", "17502-17503"), "ok")
        self.assertEqual(commands.rule_state(NETSH_EN, "TurboRivals", "TCP", "42127,14219"), "outdated")
        self.assertEqual(commands.rule_state(NETSH_EN, "TurboRivals", "UDP", "42127,14219,17502"), "outdated")
        self.assertEqual(commands.rule_state("No rules match the specified criteria.",
                                             "NFS Rivals P2P", "UDP", "3659"), "missing")
        self.assertEqual(commands.rule_state(None, "NFS Rivals P2P", "UDP", "3659"), "unknown")

    def test_netstat_owners(self):
        owners, closing = commands.parse_netstat(NETSTAT)
        self.assertEqual(owners[("TCP", 17502)], 4312)
        self.assertEqual(owners[("TCP", 14219)], 5120)
        self.assertEqual(owners[("UDP", 17503)], 4312)
        self.assertNotIn(("TCP", 42127), owners)   # an outgoing connection does not hold the port
        self.assertEqual(closing, {42127})          # PID 0: TIME_WAIT from the last session

    def test_blocked_ports_are_explained(self):
        ports = [
            {"proto": "TCP", "port": 17502, "free": False, "pid": 4312,
             "process": "SteelSeriesGG.exe", "own": False, "closing": False},
            {"proto": "TCP", "port": 42127, "free": False, "pid": None, "process": None,
             "own": False, "closing": True},
            {"proto": "UDP", "port": 17503, "free": True},
        ]
        text = commands.describe_blocked(ports)
        self.assertIn("TCP 17502 by SteelSeriesGG.exe (PID 4312)", text)
        self.assertIn("TCP 42127 still being released", text)
        self.assertNotIn("17503", text)


class Ports(unittest.TestCase):
    def test_a_taken_port_is_reported(self):
        if not support.ports_free(("TCP", 14219)):
            self.skipTest("port 14219 is in use on this machine")
        blocker = socket.socket()
        blocker.bind(("0.0.0.0", 14219))
        blocker.listen(1)
        try:
            self.assertFalse(commands.port_free("TCP", 14219))
            status = commands.port_status()
            self.assertFalse(status["ok"])
            text = commands.describe_blocked(status["ports"])
            self.assertIn("TCP 14219", text)
        finally:
            blocker.close()
        self.assertTrue(commands.port_free("TCP", 14219))


class Names(unittest.TestCase):
    def test_same_rule_as_the_server(self):
        import tls_terminator

        for name in ("Łukasz Żółć", "  José  ", "Kowal_PL", "名前", "x" * 40, "Straße", ""):
            self.assertEqual(commands.clean_name(name), tls_terminator._clean_name(name), name)


class Players(unittest.TestCase):
    def test_validation(self):
        game = commands.Game()
        self.assertTrue(game.add_player("Kowal_PL", "26.11.40.7"))
        self.assertIn("already listed", game.check("kowal_pl", "26.11.40.8"))
        self.assertIn("already listed", game.check("Other", "26.11.40.7"))
        self.assertIn("IPv4", game.check("Other", "26.11.40"))
        self.assertIn("name", game.check("名前", "26.11.40.9"))
        for i in range(commands.MAX_GUESTS - 1):
            self.assertTrue(game.add_player(f"P{i}", f"26.0.0.{i + 1}"))
        self.assertIn("limit", game.check("One more", "26.0.0.99"))
        self.assertTrue(game.remove_player("Kowal_PL"))
        self.assertFalse(game.remove_player("Kowal_PL"))

    def test_loading_drops_broken_entries(self):
        game = commands.Game([["26.11.40.7", "Kowal_PL"], ["nonsense"], ["1.2.3", "X"], "x"])
        self.assertEqual(game.get_list_players(), [("26.11.40.7", "Kowal_PL")])


class Command(unittest.TestCase):
    def test_server_command_line(self):
        command = commands.build_command("Host", [("26.11.40.7", "Kowal PL")], "26.48.21.54")
        self.assertEqual(command[1:3], ["-u", str(commands.ROOT / "proto-lab" / "tls_terminator.py")])
        joined = " ".join(command)
        for part in ("--entitlements online", "--public-ip 26.48.21.54", "--local-persona=Host",
                     "--data-dir"):
            self.assertIn(part, joined)
        self.assertEqual(command[command.index("--player") + 1], "26.11.40.7=Kowal PL")

    def test_the_server_parses_any_name(self):
        # 02.10: a host named -Heat-The_Zephyr - "argument --local-persona: expected one argument"
        import tls_terminator
        for name in ("-Heat-The_Zephyr", "--x", "Host"):
            with self.subTest(name=name):
                command = commands.build_command(name, [("26.11.40.7", "-Guest")], "26.48.21.54")
                args = tls_terminator.build_arg_parser().parse_args(command[3:])   # past the script
                self.assertEqual(args.local_persona, name)
                self.assertEqual(args.player, ["26.11.40.7=-Guest"])
        self.assertIn("--no-capture", command)                       # captures are opt-in
        self.assertNotIn("--no-capture", commands.build_command("Host", [], "", capture=True))

    def test_rejects(self):
        with self.assertRaises(ValueError):
            commands.build_command("Host", [], "26.48.21")
        with self.assertRaises(ValueError):
            commands.build_command("Host", [("1.1.1.%d" % i, str(i)) for i in range(6)], "")


class Config(unittest.TestCase):
    def setUp(self):
        commands.CONFIG_PATH.unlink(missing_ok=True)

    def test_defaults_and_partial_updates(self):
        self.assertFalse(commands.config_exists())
        self.assertEqual(commands.load_config(), commands.DEFAULT_CONFIG)
        commands.save_config({"mode": "client", "server_ip": "26.48.21.54"})
        commands.save_config({"local_persona": "Nick"})
        config = commands.load_config()
        self.assertEqual((config["mode"], config["server_ip"], config["local_persona"]),
                         ("client", "26.48.21.54", "Nick"))
        self.assertFalse(list(commands.CONFIG_PATH.parent.glob("*.tmp")))

    def test_hand_edited_garbage_is_survivable(self):
        commands.CONFIG_PATH.write_text(json.dumps({
            "mode": "spectator", "players": "everyone", "recent_servers": ["26.48.21.54", 5, "x"],
            "restore_hosts_on_exit": True, "unknown": 1}))
        config = commands.load_config()
        self.assertEqual(config["mode"], "host")
        self.assertEqual(config["players"], [])
        self.assertEqual(config["recent_servers"], ["26.48.21.54"])
        self.assertEqual(config["restore_hosts_on_exit"], "ask")
        commands.CONFIG_PATH.write_text("{not json")
        self.assertEqual(commands.load_config(), commands.DEFAULT_CONFIG)

    def test_career_save_is_a_save_id_or_automatic(self):
        for stored, expected in ((1803135130, 1803135130), (-5, 0), (True, 0), ("1803135130", 0)):
            with self.subTest(stored=stored):
                commands.CONFIG_PATH.write_text(json.dumps({"career_save": stored}))
                self.assertEqual(commands.load_config()["career_save"], expected)

    def test_recent_servers(self):
        config = {"recent_servers": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6"]}
        recent = commands.remember_server(config, "3.3.3.3")
        self.assertEqual(recent[:2], ["3.3.3.3", "1.1.1.1"])
        self.assertEqual(len(commands.remember_server(config, "9.9.9.9")), commands.RECENT_SERVERS_KEPT)


class Identity(unittest.TestCase):
    def test_resolve_runs_again_only_when_its_files_change(self):
        logs = commands.ea_identity.EA_LOGS_DIR
        logs.mkdir(parents=True, exist_ok=True)
        log = logs / "EADesktopVerbose.log"
        log.write_text("nothing yet\n")
        commands._identity_cache.update(signature=None, value=None)
        calls = []

        def fake_resolve(chosen=0):
            calls.append(1)
            return {"id": 1006400012345, "source": "EA App profile", "user": 1012900012345,
                    "persona": "Tester", "saves": []}

        with mock.patch.object(commands.ea_identity, "resolve", fake_resolve):
            first = commands.save_identity()
            commands.save_identity()
            self.assertEqual(len(calls), 1)
            first["id"] = 0                         # a caller's copy, not the cache
            self.assertEqual(commands.save_identity()["id"], 1006400012345)
            log.write_text("nothing yet\n<GetProfileResponse UserId=\"1\"/>\n")
            commands.save_identity()
            self.assertEqual(len(calls), 2)
            commands.save_config({"career_save": 1006400012345})     # a pick is part of the answer
            commands.save_identity()
            self.assertEqual(len(calls), 3)
        commands.CONFIG_PATH.unlink(missing_ok=True)


class SavePick(unittest.TestCase):
    """Career save > Pick your save on a friend's PC (02.10): two EA-era saves, so automatic is
    only a guess; our synthetic id and the EA App user id are files the game never loads."""
    USER, OLD, NEW, SERVER = 1003772287105, 1803135129, 1803135130, 1100944155289

    def setUp(self):
        commands.CONFIG_PATH.unlink(missing_ok=True)
        folder = Path(support.HOME) / "saves-pick"
        folder.mkdir(exist_ok=True)
        for uid in (self.OLD, self.NEW, self.SERVER, self.USER):
            (folder / f"{uid}.sav").write_bytes(b"x")
        ini = commands.ea_identity.EA_DESKTOP_DIR / "user_pick.ini"
        ini.parent.mkdir(parents=True, exist_ok=True)
        ini.write_text(f"user.userid={self.USER}\n")
        patch = mock.patch.object(commands.ea_identity, "saves_dir", return_value=folder)
        patch.start()
        commands._identity_cache.update(signature=None, value=None)
        self.addCleanup(patch.stop)
        self.addCleanup(shutil.rmtree, folder, True)
        self.addCleanup(ini.unlink)
        self.addCleanup(commands._identity_cache.update, signature=None, value=None)
        self.addCleanup(commands.CONFIG_PATH.unlink, missing_ok=True)

    def test_automatic_is_a_guess_here(self):
        save = commands.save_identity()
        self.assertEqual((save["id"], save["source"]), (self.USER, commands.ea_identity.SOURCE_GUESS))
        self.assertNotIn("--local-id", commands.build_command("Host", [], ""))

    def test_only_a_career_save_can_be_picked(self):
        for wrong, why in ((self.SERVER, "made up"), (self.USER, "account number"),
                           (4242, "no 4242.sav"), ("abc", "not a save id")):
            with self.subTest(wrong=wrong):
                result = commands.choose_save(wrong)
                self.assertFalse(result["ok"])
                self.assertIn(why, result["error"])
        self.assertEqual(commands.load_config()["career_save"], 0)

    def test_a_pick_is_kept_and_reaches_the_host_s_server(self):
        result = commands.choose_save(self.NEW)
        self.assertTrue(result["ok"])
        self.assertEqual((result["save"]["id"], result["save"]["source"]),
                         (self.NEW, commands.ea_identity.SOURCE_CHOSEN))
        self.assertEqual(commands.load_config()["career_save"], self.NEW)
        command = commands.build_command("Host", [], "")
        at = command.index("--local-id")
        self.assertEqual(command[at:at + 3], ["--local-id", str(self.NEW), "--local-id-chosen"])
        self.assertTrue(commands.choose_save(0)["ok"])                   # back to automatic
        self.assertNotIn("--local-id", commands.build_command("Host", [], ""))


class Avatar(unittest.TestCase):
    def test_round_trip_and_limits(self):
        png = tiny_png()
        url = "data:image/png;base64," + base64.b64encode(png).decode()
        result = commands.save_avatar(url)
        self.assertTrue(result["ok"], result)
        self.assertEqual(commands.load_avatar(), url)
        self.assertFalse(commands.AVATAR_JPG_PATH.exists())
        huge = "data:image/png;base64," + base64.b64encode(png + b"\0" * commands.AVATAR_MAX).decode()
        self.assertFalse(commands.save_avatar(huge)["ok"])
        self.assertFalse(commands.save_avatar("data:image/png;base64,bm90IGEgcG5n")["ok"])

    def test_picture_cache_is_bounded(self):
        commands._avatar_cache.clear()
        reply = mock.MagicMock()
        reply.__enter__.return_value.read.return_value = tiny_png()
        with mock.patch.object(commands, "_opener") as opener:
            opener.return_value.open.return_value = reply
            for uid in range(commands.AVATAR_CACHE_MAX + 20):
                commands._cached_avatar("http://x", "10.0.0.1", uid, 1)
        self.assertEqual(len(commands._avatar_cache), commands.AVATAR_CACHE_MAX)
        self.assertNotIn(("10.0.0.1", 0, 1), commands._avatar_cache)


class Server(unittest.TestCase):
    """ServerProcess with a stand-in for the server: lines, exit code, log file, stop."""

    @classmethod
    def setUpClass(cls):
        if not commands.cert_exists():
            result = commands.make_cert()
            assert result["ok"], result

    def run_script(self, code: str):
        lines, exits, done = [], [], threading.Event()
        server = commands.ServerProcess()
        started = server.start([sys.executable, "-u", "-c", code], on_lines=lines.extend,
                               on_exit=lambda c: (exits.append(c), done.set()))
        self.assertTrue(started["ok"], started)
        return server, lines, exits, done

    def test_lines_exit_code_and_log_file(self):
        server, lines, exits, done = self.run_script(
            "print('listening on 0.0.0.0:42127 (redirector)')\nprint('Łukasz joined')\n"
            "raise SystemExit(3)")
        self.assertTrue(done.wait(10))
        self.assertEqual(lines, ["listening on 0.0.0.0:42127 (redirector)", "Łukasz joined"])
        self.assertEqual(exits, [3])
        text = server.log_path.read_text(encoding="utf-8")
        self.assertIn("Łukasz joined\n", text)
        self.assertIn("--- server exited (code 3) ---", text)
        self.assertFalse(server.status()["running"])
        self.assertFalse(server.stop_requested)      # it ended by itself: a crash, as far as the UI knows

    def test_stop(self):
        server, lines, exits, done = self.run_script(
            "import time\nprint('up', flush=True)\ntime.sleep(60)")
        deadline = time.time() + 10
        while not lines and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(server.status()["running"])
        self.assertTrue(server.stop()["ok"])
        self.assertTrue(done.wait(10))
        self.assertFalse(server.is_running())
        self.assertNotEqual(exits, [0])              # terminated - non-zero, yet asked for
        self.assertTrue(server.stop_requested)
        self.assertIn("stopped from the launcher", server.log_path.read_text(encoding="utf-8"))

    @unittest.skipUnless(commands.IS_WINDOWS, "Windows job objects")
    def test_server_is_tied_to_the_launcher(self):
        server, lines, _exits, done = self.run_script("import time\nprint('up', flush=True)\ntime.sleep(60)")
        try:
            self.assertIsNotNone(server._job, "the job object was not created")
        finally:
            server.stop()
        self.assertTrue(done.wait(10))

    def test_log_files_are_capped(self):
        commands.LOG_DIR.mkdir(parents=True, exist_ok=True)
        for i in range(commands.LOGS_KEPT + 4):
            (commands.LOG_DIR / f"server-20000101-0000{i:02d}-1.log").write_text("old")
        server, _lines, _exits, done = self.run_script("print('x')")
        self.assertTrue(done.wait(10))
        logs = sorted(commands.LOG_DIR.glob("server-*.log"))
        self.assertEqual(len(logs), commands.LOGS_KEPT)
        self.assertIn(server.log_path, logs)
        self.assertFalse((commands.LOG_DIR / "server-20000101-000000-1.log").exists())


@unittest.skipUnless(commands.IS_WINDOWS, "needs tasklist, ipconfig and netsh")
class WindowsTools(unittest.TestCase):
    """The real console tools, on a real Windows (the CI runner): they answer, and their
    output - localised or not - parses."""

    def test_tasklist_sees_this_python(self):
        procs = commands.running_processes()
        self.assertTrue(procs)
        self.assertTrue(any(name.lower().startswith("python") for name in procs.values()), procs)
        self.assertTrue(commands.process_status(procs)["known"])

    def test_toolhelp_agrees_with_tasklist_and_is_faster(self):
        api_view = commands._processes_toolhelp()
        tool_view = commands._processes_tasklist()
        self.assertTrue(api_view and tool_view)
        self.assertEqual(api_view.get(os.getpid(), "").lower(), tool_view.get(os.getpid(), "").lower())
        both = set(api_view) & set(tool_view)
        self.assertGreater(len(both), 0.8 * len(tool_view))           # processes come and go
        timings = {}
        for name, fn in (("toolhelp", commands._processes_toolhelp), ("tasklist", commands._processes_tasklist)):
            started = time.perf_counter()
            for _ in range(5):
                fn()
            timings[name] = (time.perf_counter() - started) / 5
        print(f"\n    process list: toolhelp {timings['toolhelp'] * 1000:.1f} ms, "
              f"tasklist {timings['tasklist'] * 1000:.1f} ms per call")
        self.assertLess(timings["toolhelp"], timings["tasklist"])

    def test_ipconfig_lists_an_adapter(self):
        addresses = commands.local_addresses()
        self.assertTrue(addresses)
        self.assertTrue(all(commands.valid_ipv4(a["ip"]) for a in addresses), addresses)

    def test_netsh_rule_states(self):
        status = commands.firewall_status("host")
        self.assertTrue(status["supported"])
        self.assertEqual(len(status["rules"]), 3)
        self.assertTrue(all(r["state"] in ("ok", "missing", "outdated") for r in status["rules"]), status)

    def test_version_and_netstat(self):
        self.assertTrue(commands.windows_version().startswith("Windows "))
        result = commands._run(["netstat", "-ano"], timeout=30)
        self.assertIsNotNone(result)
        owners, _closing = commands.parse_netstat(commands._console_text(result.stdout))
        self.assertTrue(owners)


class Links(unittest.TestCase):
    def test_only_project_links_open(self):
        with mock.patch.object(commands.webbrowser, "open") as browser:
            self.assertTrue(commands.open_url(commands.PROJECT_URL + "/issues/new/choose")["ok"])
            self.assertFalse(commands.open_url("https://example.com/")["ok"])
            self.assertFalse(commands.open_url(commands.PROJECT_URL + ".evil.example/")["ok"])
        browser.assert_called_once()


if __name__ == "__main__":
    unittest.main()
