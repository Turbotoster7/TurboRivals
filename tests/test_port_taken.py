"""A server that cannot have one of its ports must stop and say which one.

Named to run before test_server.py: on Windows the connections that test closes linger in
TIME_WAIT and can keep even the blocker below from binding.

Before the fix the listener threads called sys.exit() on a failed bind, which ends only that
thread - silently - so with TCP 17502 taken the server ran on with no QoS HTTP listener and no
launcher channel (identify, pictures, ONLINE NOW), and its log said nothing about it."""
import support

import socket
import subprocess
import sys
import unittest

import commands


@unittest.skipUnless(support.ports_free(*[(p, n) for p, n, _ in commands.SERVER_PORTS]),
                     "the server's ports are in use on this machine")
class PortTaken(unittest.TestCase):
    def test_server_exits_naming_the_port(self):
        if not commands.cert_exists():
            result = commands.make_cert()
            if not result["ok"]:
                self.skipTest(result["error"])
        blocker = socket.socket()
        if not hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # past TIME_WAIT left by an earlier test; it still keeps the port from the server
            blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("0.0.0.0", 17502))
        blocker.listen(1)
        try:
            command = commands.build_command("HostPlayer", [], "127.0.0.1")
            run = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                 cwd=str(commands.ROOT), encoding="utf-8", errors="replace")
        finally:
            blocker.close()
        output = run.stdout + run.stderr
        self.assertEqual(run.returncode, 1, output)
        self.assertIn(":17502 (QoS HTTP) IS ALREADY IN USE", output)


class LinePrint(unittest.TestCase):
    """The server's print writes whole lines, so threads cannot run them together."""

    def test_one_write_per_line_across_threads(self):
        import builtins
        import threading
        import time

        import tls_terminator

        class SlowFile:
            def __init__(self):
                self.writes = []

            def write(self, text):
                time.sleep(0.0002)              # widen the gap between two writes
                self.writes.append(text)

            def flush(self):
                pass

        original = builtins.print
        target = SlowFile()
        try:
            builtins.print(" probe", end="!", file=target)
            self.assertEqual(target.writes, [" probe", "!"])   # the built-in: two writes
            target.writes.clear()
            tls_terminator._install_line_print()

            def worker(n):
                for i in range(60):
                    print(f"  [player] thread {n} line {i}", file=target)

            threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            builtins.print = original
        self.assertEqual(len(target.writes), 8 * 60)
        self.assertTrue(all(w.startswith("  [player] thread ") and w.endswith("\n") and w.count("\n") == 1
                            for w in target.writes))


if __name__ == "__main__":
    unittest.main()
