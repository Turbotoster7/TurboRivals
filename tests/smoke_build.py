"""Smoke test for a build of the launcher: the installed or packaged exe in CI, or the source tree.

    python tests/smoke_build.py --exe "%LOCALAPPDATA%\\Programs\\TurboRivals\\TurboRivals.exe"
    python tests/smoke_build.py                       # the source: python launcher/app.py

Calls the exe the way the launcher and the installer do: --make-cert; --run-server, logged into by
fake_game.py, its QoS HTTP and UDP answered, stopped again; --hosts-off on a hosts file of its
own; --self-test, which opens the window and checks that the page came up with both directions of
the bridge working. Everything goes to a throw-away TURBORIVALS_HOME (support.py).

    --screenshot PATH   then opens the window as a player would see it and saves the screen
    --dist DIR          adds the size of DIR/TurboRivals and of the installer next to it
    --json PATH         writes the results; under GitHub Actions they also go into the job summary
"""
from __future__ import annotations

import support

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import commands
import fake_game

STEPS: list[dict] = []
WINDOW = [1100, 680]          # the size launcher/app.py asks for, in CSS pixels at any scaling


def step(name: str):
    def wrap(fn):
        def run(*args, **kwargs):
            started = time.perf_counter()
            entry = {"step": name, "ok": False, "detail": ""}
            try:
                entry["detail"] = fn(*args, **kwargs) or ""
                entry["ok"] = True
            except Exception as error:                     # one failed step must not hide the rest
                entry["detail"] = f"{type(error).__name__}: {error}"
            entry["seconds"] = round(time.perf_counter() - started, 2)
            STEPS.append(entry)
            print(f"[{'ok' if entry['ok'] else 'FAIL'}] {name} ({entry['seconds']} s) {entry['detail']}",
                  flush=True)
            return entry["ok"]
        return run
    return wrap


def run(launcher: list[str], *flags: str, timeout: float = 60) -> subprocess.CompletedProcess:
    return subprocess.run(launcher + list(flags), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


@step("certificate (--make-cert)")
def make_cert(launcher: list[str]) -> str:
    result = run(launcher, "--make-cert")
    check(result.returncode == 0, f"exit {result.returncode}: {result.stdout}{result.stderr}")
    check(commands.cert_exists(), f"no server.der/server.key in {commands.PKI_DIR}")
    return result.stdout.strip()


@step("server (--run-server): listening, login, QoS, stop")
def server(launcher: list[str]) -> str:
    check(support.ports_free(*[(proto, port) for proto, port, _ in commands.SERVER_PORTS]),
          "the server's ports are in use on this machine")
    command = commands.build_command("Smoke", [], "127.0.0.1")
    script = command.index(str(commands.ROOT / "proto-lab" / "tls_terminator.py"))
    command = launcher + ["--run-server"] + command[script + 1:]

    lines: list[str] = []
    lock = threading.Lock()

    def collect(batch):
        with lock:
            lines.extend(batch)

    def wait_for(text: str, count: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with lock:
                if sum(text in line for line in lines) >= count:
                    return True
            time.sleep(0.05)
        return False

    process = commands.ServerProcess()
    started = time.perf_counter()
    check(process.start(command, on_lines=collect)["ok"], "the server did not start")
    try:
        sockets = len(commands.SERVER_PORTS)
        check(wait_for("listening on ", sockets, 30),
              f"not all {sockets} sockets listening after 30 s:\n" + "\n".join(lines[-30:]))
        up = time.perf_counter() - started

        game = fake_game.FakeGame("127.0.0.1", 14219, commands.PKI_DIR / "server.key")
        try:
            check(game.rpc(9, 7).error == 0, "Util.preAuth failed")
            check(game.rpc(1, 152).error == 0, "Authentication.originLogin failed")
            deadline, names = time.monotonic() + 5, []
            while time.monotonic() < deadline and not names:
                online = commands.fetch_players("127.0.0.1")
                check(online["ok"], f"ONLINE NOW: {online}")
                names = [p["name"] for p in online["players"]]
                time.sleep(0.2)
            check(names == ["Smoke"], f"ONLINE NOW after the login: {names}")
        finally:
            game.close()

        test = commands.test_host("127.0.0.1")
        check(test["ok"], f"QoS HTTP / test_host: {test}")

        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(3)
        try:
            probe.sendto(bytes(20), ("127.0.0.1", 17502))
            reply, _ = probe.recvfrom(4096)
        finally:
            probe.close()
        check(len(reply) == 30, f"QoS UDP replied {len(reply)} bytes")
    finally:
        stopped = process.stop()
    check(stopped["ok"], f"stop: {stopped}")
    check(wait_for_ports_free(5), "the ports were still taken 5 s after the stop")
    return f"{sockets} sockets listening after {up:.2f} s, login and ONLINE NOW, QoS HTTP {test['ms']} ms, QoS UDP"


def wait_for_ports_free(timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    ports = [(proto, port) for proto, port, _ in commands.SERVER_PORTS]
    while time.monotonic() < deadline:
        if support.ports_free(*ports):
            return True
        time.sleep(0.2)
    return False


@step("hosts redirect off (--hosts-off, as the uninstaller calls it)")
def hosts_off(launcher: list[str]) -> str:
    support.write_hosts()
    check(commands.hosts_on("127.0.0.1")["ok"], "could not write the test block")
    check(commands.hosts_status()["active"], "the test block is not there")
    result = run(launcher, "--hosts-off")
    check(result.returncode == 0, f"exit {result.returncode}: {result.stdout}{result.stderr}")
    status = commands.hosts_status()
    check(not status["active"] and not status["foreign"], f"still redirected: {status}")
    check("nas.local" in support.HOSTS.read_text(encoding="utf-8"), "the rest of the file is gone")
    return result.stdout.strip()


def window_run(launcher: list[str]) -> dict:
    """One --self-test run, timed from the moment the process is started: when the page began
    loading, the marks app.js sets (DOM loaded, snapshot drawn, each probe arriving), all checks
    known - and how long the process took to end after the self-test closed the window.

    The end is the process's own, not the end of its output: WebView2's browser processes can
    hold the inherited pipes open for a while after the launcher is gone."""
    output: list[str] = []
    spawned = time.time()
    proc = subprocess.Popen(launcher + ["--self-test"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    reader = threading.Thread(target=lambda: output.extend(proc.stdout), daemon=True)
    reader.start()
    try:
        code = proc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    exited = time.time()
    reader.join(2)
    report, closed = None, None
    for line in list(output):
        if line.startswith("self-test: "):
            report = json.loads(line[len("self-test: "):])
        elif line.startswith("self-test closed: "):
            closed = json.loads(line[len("self-test closed: "):])["at"]
    check(report is not None, f"no report, exit {code}: {''.join(output)[-3000:]}")
    check(code == 0 and report["ok"], f"exit {code}: {report}")
    if all(room >= want for room, want in zip(report["screen"], WINDOW)):   # else Windows shrinks it to fit
        check(all(abs(got - want) <= 1 for got, want in zip(report["size"], WINDOW)),
              f"the window opened at {report['size']}, not {WINDOW}")
    origin = report["origin"] / 1000
    times = {"page": origin - spawned}
    times.update({name: origin + ms / 1000 - spawned for name, ms in report["marks"].items()})
    probes = [t for name, t in times.items() if name.startswith("probe ")]
    times["all checks"] = max(probes) if probes else report["ready_at"] - spawned
    times["closing"] = exited - report["ready_at"]
    if closed:
        times["window gone"] = closed - report["ready_at"]
        times["exit"] = exited - closed
    return {"report": report, "seconds": {name: round(t, 2) for name, t in times.items()}}


@step("window (--self-test), first and second start")
def self_test(launcher: list[str], results: dict) -> str:
    runs = [window_run(launcher), window_run(launcher)]
    results["self_test"] = runs[0]["report"]
    results["startup"] = [r["seconds"] for r in runs]
    results["ui_ready_seconds"] = runs[0]["seconds"]["snapshot"]
    return "; ".join(
        f"{label} start: drawn {t['snapshot']:.2f} s, all checks {t['all checks']:.2f} s, closed in {t['closing']:.2f} s"
        for label, t in zip(("first", "second"), results["startup"])) + (
        f" - {runs[0]['report']['version']}, {runs[0]['report']['size'][0]}x{runs[0]['report']['size'][1]}, no script errors")


@step("screenshot")
def screenshot(launcher: list[str], path: Path) -> str:
    from PIL import ImageGrab

    commands.save_config({"onboarded": True, "mode": "host", "local_persona": "Smoke test"})
    window = subprocess.Popen(launcher)
    try:
        time.sleep(10)
        check(window.poll() is None, f"the launcher ended with {window.returncode}")
        path.parent.mkdir(parents=True, exist_ok=True)
        ImageGrab.grab().save(path)
    finally:
        window.terminate()
        try:
            window.wait(10)
        except subprocess.TimeoutExpired:
            window.kill()
    return str(path)


def sizes(dist: Path) -> dict:
    folder = dist / "TurboRivals"
    files = [p for p in folder.rglob("*") if p.is_file()]
    biggest = sorted(files, key=lambda p: p.stat().st_size, reverse=True)[:12]
    out = {"folder_mb": round(sum(p.stat().st_size for p in files) / 2**20, 1), "files": len(files),
           "biggest": [[str(p.relative_to(folder)), round(p.stat().st_size / 2**20, 2)] for p in biggest]}
    setups = sorted(dist.glob("TurboRivalsSetup-*.exe"))
    if setups:
        out["installer"] = setups[-1].name
        out["installer_mb"] = round(setups[-1].stat().st_size / 2**20, 1)
    return out


def markdown(results: dict) -> str:
    out = [f"### Smoke test - TurboRivals {results['version']}", "",
           "| Step | Result | Time | Detail |", "| --- | --- | --- | --- |"]
    for s in results["steps"]:
        detail = s["detail"].replace("|", "\\|").replace("\n", " ")[:300]
        out.append(f"| {s['step']} | {'ok' if s['ok'] else '**FAILED**'} | {s['seconds']} s | {detail} |")
    if results.get("startup"):
        columns = ["page", "loaded", "snapshot", "all checks", "closing", "window gone", "exit"]
        probes = sorted({k for t in results["startup"] for k in t if k.startswith("probe ")})
        out += ["", "**Window timing** (seconds after the process started; closing - split into the window"
                " going and the process ending - after the self-test closed the window)", "",
                "| Start | " + " | ".join(columns + [p[6:] for p in probes]) + " |",
                "| --- " * (len(columns) + len(probes) + 1) + "|"]
        for label, t in zip(("first", "second"), results["startup"]):
            out.append(f"| {label} | " + " | ".join(str(t.get(c, "-")) for c in columns + probes) + " |")
    size = results.get("size")
    if size:
        line = f"**Package:** `dist/TurboRivals` {size['folder_mb']} MB in {size['files']} files"
        if "installer" in size:
            line += f", `{size['installer']}` {size['installer_mb']} MB"
        out += ["", line, "", "<details><summary>Largest files</summary>", "",
                "| File | MB |", "| --- | --- |"]
        out += [f"| `{name}` | {mb} |" for name, mb in size["biggest"]]
        out += ["", "</details>"]
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--exe", help="TurboRivals.exe to test (default: the source)")
    parser.add_argument("--screenshot", type=Path)
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    launcher = ([str(Path(args.exe).resolve())] if args.exe
                else [sys.executable, str(support.ROOT / "launcher" / "app.py")])
    results: dict = {"launcher": " ".join(launcher), "version": commands.APP_VERSION}
    make_cert(launcher)
    server(launcher)
    hosts_off(launcher)
    self_test(launcher, results)
    if args.screenshot:
        screenshot(launcher, args.screenshot)
    if args.dist:
        results["size"] = sizes(args.dist)
    results["steps"] = STEPS
    results["ok"] = all(s["ok"] for s in STEPS)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write(markdown(results))
    print(json.dumps({k: v for k, v in results.items() if k != "steps"}, indent=2))
    return 0 if results["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
