// Tests for launcher/web/js/core.js. Run from the repository root:  node --test tests/js/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const core = require(path.join(ROOT, 'launcher', 'web', 'js', 'core.js'));

function python(code) {
  // On Windows "python3" can be the Microsoft Store stub rather than a missing command.
  for (const exe of process.platform === 'win32' ? ['python', 'py'] : ['python3', 'python']) {
    try {
      return execFileSync(exe, ['-c', code], { cwd: ROOT, encoding: 'utf-8',
        env: { ...process.env, PYTHONIOENCODING: 'utf-8' } });
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
  }
  return null;
}

const NAMES = ['Łukasz Żółć', '  José  ', 'Kowal_PL', '名前', 'x'.repeat(40), 'Straße', '', 'Æsir Œuvre'];
const ADDRESSES = ['127.0.0.1', '26.48.21.54', ' 192.168.1.10 ', '', 'localhost', '192.168.1',
  '192.168.1.300', '192.168.001.5', '::1', '0.0.0.0', '255.255.255.255', '224.0.0.1',
  '26.48.21.54:42127', '1.2.3.4 x', '10.0.0.0'];

test('names and addresses follow the same rules as the Python side', (t) => {
  const out = python(
    'import json,sys; sys.path[:0]=["launcher","tools","proto-lab"]\n' +
    'import hosts_switch, tls_terminator\n' +
    `names=${JSON.stringify(NAMES)}; ips=${JSON.stringify(ADDRESSES)}\n` +
    'print(json.dumps([[tls_terminator._clean_name(n) for n in names],' +
    ' [hosts_switch.valid_address(i) for i in ips]]))');
  if (out === null) return t.skip('no Python on PATH');
  const [names, ips] = JSON.parse(out.trim().split('\n').pop());
  assert.deepEqual(NAMES.map(core.cleanName), names);
  assert.deepEqual(ADDRESSES.map(core.validIPv4), ips);
});

test('log lines are classified by what they mean', () => {
  const cases = {
    '  [hint] 26.11.40.7: the game connected but never logged in - is the EA App running?': 'hint',
    'PORT 17502 (QoS HTTP) IS ALREADY IN USE: [WinError 10048]': 'error',
    'Traceback (most recent call last):': 'error',
    '  [identity] WARNING 26.11.40.7: no usable save id': 'warn',
    '  -> keepalive PING seq=4': 'noise',
    '  00000000  16 03 00 00 2d 01 00 00  29 03 00 52 1c 41 a2 3d  ....-...)..R.A.=': 'noise',
    '=== [204512-001] client 127.0.0.1:51234 -> our port 42127 (redirector) ===': 'event',
    '  [player] 26.11.40.7 -> Kowal_PL (uid 1003311557799, launcher, ok)': 'event',
    'listening on 0.0.0.0:42127 (redirector)': 'event',
    '  <- Fire2 comp=9 cmd=7 err=0 type=0x00 seq=2 payload=301B  [Util.preAuth]': 'traffic',
    '  *** no handler: NFS.getSpecialGuestInfo ***': 'traffic',
    '  (client closed the connection)': 'event',
  };
  for (const [line, level] of Object.entries(cases)) assert.equal(core.classifyLine(line), level, line);
  assert.ok(core.inView('event', 'key'));
  assert.ok(!core.inView('traffic', 'key'));
  assert.ok(!core.inView('noise', 'standard'));
  assert.ok(core.inView('noise', 'raw'));
  assert.ok(!core.inView('event', 'problems'));
});

test('insights surface the server hints in words', () => {
  assert.deepEqual(core.insightFrom('  [hint] 26.11.40.7: the game connected but never logged in'),
    { level: 'hint', text: '26.11.40.7: the game connected but never logged in' });
  assert.equal(core.insightFrom('PORT 14219 (redirector/Blaze) IS ALREADY IN USE: x').level, 'error');
  assert.equal(core.insightFrom('  <- Fire2 comp=1 cmd=152'), null);
});

test('roster changes become joined / left', () => {
  const a = { uid: 1, name: 'Host' }, b = { uid: 2, name: 'Kowal' }, c = { uid: 3, name: 'test2' };
  const diff = core.rosterDiff([a, b], [a, c]);
  assert.deepEqual(diff.joined.map((p) => p.name), ['test2']);
  assert.deepEqual(diff.left.map((p) => p.name), ['Kowal']);
  assert.deepEqual(core.rosterDiff(null, []), { joined: [], left: [] });
});

test('readiness: host and guest lists, pending until probed', () => {
  const base = { mode: 'host', admin: true, processes: null, cert: false, firewall: null, ports: null,
    hosts: { active: true, ip: '127.0.0.1', foreign: [] }, serverIp: '' };
  const host = core.checks(base);
  assert.deepEqual(host.map((c) => c.id), ['admin', 'eaApp', 'cert', 'hosts', 'firewall', 'ports']);
  assert.deepEqual(core.summary(host), { ready: 2, total: 6, pending: 3, problems: 1 });

  const guest = core.checks({ ...base, mode: 'client', serverIp: '26.48.21.54',
    processes: { known: true, ea_app: true }, firewall: { supported: true, ok: true } });
  assert.deepEqual(guest.map((c) => c.id), ['admin', 'eaApp', 'hosts', 'firewall']);
  assert.equal(guest.find((c) => c.id === 'hosts').status, 'warn');   // still points at 127.0.0.1

  const stale = core.checks({ ...base, hosts: { active: true, ip: '127.0.0.1', foreign: ['127.0.0.1 gosredirector.ea.com'] } });
  assert.equal(stale.find((c) => c.id === 'hosts').status, 'error');
  const noTasklist = core.checks({ ...base, processes: { known: false } });
  assert.equal(noTasklist.find((c) => c.id === 'eaApp').status, 'na');
});

test('blockers name what stops the big button', () => {
  assert.deepEqual(core.blockers({ mode: 'host', name: '', cert: false, ports: { ok: false }, server: {} }),
    ['Enter your name', 'Generate the certificate', 'Free the server ports']);
  assert.deepEqual(core.blockers({ mode: 'host', name: 'x', cert: true, server: { running: true } }), []);
  assert.deepEqual(core.blockers({ mode: 'client', serverIp: '26.48.21', name: 'x' }), ["Enter the host's address"]);
});

test('command preview mirrors build_command without paths', () => {
  assert.equal(core.commandPreview({ name: 'Łukasz', publicIp: '26.48.21.54', players: [['26.11.40.7', 'Kowal PL']] }),
    'TurboRivals --run-server --entitlements online --public-ip 26.48.21.54 --local-persona Lukasz --player "26.11.40.7=Kowal PL"');
});

test('uptime and save state', () => {
  assert.equal(core.formatUptime(75), '01:15');
  assert.equal(core.formatUptime(3725), '1:02:05');
  assert.equal(core.saveState({ id: 1, source: core.SAVE_GUESS }), 'guessed');
  assert.equal(core.saveState({ id: null }), 'missing');
  assert.equal(core.saveState({ id: 5, source: 'EA App profile' }), 'found');
});

test('the bug report carries the issue form fields', () => {
  const report = core.buildReport({
    version: '1.1.0', frozen: true, windows: 'Windows 11 (build 22631)', admin: true, mode: 'client',
    processes: { known: true, ea_app: false, game: false },
    hosts: { active: true, ip: '26.48.21.54', effective_ip: '127.0.0.1', foreign: ['127.0.0.1 gosredirector.ea.com'] },
    firewall: { supported: true, rules: [{ name: 'NFS Rivals P2P', proto: 'UDP', ports: '3659', state: 'ok' }] },
    addresses: [{ ip: '26.11.40.7', adapter: 'Radmin VPN', kind: 'vpn' }],
    public_ip: '', server_ip: '26.48.21.54',
    save: { id: 1004000060810, source: core.SAVE_GUESS, user: 1004000060810, saves: [] },
    game: { found: true, offers: ['1004776'] }, server: { running: false },
  }, { activity: [{ time: '21:04:10', text: 'hosts redirect -> 26.48.21.54' }], log: [] });
  for (const part of ['Launcher version:** 1.1.0', 'Joining player', 'Radmin VPN (26.48.21.54)',
    '#### Setup', '#### Career save', 'EA App running: no', 'OLD ENTRIES OUTSIDE THE BLOCK', '1004000060810 - GUESSED', 'EA offer 1004776',
    '21:04:10 hosts redirect']) {
    assert.ok(report.includes(part), part);
  }
});
