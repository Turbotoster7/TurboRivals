/* Stand-in for the pywebview bridge, loaded by dev/preview.py ahead of the app's scripts.

   Answers every Api method from launcher/app.py with canned data, so the UI can be developed
   and screenshotted in a plain browser. ?scenario= picks the starting situation, ?latency= the
   delay of each call in ms (default 120 - enough to see the pending states). */
(function () {
    'use strict';

    const params = new URLSearchParams(location.search);
    const LATENCY = Number(params.get('latency') || 120);

    const svgAvatar = (text, from, to) => 'data:image/svg+xml;utf8,' + encodeURIComponent(
        `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
           <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
             <stop offset="0" stop-color="${from}"/><stop offset="1" stop-color="${to}"/>
           </linearGradient></defs>
           <rect width="128" height="128" fill="url(#g)"/>
           <text x="64" y="80" font-family="Segoe UI, Arial" font-size="46" font-weight="700"
                 fill="#fff" text-anchor="middle">${text}</text></svg>`);

    const ADDRESSES = [
        { ip: '26.48.21.54', adapter: 'Radmin VPN', kind: 'vpn' },
        { ip: '192.168.1.23', adapter: 'Ethernet', kind: 'lan' },
        { ip: '172.27.96.1', adapter: 'vEthernet (WSL)', kind: 'virtual' },
    ];
    const SAVE_FOUND = {
        id: 1006400012345, source: 'EA App profile', user: 1012900012345,
        persona: 'NightRider', saves: [1006400012345],
    };
    const SAVE_GUESS = {
        id: 1004000060810, source: 'EA App user id (guess)', user: 1004000060810,
        persona: 'test2', saves: [],
    };
    const ME = { uid: 1006400012345, name: 'NightRider', local: true, avatar: svgAvatar('NR', '#0bc5ea', '#1d4ed8') };
    const GUESTS = [
        { uid: 1802434674, name: 'test2', local: false, avatar: svgAvatar('T2', '#f97316', '#be123c') },
        { uid: 1003311557799, name: 'Kowal_PL', local: false, avatar: '' },
    ];
    const RULES = {
        host: [['TurboRivals', 'TCP', '42127,14219,17502'], ['TurboRivals QoS', 'UDP', '17502-17503'],
               ['NFS Rivals P2P', 'UDP', '3659']],
        client: [['NFS Rivals P2P', 'UDP', '3659']],
    };
    const PORTS = [['TCP', 42127, 'redirector'], ['TCP', 14219, 'Blaze'], ['TCP', 17502, 'QoS HTTP + launchers'],
                   ['UDP', 17502, 'QoS probes'], ['UDP', 17503, 'QoS probes']];
    const NO_HOSTS = { active: false, ip: null, entries: [], foreign: [], effective_ip: null, error: null };
    const hostsAt = (ip) => ({ active: true, ip, entries: [`${ip}\tgosredirector.ea.com`], foreign: [], effective_ip: ip, error: null });

    function scenario(name) {
        const base = {
            admin: true, eaApp: true, gameRunning: false, cert: true,
            hosts: hostsAt('127.0.0.1'),
            firewall: { 'TurboRivals': 'ok', 'TurboRivals QoS': 'ok', 'NFS Rivals P2P': 'ok' },
            busyPorts: {},
            save: SAVE_FOUND,
            avatar: svgAvatar('NR', '#0bc5ea', '#1d4ed8'),
            config: { mode: 'host', local_persona: 'NightRider', public_ip: '26.48.21.54', server_ip: '',
                      entitlements: 'online', players: [], recent_servers: [], restore_hosts_on_exit: 'ask',
                      onboarded: true, log_view: 'key' },
            players: [],
            serverRunning: false,
            online: [],
            firstRun: false,
            hostReachable: true,
        };
        const variants = {
            fresh: {
                admin: false, eaApp: false, cert: false, firstRun: true, hosts: NO_HOSTS, firewall: {}, avatar: '',
                config: { mode: 'host', local_persona: '', public_ip: '', server_ip: '', entitlements: 'online',
                          players: [], recent_servers: [], restore_hosts_on_exit: 'ask', onboarded: false, log_view: 'key', keep_captures: false },
            },
            ready: {},
            issues: {
                eaApp: false, cert: false,
                hosts: { active: true, ip: '127.0.0.1', entries: ['127.0.0.1\tgosredirector.ea.com'],
                         foreign: ['26.11.40.7 gosredirector.ea.com'], effective_ip: '26.11.40.7', error: null },
                firewall: { 'TurboRivals': 'ok', 'TurboRivals QoS': 'outdated' },
                busyPorts: { 'TCP 17502': { pid: 4312, process: 'SteelSeriesGG.exe' } },
            },
            hosting: {
                serverRunning: true, gameRunning: true, online: [ME, ...GUESTS],
                players: [['26.11.40.7', 'Kowal_PL']],
            },
            joining: {
                save: SAVE_GUESS, avatar: svgAvatar('T2', '#f97316', '#be123c'), hosts: NO_HOSTS,
                firewall: { 'NFS Rivals P2P': 'ok' },
                config: { mode: 'client', local_persona: 'test2', public_ip: '', server_ip: '26.48.21.54',
                          entitlements: 'online', players: [], recent_servers: ['26.48.21.54', '192.168.1.23'],
                          restore_hosts_on_exit: 'ask', onboarded: true, log_view: 'key', keep_captures: false },
            },
            unreachable: {
                save: SAVE_FOUND, hosts: NO_HOSTS, firewall: { 'NFS Rivals P2P': 'ok' }, hostReachable: false,
                config: { mode: 'client', local_persona: 'NightRider', public_ip: '', server_ip: '26.48.21.99',
                          entitlements: 'online', players: [], recent_servers: ['26.48.21.54'],
                          restore_hosts_on_exit: 'ask', onboarded: true, log_view: 'key', keep_captures: false },
            },
        };
        const s = Object.assign(structuredClone(base), structuredClone(variants[name] || {}));
        if (params.get('mode')) s.config.mode = params.get('mode');
        if (params.get('mode') === 'client' && s.hosts.ip === '127.0.0.1') s.hosts = NO_HOSTS;
        s.startedAt = Date.now() / 1000 - 754;
        return s;
    }

    const S = scenario(params.get('scenario') || 'ready');
    const wait = (ms) => new Promise((done) => setTimeout(done, ms));
    const answer = async (value, ms = LATENCY) => { await wait(ms); return structuredClone(value); };
    const emit = (event, payload) => window.TR && window.TR.on && window.TR.on(event, payload);

    const firewallStatus = (mode) => {
        const rules = RULES[mode].map(([name, proto, ports]) => ({ name, proto, ports, state: S.firewall[name] || 'missing' }));
        return { supported: true, ok: rules.every((r) => r.state === 'ok'), rules };
    };
    const portStatus = () => {
        if (S.serverRunning) return { ok: true, server: true, ports: [] };
        const ports = PORTS.map(([proto, port, purpose]) => {
            const busy = S.busyPorts[`${proto} ${port}`];
            return { proto, port, purpose, free: !busy, pid: busy ? busy.pid : null, process: busy ? busy.process : null, own: false, closing: false };
        });
        return { ok: ports.every((p) => p.free), ports };
    };
    const serverStatus = () => (S.serverRunning
        ? { running: true, pid: 9184, started_at: S.startedAt, uptime: Math.round(Date.now() / 1000 - S.startedAt), exit_code: null, log_path: '%LOCALAPPDATA%\\TurboRivals\\logs\\server-20261001-210412-9184.log' }
        : { running: false, pid: null, started_at: null, uptime: 0, exit_code: null, log_path: null });

    /* --- server log, in the real server's own wording (proto-lab/tls_terminator.py) --- */
    const BANNER = [
        'RSA key loaded (1024 bit), cert 787 B',
        'listening on 0.0.0.0:14219 (BLAZE)',
        'listening on UDP 0.0.0.0:17502 (QoS probes)',
        'listening on UDP 0.0.0.0:17503 (QoS probes)',
        'listening on TCP 0.0.0.0:17502 (QoS HTTP)',
        '[identity] local player: EA App user 1012900012345, saves 1006400012345 -> uid 1006400012345 (local-auto, EA App profile)',
        'handing the game this Blaze address: 127.0.0.1:14219. Ctrl+C to stop.',
        'progress saving: C:\\Users\\player\\TurboRivals\\data',
        "multiplayer: server address on this network is 26.48.21.54. On every other machine add a hosts entry '26.48.21.54 gosredirector.ea.com'. Windows firewall: Python TCP 42127, 14219, 17502 and UDP 17502-17503; game UDP 3659.",
        '',
        'listening on 0.0.0.0:42127 (redirector)',
    ];
    const SESSION = [
        '', '=== [204512-001] client 127.0.0.1:51234 -> our port 42127 (redirector) ===',
        '  ClientHello: record 0x300, 1 cipher suites (RC4_SHA offered)',
        '  -> ServerHello (RC4_SHA) + Certificate (787 B) + Done',
        '  client Finished: verify_data OK',
        '  <- Fire2 comp=5 cmd=1 err=0 type=0x00 seq=1 payload=112B  [Redirector.getServerInstance]',
        '  -> reply comp=5 cmd=1 (98 B)',
        '', '=== [204513-002] client 127.0.0.1:51236 -> our port 14219 (BLAZE) ===',
        '  <- Fire2 comp=9 cmd=7 err=0 type=0x00 seq=2 payload=301B  [Util.preAuth]',
        '  -> reply comp=9 cmd=7 (1290 B)',
        '  <- Fire2 comp=1 cmd=152 err=0 type=0x00 seq=4 payload=420B  [Authentication.originLogin]',
        '  [player] 127.0.0.1 -> NightRider (uid 1006400012345, local-auto, EA App profile, ok)',
        '  -> reply comp=1 cmd=152 (388 B)',
        '  <- Fire2 comp=2050 cmd=39 err=0 type=0x00 seq=9 payload=24B  [NFS.getSpecialGuestInfo]',
        '  *** no handler: NFS.getSpecialGuestInfo ***',
        '  -> empty acknowledgement comp=2050 cmd=39 (12 B)',
        '  -> keepalive PING seq=0',
        '',
        '  [identity] 26.11.40.7 launcher: name Kowal_PL, save id 1003311557799 (EA App profile), EA App user 1012900077799, saves 1003311557799',
        '  [avatar] 26.11.40.7: picture of uid 1003311557799 saved (png, 9120 B)',
        '', '=== [204601-003] client 26.11.40.7:60411 -> our port 14219 (BLAZE) ===',
        '  <- Fire2 comp=9 cmd=7 err=0 type=0x00 seq=2 payload=301B  [Util.preAuth]',
        '  <- Fire2 comp=9 cmd=2 err=0 type=0x00 seq=3 payload=0B  [Util.ping]',
        '  (client closed the connection)',
        '  [hint] 26.11.40.7: the game connected but never logged in - is the EA App running and signed in on that machine?',
        '', '=== [204655-004] client 26.11.40.7:60502 -> our port 14219 (BLAZE) ===',
        '  <- Fire2 comp=9 cmd=7 err=0 type=0x00 seq=2 payload=301B  [Util.preAuth]',
        '  <- Fire2 comp=1 cmd=152 err=0 type=0x00 seq=4 payload=420B  [Authentication.originLogin]',
        '  [player] 26.11.40.7 -> Kowal_PL (uid 1003311557799, launcher, ok)',
        '  <- Fire2 comp=4 cmd=9 err=0 type=0x00 seq=12 payload=210B  [GameManager.joinGame]',
        '  -> reply comp=4 cmd=9 (64 B)',
    ];

    let logTimer = null;
    function streamLog(lines) {
        clearInterval(logTimer);
        const queue = lines.slice();
        logTimer = setInterval(() => {
            if (!S.serverRunning) return clearInterval(logTimer);
            if (!queue.length) {
                emit('log', [`  -> keepalive PING seq=${Math.floor(Math.random() * 90)}`]);
                return;
            }
            emit('log', queue.splice(0, 3));
        }, 140);
    }

    const PROBE_DELAY = { processes: 260, addresses: 420, save: 640, firewall: 820, ports: 380 };
    function probe(name) {
        const mode = S.config.mode;
        switch (name) {
        case 'processes': return { known: true, ea_app: S.eaApp, game: S.gameRunning };
        case 'addresses': return { list: ADDRESSES, suggested: ADDRESSES[0].ip };
        case 'save': return S.save;
        case 'firewall': return firewallStatus(mode);
        case 'ports': return portStatus();
        default: return { error: 'unknown probe' };
        }
    }

    const api = {
        get_snapshot: () => answer({
            version: '1.1.0', windows: true, frozen: true, first_run: S.firstRun, config: S.config,
            players: S.players, max_guests: 5, admin: S.admin, can_edit_hosts: S.admin, hosts: S.hosts,
            cert: S.cert, server: serverStatus(), avatar: S.avatar, firewall_rules: RULES,
            server_ports: PORTS.map(([proto, port, purpose]) => ({ proto, port, purpose })),
            redirector: 'gosredirector.ea.com', project_url: 'https://github.com/Turbotoster7/TurboRivals',
        }, LATENCY),
        refresh: async (names) => {
            const wanted = names || Object.keys(PROBE_DELAY);
            const results = { hosts: S.hosts, admin: S.admin };
            await Promise.all(wanted.map(async (name) => {
                await wait(PROBE_DELAY[name] || 200);
                results[name] = probe(name);
                emit('probe', { name, value: structuredClone(results[name]) });
            }));
            return structuredClone(results);
        },
        save_config: (changes) => { Object.assign(S.config, changes); return answer({ ok: true, config: S.config }); },
        relaunch_as_admin: () => answer({ ok: false, error: 'UAC declined (preview)' }),
        hosts_status: () => answer(S.hosts),
        hosts_on: (ip) => {
            if (!S.admin) return answer({ ok: false, error: 'administrator rights required', needs_admin: true, status: S.hosts });
            const removed = S.hosts.foreign.slice();
            S.hosts = hostsAt(ip);
            return answer({ ok: true, ip, removed, backup: 'hosts.turborivals-preview.bak', changed: true, status: S.hosts }, 450);
        },
        hosts_off: () => {
            if (!S.admin) return answer({ ok: false, error: 'administrator rights required', needs_admin: true, status: S.hosts });
            S.hosts = NO_HOSTS;
            return answer({ ok: true, removed: [], backup: null, changed: true, status: S.hosts }, 450);
        },
        resolved_redirector: () => answer(S.hosts.effective_ip ? [S.hosts.effective_ip] : [], 300),
        firewall_status: (mode) => answer(firewallStatus(mode), 600),
        firewall_rules: (mode) => {
            if (!S.admin) return answer({ ok: false, error: 'administrator rights required', needs_admin: true });
            const added = RULES[mode].filter(([name]) => S.firewall[name] !== 'ok').map(([n, p, ports]) => `${n} (${p} ${ports})`);
            RULES[mode].forEach(([name]) => { S.firewall[name] = 'ok'; });
            return answer({ ok: true, rules: added, status: firewallStatus(mode) }, 900);
        },
        check_ports: () => answer(portStatus(), 400),
        make_cert: () => { S.cert = true; return answer({ ok: true, output: '%LOCALAPPDATA%\\TurboRivals\\pki' }, 1000); },
        launch_game: () => {
            const running = S.gameRunning;
            S.gameRunning = true;
            return answer(running ? { ok: true, via: 'already running', running: true } : { ok: true, via: 'EA App (offer 1004776)' }, 500);
        },
        identify: (ip, name) => {
            if (!S.hostReachable) {
                return answer({ ok: false, ...S.save, reason: 'timeout', error: `no answer from ${ip} - wrong address, the machines do not see each other (VPN not connected, different network) or the host's firewall`, backup: { ok: true } }, 3000);
            }
            S.joinedIp = ip;
            if (!S.config.recent_servers.includes(ip)) S.config.recent_servers.unshift(ip);
            S.online = [ME, ...GUESTS].map((p) => (p.uid === GUESTS[0].uid ? p : p));
            return answer({ ok: true, ...S.save, persona: name, backup: { ok: true } }, 600);
        },
        test_host: (ip) => answer(S.hostReachable
            ? { ok: true, ms: 23, players: 2 }
            : { ok: false, reason: 'timeout', error: `no answer from ${ip} - wrong address, the machines do not see each other (VPN not connected, different network) or the host's firewall` }, 900),
        save_avatar: (png) => { S.avatar = png; return answer({ ok: true, avatar: png }); },
        upload_avatar: () => answer({ ok: true }, 300),
        fetch_players: () => answer(S.serverRunning || S.joinedIp
            ? { ok: true, players: S.online } : { ok: false, players: [], error: 'no server address' }),
        add_player: (nick, ip) => {
            if (S.players.length >= 5) return answer({ ok: false, error: 'limit is 5 players + host', players: S.players });
            if (!nick || !ip) return answer({ ok: false, error: "enter both the player's name and their address", players: S.players });
            if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return answer({ ok: false, error: `"${ip}" is not an IPv4 address like 26.48.21.54`, players: S.players });
            S.players.push([ip, nick]);
            return answer({ ok: true, players: S.players });
        },
        remove_player: (nick) => {
            S.players = S.players.filter(([, n]) => n !== nick);
            return answer({ ok: true, players: S.players });
        },
        get_players: () => answer(S.players),
        start_server: (name, ip) => {
            const ports = portStatus();
            if (!ports.ok) {
                return answer({ ok: false, ports, error: 'the server cannot start: port TCP 17502 by SteelSeriesGG.exe (PID 4312) - close that program (or an older TurboRivals server) and try again' }, 500);
            }
            S.serverRunning = true;
            S.startedAt = Date.now() / 1000;
            S.online = [];
            setTimeout(() => { S.online = [ME]; }, 2600);
            setTimeout(() => { S.online = [ME, GUESTS[1]]; }, 7500);
            setTimeout(() => { S.online = [ME, GUESTS[1], GUESTS[0]]; }, 11000);
            setTimeout(() => streamLog(BANNER.concat(SESSION)), 250);
            return answer({ ok: true, pid: 9184, command: ['TurboRivals.exe', '--run-server', '--public-ip', ip, '--local-persona', name],
                            log_path: '%LOCALAPPDATA%\\TurboRivals\\logs\\server-20261001-210412-9184.log' }, 700);
        },
        stop_server: () => {
            S.serverRunning = false;
            S.online = [];
            setTimeout(() => emit('server-exit', { code: 1, requested: true }), 200);   // TerminateProcess leaves 1
            return answer({ ok: true, exit_code: 0 }, 300);
        },
        server_status: () => answer(serverStatus()),
        diagnostics: () => answer({
            version: '1.1.0', frozen: true, windows: 'Windows 11 (build 22631)', admin: S.admin, mode: S.config.mode,
            processes: { known: true, ea_app: S.eaApp, game: S.gameRunning }, hosts: S.hosts,
            firewall: firewallStatus(S.config.mode), ports: portStatus(), addresses: ADDRESSES,
            public_ip: S.config.public_ip, server_ip: S.config.server_ip, save: S.save,
            game: { found: true, dir: 'C:\\Program Files (x86)\\Steam\\steamapps\\common\\Need for Speed Rivals', offers: ['1004776'] },
            cert: S.cert, server: serverStatus(), data_dir: '%LOCALAPPDATA%\\TurboRivals', log_dir: '%LOCALAPPDATA%\\TurboRivals\\logs',
        }, 700),
        open_folder: (kind) => answer({ ok: true, path: `%LOCALAPPDATA%\\TurboRivals\\${kind}` }),
        open_url: () => answer({ ok: true }),
        minimize: () => answer(null),
        quit: () => answer({ ok: true }),
        close: () => answer(null),
    };

    window.__mock = { state: S, api, emit, scenario: params.get('scenario') || 'ready' };
    /* Like the real bridge: absent at first, injected a moment after the page loads. */
    setTimeout(() => {
        window.pywebview = { api };
        window.dispatchEvent(new Event('pywebviewready'));
    }, 60);
})();
