/* TurboRivals launcher - the parts of the interface logic that need no page.

   Log classification, input checks, the readiness list and the bug report are plain functions
   of their inputs, so they are tested without a browser (tests/js/core.test.mjs, `node --test`).
   Loaded by index.html before app.js as window.TRCore; under Node, module.exports. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.TRCore = api;
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /* --- names: the server's own rule (tls_terminator._clean_name, commands.clean_name) --- */
    const NAME_MAX = 32;
    const FOLD = { 'Ł': 'L', 'ł': 'l', 'Ø': 'O', 'ø': 'o', 'Đ': 'D', 'đ': 'd', 'ß': 's',
                   'Æ': 'A', 'æ': 'a', 'Œ': 'O', 'œ': 'o' };

    function cleanName(name) {
        const folded = String(name || '').replace(/[ŁłØøĐđßÆæŒœ]/g, (c) => FOLD[c]).normalize('NFKD');
        let out = '';
        for (const ch of folded) if (ch >= ' ' && ch <= '~') out += ch;
        return out.trim().slice(0, NAME_MAX).trim();
    }

    /* --- addresses: the same rule as hosts_switch.valid_address --- */
    function validIPv4(text) {
        const s = String(text || '').trim();
        const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
        if (!m) return false;
        const parts = m.slice(1);
        if (parts.some((p) => (p.length > 1 && p[0] === '0') || Number(p) > 255)) return false;
        const first = Number(parts[0]);
        return s !== '0.0.0.0' && s !== '255.255.255.255' && !(first >= 224 && first <= 239);
    }

    /* --- the server log ---------------------------------------------------------------
       Levels, most important first. This colours and filters the log; it never drives
       behaviour - except the insights, which only surface what the server already said. */
    const LEVELS = ['error', 'hint', 'warn', 'event', 'traffic', 'info', 'noise'];

    function classifyLine(line) {
        const text = String(line);
        if (/\[hint\]/.test(text)) return 'hint';
        if (/traceback|exception|\berror\b|refused|IS ALREADY IN USE|session error|could not/i.test(text)) return 'error';
        if (/warning|timeout|skipped|bad record MAC|\[!\]|expected .* got type/i.test(text)) return 'warn';
        if (/keepalive PING|\[QoS UDP|-> replying \d+ B \(probe|^\s+[0-9a-f]{8}\s{2}[0-9a-f]{2}(\s|$)|^\s+\.\.\. \(\+\d+ bytes\)|B tail - waiting/.test(text)) return 'noise';
        if (/^\s*\[(player|identity|avatar|lobby|migration|matchmaking|game|session)\]|^=== \[|listening on|progress saving|multiplayer:|handing the game|RSA key loaded|client closed the connection|^--- |^stopped$/i.test(text)) return 'event';
        /* "no handler" is expected (readme: RPCs still answered with an empty acknowledgement)
           - a detail for whoever builds the next handler, not a problem for the player. */
        if (/<- Fire2|-> reply|-> empty acknowledgement|no handler|ClientHello|ServerHello|ClientKeyExchange|Finished|ChangeCipherSpec|\[QoS HTTP\]|-> replying|^\s{4}\S/.test(text)) return 'traffic';
        return 'info';
    }

    const LOG_VIEWS = {
        key: ['error', 'hint', 'warn', 'event'],
        standard: ['error', 'hint', 'warn', 'event', 'traffic', 'info'],
        raw: LEVELS,
        problems: ['error', 'hint', 'warn'],
    };

    function inView(level, view) {
        return (LOG_VIEWS[view] || LOG_VIEWS.standard).includes(level);
    }

    /* What the session panel should say out loud: the server's hints and warnings, in words.
       null for an ordinary line. */
    function insightFrom(line) {
        const text = String(line).trim();
        let m = /^\[hint\]\s*(.*)$/.exec(text);
        if (m) return { level: 'hint', text: m[1] };
        m = /^\[identity\] WARNING ([\d.]+): (.*)$/.exec(text);
        if (m) return { level: 'warn', text: `${m[1]}: ${m[2]}` };
        m = /^PORT (\d+) \(([^)]+)\) IS ALREADY IN USE/.exec(text);
        if (m) return { level: 'error', text: `Port ${m[1]} (${m[2]}) is taken - the server stopped.` };
        if (/^Traceback \(most recent call last\)/.test(text)) {
            return { level: 'error', text: 'The server hit an error - the log has the details.' };
        }
        return null;
    }

    /* --- the session ------------------------------------------------------------------ */
    function rosterDiff(before, after) {
        const key = (p) => String(p.uid);
        const was = new Map((before || []).map((p) => [key(p), p]));
        const now = new Map((after || []).map((p) => [key(p), p]));
        return {
            joined: [...now.values()].filter((p) => !was.has(key(p))),
            left: [...was.values()].filter((p) => !now.has(key(p))),
        };
    }

    function formatUptime(seconds) {
        const s = Math.max(0, Math.floor(seconds || 0));
        const h = Math.floor(s / 3600);
        const m = Math.floor((s % 3600) / 60);
        const pad = (n) => String(n).padStart(2, '0');
        return h ? `${h}:${pad(m)}:${pad(s % 60)}` : `${pad(m)}:${pad(s % 60)}`;
    }

    /* Mirrors build_command() in commands.py, for the preview under the server card. No
       absolute path: it is always the same, and printing it would put the Windows user name
       on screen and in every screenshot. */
    function commandPreview({ name, publicIp, players }) {
        const quote = (v) => (/\s/.test(v) ? `"${v}"` : v);
        const parts = ['TurboRivals', '--run-server', '--entitlements', 'online'];
        if (publicIp) parts.push('--public-ip', publicIp);
        if (cleanName(name)) parts.push('--local-persona', quote(cleanName(name)));
        (players || []).forEach(([ip, nick]) => parts.push('--player', quote(`${ip}=${nick}`)));
        return parts.join(' ');
    }

    /* --- readiness ---------------------------------------------------------------------
       The setup checklist for the current mode. Each check: {id, status, ...} with status
       ok / warn / error / pending (not known yet) / na (does not apply on this system). */
    const SAVE_GUESS = 'EA App user id (guess)';

    function checks(s) {
        const host = s.mode === 'host';
        const list = [];
        list.push({ id: 'admin', status: s.admin === null ? 'pending' : s.admin ? 'ok' : 'warn' });
        const procs = s.processes;
        list.push({ id: 'eaApp', status: !procs ? 'pending' : !procs.known ? 'na' : procs.ea_app ? 'ok' : 'warn' });
        if (host) list.push({ id: 'cert', status: s.cert ? 'ok' : 'warn' });

        const hosts = s.hosts || {};
        const target = host ? '127.0.0.1' : (validIPv4(s.serverIp) ? s.serverIp.trim() : '');
        let hostsStatus;
        if (hosts.error) hostsStatus = 'error';
        else if ((hosts.foreign || []).length) hostsStatus = 'error';
        else if (!hosts.active) hostsStatus = 'warn';
        else if (target && hosts.ip !== target) hostsStatus = 'warn';
        else if (!target && !host) hostsStatus = hosts.active ? 'ok' : 'warn';
        else hostsStatus = 'ok';
        list.push({ id: 'hosts', status: hostsStatus, target });

        const fw = s.firewall;
        list.push({ id: 'firewall', status: !fw ? 'pending' : !fw.supported ? 'na' : fw.ok ? 'ok' : 'warn' });
        if (host) {
            const ports = s.ports;
            list.push({ id: 'ports', status: !ports ? 'pending' : ports.ok ? 'ok' : 'error' });
        }
        return list;
    }

    function summary(list) {
        const counted = list.filter((c) => c.status !== 'na');
        return {
            ready: counted.filter((c) => c.status === 'ok').length,
            total: counted.length,
            pending: counted.filter((c) => c.status === 'pending').length,
            problems: counted.filter((c) => c.status === 'warn' || c.status === 'error').length,
        };
    }

    /* Why the big button cannot go yet - in the order a player would fix it. */
    function blockers(s) {
        const out = [];
        if (s.mode === 'host') {
            if (s.server && s.server.running) return out;
            if (!cleanName(s.name)) out.push('Enter your name');
            if (!s.cert) out.push('Generate the certificate');
            if (s.publicIp && !validIPv4(s.publicIp)) out.push('Fix the address players connect to');
            if (s.ports && !s.ports.ok) out.push('Free the server ports');
        } else {
            if (!validIPv4(s.serverIp)) out.push("Enter the host's address");
            if (!cleanName(s.name)) out.push('Enter your name');
        }
        return out;
    }

    function saveState(save) {
        if (!save) return 'pending';
        if (!save.id) return 'missing';
        return save.source === SAVE_GUESS ? 'guessed' : 'found';
    }

    /* --- the bug report: the fields of .github/ISSUE_TEMPLATE/bug_report.yml ------------- */
    function networkGuess(diag) {
        const ip = diag.mode === 'host' ? diag.public_ip : diag.server_ip;
        const mine = (diag.addresses || []).find((a) => a.ip === diag.public_ip);
        const vpn = (diag.addresses || []).find((a) => a.kind === 'vpn');
        if (mine && mine.kind === 'vpn') return `${mine.adapter} (${ip})`;
        if (diag.mode !== 'host' && vpn && ip && ip.split('.')[0] === vpn.ip.split('.')[0]) {
            return `${vpn.adapter} (${ip})`;
        }
        if (mine) return `Same local network - ${mine.adapter} (${ip})`;
        return ip ? `address ${ip}` : 'not set';
    }

    function buildReport(diag, ctx) {
        const yes = (v) => (v ? 'yes' : 'no');
        const lines = [];
        const role = diag.mode === 'host' ? 'Host (running the server)' : 'Joining player';
        lines.push('### TurboRivals diagnostics', '');
        lines.push(`- **Launcher version:** ${diag.version}${diag.frozen ? '' : ' (from source)'}`);
        lines.push(`- **Windows:** ${diag.windows}`);
        lines.push(`- **Role:** ${role}`);
        lines.push(`- **Network:** ${networkGuess(diag)}`);
        lines.push('', '#### Setup');
        lines.push(`- Administrator rights: ${yes(diag.admin)}`);
        const procs = diag.processes || {};
        lines.push(`- EA App running: ${procs.known === false ? 'unknown' : yes(procs.ea_app)}`
                   + `, game running: ${procs.known === false ? 'unknown' : yes(procs.game)}`);
        if (diag.mode === 'host') lines.push(`- Certificate: ${diag.cert ? 'present' : 'missing'}`);
        const hosts = diag.hosts || {};
        const foreign = (hosts.foreign || []).length ? ` - OLD ENTRIES OUTSIDE THE BLOCK: ${hosts.foreign.join(' | ')}` : '';
        lines.push(`- hosts redirect: ${hosts.active ? `on, gosredirector.ea.com -> ${hosts.ip}` : 'off'}`
                   + `, the game goes to ${hosts.effective_ip || 'real DNS'}${foreign}`);
        const fw = diag.firewall || {};
        lines.push(`- Firewall rules: ${!fw.supported ? 'not checked' : (fw.rules || []).map((r) => `${r.name} ${r.proto} ${r.ports} ${r.state}`).join('; ')}`);
        if (diag.mode === 'host') {
            const ports = diag.ports || {};
            const busy = (ports.ports || []).filter((p) => !p.free && !p.own);
            lines.push(`- Server ports: ${ports.server ? 'in use by the running server' : busy.length
                ? busy.map((p) => `${p.proto} ${p.port} taken${p.process ? ` by ${p.process}` : ''}`).join(', ') : 'all free'}`);
        }
        lines.push('', '#### Career save');
        const save = diag.save || {};
        const state = saveState(save);
        lines.push(state === 'missing' ? '- not found (no EA App account on this PC)'
            : `- ${save.id} - ${state === 'guessed' ? 'GUESSED' : 'found'} (${save.source}), EA App user ${save.user || '-'}, saves: ${(save.saves || []).join(', ') || '-'}`);
        const game = diag.game || {};
        lines.push('', '#### Game', `- Install folder found: ${yes(game.found)}${game.offers && game.offers.length ? `, EA offer ${game.offers[0]}` : ''}`);
        const server = diag.server || {};
        if (diag.mode === 'host') {
            lines.push('', '#### Server', `- ${server.running ? `running for ${formatUptime(server.uptime)} (PID ${server.pid})` : `not running${server.exit_code !== null && server.exit_code !== undefined ? `, last exit code ${server.exit_code}` : ''}`}`);
            if (server.log_path) lines.push(`- Log file: ${server.log_path}`);
        }
        if (ctx && ctx.activity && ctx.activity.length) {
            lines.push('', '#### Launcher activity');
            ctx.activity.slice(-15).forEach((a) => lines.push(`- ${a.time} ${a.text}`));
        }
        if (ctx && ctx.log && ctx.log.length) {
            lines.push('', '#### Server log (last lines)', '```text', ...ctx.log.slice(-80), '```');
        }
        return lines.join('\n');
    }

    return {
        NAME_MAX, LEVELS, LOG_VIEWS, SAVE_GUESS,
        cleanName, validIPv4, classifyLine, inView, insightFrom, rosterDiff, formatUptime,
        commandPreview, checks, summary, blockers, saveState, networkGuess, buildReport,
    };
});
