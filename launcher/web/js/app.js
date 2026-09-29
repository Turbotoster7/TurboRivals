/* =========================================
   TURBORIVALS LAUNCHER - interface logic

   Nothing here waits on the Python bridge to become usable. pywebview only
   injects it once navigation completes, so the UI binds and paints first, and
   every backend call queues behind `whenReady`.
   ========================================= */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
    known: false,          // has the backend answered once?
    mode: 'host',
    admin: false,
    cert: false,
    hosts: { active: false, ip: null },
    serverRunning: false,
    players: [],
    maxGuests: 5,
    addresses: [],
    eaApp: false,
};

/* --- bridge ----------------------------------------------------------
   Resolved either straight away (the event may already have fired before
   this script ran) or on pywebviewready. */
const whenReady = new Promise((resolve) => {
    if (window.pywebview && window.pywebview.api) {
        resolve(window.pywebview.api);
    } else {
        window.addEventListener('pywebviewready',
            () => resolve(window.pywebview.api), { once: true });
    }
});

/* Every backend call goes through here, so a click landing before the bridge
   is up queues instead of throwing on a null api. */
async function callApi(name, ...args) {
    const bridge = await whenReady;
    return bridge[name](...args);
}

/* --- events pushed from Python: window.TR.on(event, payload) --- */
window.TR = {
    on(event, payload) {
        if (event === 'log') appendLog(payload);
        if (event === 'server-exit') onServerExit(payload);
    },
};

/* =======================================================================
   BOOT SCREEN
   ======================================================================= */
function runLoader() {
    const bar = $('#loaderBar');
    const percent = $('#loaderPercent');
    const started = Date.now();
    let value = 0;
    let settled = false;

    const paint = () => {
        bar.style.width = value + '%';
        percent.textContent = Math.floor(value) + '%';
    };

    /* Creep towards 90% while waiting, then jump to 100 when the bridge is
       actually up - the bar tracks readiness instead of inventing progress. */
    const timer = setInterval(() => {
        value = Math.min(90, value + 7);
        paint();
    }, 90);

    const finish = () => {
        if (settled) return;
        settled = true;
        clearInterval(timer);
        value = 100;
        paint();
        // Floor so it does not flash, ceiling so a stuck bridge never traps us.
        setTimeout(() => $('#loader').classList.add('done'),
                   Math.max(0, 600 - (Date.now() - started)));
    };

    whenReady.then(finish);
    setTimeout(finish, 4000);
}

/* =======================================================================
   TOASTS
   ======================================================================= */
function toast(message, kind = '') {
    const el = document.createElement('div');
    el.className = 'toast ' + kind;
    el.textContent = '> ' + message;
    $('#toasts').appendChild(el);
    setTimeout(() => {
        el.classList.add('out');
        setTimeout(() => el.remove(), 300);
    }, 4200);
}

/* Disables a button for the length of a slow privileged action (netsh,
   ipconfig /flushdns, cert generation) so it does not look broken. */
async function withPending(button, fn) {
    if (button.dataset.pending) return;
    const label = button.textContent;
    button.dataset.pending = '1';
    button.classList.add('pending');
    button.disabled = true;
    button.textContent = 'WORKING';
    try {
        return await fn();
    } finally {
        delete button.dataset.pending;
        button.classList.remove('pending');
        button.disabled = false;
        button.textContent = label;
    }
}

/* =======================================================================
   SERVER LOG
   ======================================================================= */

/* The server prints in Polish, so the patterns carry both spellings - this
   colours the log, it never drives behaviour. */
function classifyLine(line) {
    const lower = line.toLowerCase();
    if (/traceback|error|blad|exception|refused/.test(lower)) return 'bad';
    if (/brak handlera|no handler|warn|timeout|skipped/.test(lower)) return 'warn';
    if (/dolaczy|joined|joincompleted|playerstate|login/.test(lower)) return 'good';
    if (/^\s*\[|->/.test(line)) return 'hit';
    return '';
}

const LOG_LIMIT = 1500;

/* Python hands over a batch every 100 ms. One fragment, one append, one trim -
   a burst of a few hundred lines costs the same as a single line. */
function appendLog(lines) {
    const batch = Array.isArray(lines) ? lines : [lines];
    if (!batch.length) return;

    const body = $('#logBody');
    const empty = body.querySelector('.log-empty');
    if (empty) empty.remove();

    const stuck = body.scrollHeight - body.scrollTop - body.clientHeight < 40;

    const fragment = document.createDocumentFragment();
    for (const line of batch) {
        const row = document.createElement('div');
        row.className = 'log-row ' + classifyLine(line);
        row.textContent = line;
        fragment.appendChild(row);
    }
    body.appendChild(fragment);

    for (let over = body.childElementCount - LOG_LIMIT; over > 0; over--) {
        body.firstElementChild.remove();
    }
    if (stuck) body.scrollTop = body.scrollHeight;
}

function clearLog() {
    $('#logBody').innerHTML = '<div class="log-empty">&gt; log cleared</div>';
}

function onServerExit(code) {
    state.serverRunning = false;
    appendLog([`--- server exited (code ${code}) ---`]);
    toast(code === 0 ? 'server stopped' : `server died (code ${code})`,
          code === 0 ? '' : 'bad');
    render();
}

/* =======================================================================
   RENDER
   ======================================================================= */
function render() {
    /* status bar */
    const status = $('#adminStatus');
    const statusText = status.querySelector('.status-text');
    if (!state.known) {
        status.className = 'system-status busy';
        statusText.textContent = 'CHECKING...';
    } else if (state.serverRunning) {
        status.className = 'system-status live';
        statusText.textContent = 'SERVER ONLINE';
    } else if (state.admin) {
        status.className = 'system-status ok';
        statusText.textContent = 'READY';
    } else {
        status.className = 'system-status warn';
        statusText.textContent = 'NO ADMIN';
    }

    /* pre-flight */
    setCheck('#checkAdmin', state.admin,
        state.admin ? 'running elevated' : 'hosts and firewall will not work');
    $('#checkAdmin').querySelector('button').style.display = state.admin ? 'none' : '';

    setCheck('#checkEaApp', state.eaApp,
        state.eaApp ? 'running'
                    : 'not running - the game gets no Origin token and never logs in');

    setCheck('#checkCert', state.cert,
        state.cert ? 'proto-lab/pki/server.der' : 'missing - generate before starting');
    $('#checkCert').querySelector('button').style.display = state.cert ? 'none' : '';
    $('#checkCert').style.display = state.mode === 'host' ? '' : 'none';

    const hostsOn = state.hosts.active;
    const hostsTarget = state.mode === 'host' ? '127.0.0.1 (this machine)' : 'the host';
    setCheck('#checkHosts', hostsOn,
        hostsOn ? `gosredirector.ea.com -> ${state.hosts.ip || '?'}`
                : `the game still looks for EA servers - will point at ${hostsTarget}`);
    const btnHosts = $('#btnHosts');
    if (!btnHosts.dataset.pending) {
        btnHosts.textContent = hostsOn ? 'TURN OFF' : 'TURN ON';
    }
    btnHosts.classList.toggle('off', hostsOn);

    $('#firewallNote').textContent = state.mode === 'host'
        ? 'TCP 42127,14219,17502 + UDP 17502-17503, 3659'
        : 'UDP 3659 (player-to-player traffic)';

    /* Count only the checks that actually apply: the certificate is the host's
       business alone. Folding it in as "cert || client" used to hand the
       joining player a free point and print 3/3 next to a red EA APP row. */
    const checks = state.mode === 'host'
        ? [state.admin, state.eaApp, state.cert, hostsOn]
        : [state.admin, state.eaApp, hostsOn];
    const ready = checks.filter(Boolean).length;
    $('#checkSummary').textContent = state.known
        ? `${ready}/${checks.length} OK` : '--';

    /* mode panels */
    $$('.mode-panel').forEach((panel) => {
        panel.classList.toggle('hidden', panel.dataset.panel !== state.mode);
    });
    $$('#modeMenu .nav-link').forEach((link) => {
        link.classList.toggle('active', link.dataset.mode === state.mode);
    });

    /* actions */
    $('#btnServer').classList.toggle('hidden', state.mode !== 'host');
    $('#btnConnect').classList.toggle('hidden', state.mode !== 'client');

    const btnServer = $('#btnServer');
    if (!btnServer.dataset.pending) {
        btnServer.textContent = state.serverRunning ? 'STOP SERVER' : 'START SERVER';
    }
    btnServer.classList.toggle('danger', state.serverRunning);

    const serverStatus = $('#serverStatus');
    serverStatus.textContent = state.serverRunning ? 'RUNNING' : 'OFFLINE';
    serverStatus.className = 'status ' + (state.serverRunning ? 'running' : 'stopped');

    /* players */
    renderPlayers();
    renderAddressChips();
    renderIpHint();
    renderCommandPreview();
}

function setCheck(selector, ok, note) {
    const row = $(selector);
    row.classList.toggle('ok', ok);
    row.classList.toggle('warn', !ok);
    row.querySelector('.check-note').textContent = note;
}

function renderPlayers() {
    const list = $('#playerList');
    list.innerHTML = '';
    state.players.forEach(([ip, nick], index) => {
        const row = document.createElement('li');
        row.className = 'player-row';
        row.innerHTML = `
            <span class="player-slot">P${String(index + 2).padStart(2, '0')}</span>
            <span class="player-nick"></span>
            <span class="player-ip"></span>
            <button class="player-kill">REMOVE</button>`;
        row.querySelector('.player-nick').textContent = nick;
        row.querySelector('.player-ip').textContent = ip;
        row.querySelector('.player-kill').onclick = () => removePlayer(nick);
        list.appendChild(row);
    });
    $('#slotsTag').textContent = `${state.players.length}/${state.maxGuests} SLOTS`;
    $('#btnAddPlayer').disabled = state.players.length >= state.maxGuests;
}

/* One chip per detected adapter. Which address is right depends on how the
   players connect, so the launcher shows what it found and lets you pick. */
function renderAddressChips() {
    const box = $('#addrChips');
    const chosen = $('#publicIp').value.trim();
    box.innerHTML = '';

    state.addresses.forEach((addr) => {
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = `addr-chip ${addr.kind}` + (addr.ip === chosen ? ' active' : '');
        chip.innerHTML = '<span class="chip-name"></span><span class="chip-ip"></span>';
        chip.querySelector('.chip-name').textContent = addr.adapter;
        chip.querySelector('.chip-ip').textContent = addr.ip;
        chip.onclick = () => {
            $('#publicIp').value = addr.ip;
            persist();
            render();
        };
        box.appendChild(chip);
    });
}

function renderIpHint() {
    const hint = $('#ipHint');
    const value = $('#publicIp').value.trim();
    const picked = state.addresses.find((a) => a.ip === value);
    hint.classList.remove('alert');

    if (!value) {
        hint.textContent = 'Pick the adapter the other players reach you on, or type an address yourself.';
    } else if (!picked) {
        hint.innerHTML = 'Typed by hand. It has to be an address every player can actually reach you at &mdash; '
            + 'over a VPN the one that VPN shows, on a shared network the one from '
            + '<span class="mono">ipconfig</span>.';
    } else if (picked.kind === 'virtual') {
        hint.textContent = `${picked.adapter} is a virtual adapter - no other machine can reach it. Pick your network card or VPN instead.`;
        hint.classList.add('alert');
    } else if (picked.kind === 'vpn') {
        hint.textContent = `Players join over ${picked.adapter}. Every one of them needs that VPN running and connected to you.`;
    } else {
        hint.textContent = `Same-network play over ${picked.adapter}. Everyone has to be on this network - no VPN needed.`;
    }
}

/* Mirrors build_command() in commands.py. Built locally so typing costs no
   IPC round trip; start_server() stays the authority and reports any error. */
function renderCommandPreview() {
    if (state.mode !== 'host') { $('#cmdPreview').textContent = ' '; return; }

    const quote = (v) => (/\s/.test(v) ? `"${v}"` : v);
    /* Deliberately no absolute path: it is always the same, and printing it
       would put the Windows user name on screen and in any screenshot. */
    const parts = ['TurboRivals', '--run-server', '--entitlements', 'online'];

    const ip = $('#publicIp').value.trim();
    const name = $('#persona').value.trim();
    if (ip) parts.push('--public-ip', ip);
    if (name) parts.push('--local-persona', quote(name));
    state.players.forEach(([playerIp, nick]) => {
        parts.push('--player', quote(`${playerIp}=${nick}`));
    });

    $('#cmdPreview').textContent = parts.join(' ');
}

/* =======================================================================
   ACTIONS
   ======================================================================= */
async function refreshState() {
    const fresh = await callApi('get_state');
    state.known = true;
    state.admin = fresh.admin;
    state.cert = fresh.cert;
    state.hosts = fresh.hosts;
    state.serverRunning = fresh.server_running;
    state.maxGuests = fresh.max_guests;
    state.addresses = fresh.addresses;
    state.eaApp = fresh.ea_app;
    $('#appVersion').textContent = fresh.version ? '· v' + fresh.version : '';
    state.players = await callApi('get_players');

    const config = fresh.config;
    state.mode = config.mode || 'host';
    $('#persona').value = config.local_persona || '';
    $('#publicIp').value = config.public_ip || fresh.suggested_ip || '';
    $('#serverIp').value = config.server_ip || '';

    render();
}

let persistTimer = null;

/* Debounced: typing a name should not write config.json on every keystroke. */
function persist() {
    clearTimeout(persistTimer);
    persistTimer = setTimeout(() => {
        callApi('save_config', {
            mode: state.mode,
            local_persona: $('#persona').value.trim(),
            public_ip: $('#publicIp').value.trim(),
            server_ip: $('#serverIp').value.trim(),
            entitlements: 'online',
            players: state.players,
        });
    }, 400);
}

async function addPlayer() {
    const nick = $('#newNick').value.trim();
    const ip = $('#newIp').value.trim();
    const result = await callApi('add_player', nick, ip);
    if (!result.ok) return toast(result.error, 'bad');

    state.players = result.players;
    $('#newNick').value = '';
    $('#newIp').value = '';
    $('#newNick').focus();
    persist();
    render();
}

async function removePlayer(nick) {
    const result = await callApi('remove_player', nick);
    state.players = result.players;
    persist();
    render();
}

async function toggleHosts() {
    /* Hosting, the redirect points at 127.0.0.1 - your own game has to reach
       the server on this machine. The --public-ip address is a different thing
       entirely: it is what the server hands to OTHER players. Sending your own
       hosts entry there makes the server see you arriving from a LAN address,
       treat you as a remote player and name you Player_<last octet> instead of
       your own name (lobby.py LOCAL_IPS). */
    const ip = state.mode === 'host' ? '127.0.0.1' : $('#serverIp').value.trim();

    if (state.hosts.active) {
        const result = await callApi('hosts_off');
        if (!result.ok) return toast(result.error, 'bad');
        toast('hosts restored, DNS cache flushed', 'good');
    } else {
        if (!ip) return toast('enter the server address', 'bad');
        const result = await callApi('hosts_on', ip);
        if (!result.ok) return toast(result.error, 'bad');
        toast(`gosredirector.ea.com -> ${ip}`, 'good');
    }
    state.hosts = await callApi('hosts_status');
}

async function addFirewall() {
    const result = await callApi('firewall_rules', state.mode);
    if (!result.ok) return toast(result.error, 'bad');
    $('#checkFirewall').classList.add('ok');
    $('#checkFirewall').querySelector('.check-dot').classList.remove('neutral');
    toast(`rules added: ${result.rules.length}`, 'good');
}

async function makeCert() {
    const result = await callApi('make_cert');
    if (!result.ok) return toast(result.error, 'bad');
    state.cert = true;
    toast('certificate ready', 'good');
}

async function toggleServer() {
    if (state.serverRunning) {
        await callApi('stop_server');
        state.serverRunning = false;
        return;
    }

    const persona = $('#persona').value.trim();
    if (!persona) return toast('enter your name - the server stores progress under it', 'warn');

    const result = await callApi('start_server', persona, $('#publicIp').value.trim(), 'online');
    if (!result.ok) return toast(result.error, 'bad');

    state.serverRunning = true;
    clearLog();
    appendLog([`--- start: ${result.command.join(' ')} ---`]);
    toast(`server up (PID ${result.pid})`, 'good');
    persist();
}

async function connectAsClient() {
    const ip = $('#serverIp').value.trim();
    if (!ip) return toast('enter the server address from the host', 'bad');

    if (!state.hosts.active || state.hosts.ip !== ip) {
        if (state.hosts.active) await callApi('hosts_off');
        const result = await callApi('hosts_on', ip);
        if (!result.ok) return toast(result.error, 'bad');
        state.hosts = await callApi('hosts_status');
    }
    persist();
    const launched = await callApi('launch_game');
    toast(launched.ok ? `redirect active - launching via ${launched.via}`
                      : launched.error,
          launched.ok ? 'good' : 'bad');
}

/* =======================================================================
   STARTUP
   ======================================================================= */

/* Runs a slow action on a button and repaints once it settles, so render()
   never fights withPending() over the label. */
function onPending(selector, fn) {
    $(selector).onclick = (event) =>
        withPending(event.currentTarget, fn).then(render, (e) => {
            toast(String(e), 'bad');
            render();
        });
}

function bind() {
    $('#btnMinimize').onclick = () => callApi('minimize');
    $('#btnClose').onclick = () => callApi('close');

    $$('#modeMenu .nav-link').forEach((link) => {
        link.onclick = () => {
            state.mode = link.dataset.mode;
            persist();
            render();
        };
    });

    $('[data-action="elevate"]').onclick = async (event) => {
        await withPending(event.currentTarget, async () => {
            const result = await callApi('relaunch_as_admin');
            if (!result.ok) toast(result.error, 'bad');
        });
    };
    onPending('[data-action="cert"]', makeCert);
    onPending('[data-action="hosts-toggle"]', toggleHosts);
    onPending('[data-action="firewall"]', addFirewall);
    onPending('#btnServer', toggleServer);
    onPending('#btnConnect', connectAsClient);

    $('#btnAddPlayer').onclick = addPlayer;
    $('#newIp').onkeydown = (e) => { if (e.key === 'Enter') addPlayer(); };
    $('#newNick').onkeydown = (e) => { if (e.key === 'Enter') $('#newIp').focus(); };

    $('#btnGame').onclick = async () => {
        const result = await callApi('launch_game');
        if (!result.ok) return toast(result.error, 'bad');
        toast(`launching via ${result.via}`, 'good');
    };
    $('#btnClearLog').onclick = clearLog;

    ['#persona', '#publicIp', '#serverIp'].forEach((sel) => {
        $(sel).oninput = () => { renderAddressChips(); renderIpHint(); renderCommandPreview(); persist(); };
    });
}

/* Bind and paint immediately - the bridge catches up on its own. */
runLoader();
bind();
render();
whenReady.then(refreshState);
