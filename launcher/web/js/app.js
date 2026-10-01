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
    firewall: { host: false, client: false, any: false },   // commands.firewall_status()
    serverRunning: false,
    players: [],
    maxGuests: 5,
    addresses: [],
    eaApp: false,
    save: { id: null, user: null, saves: [] },   // commands.save_identity()
    avatar: '',            // this player's picture, a PNG data URL
    online: null,          // ONLINE NOW: commands.fetch_players(), null = nothing to ask
    onlineNote: '',
    joinedIp: '',          // the server this launcher connected a guest to
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

/* This colours the log, it never drives behaviour. */
function classifyLine(line) {
    const lower = line.toLowerCase();
    if (/traceback|error|exception|refused/.test(lower)) return 'bad';
    if (/no handler|warn|timeout|skipped/.test(lower)) return 'warn';
    if (/joined|joincompleted|playerstate|login/.test(lower)) return 'good';
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

/* The window keeps the last LOG_LIMIT lines; the whole run is in a file (commands.LOG_DIR). */
async function openLogs() {
    const result = await callApi('open_logs');
    if (!result.ok) toast(result.error, 'bad');
}

/* Windows ends a terminated process with code 1, so a STOP alone used to read "server died". */
let serverStopRequested = false;

function onServerExit(code) {
    state.serverRunning = false;
    const stopped = code === 0 || serverStopRequested;
    serverStopRequested = false;
    appendLog([`--- server ${stopped ? 'stopped' : 'exited'} (code ${code}) ---`]);
    toast(stopped ? 'server stopped' : `server died (code ${code})`, stopped ? '' : 'bad');
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
    /* A line for the same name outside our block comes first in the file and the
       game follows it, whatever the block says (hosts_switch.strip_redirects). */
    const foreign = state.hosts.foreign || [];
    const hostsTarget = state.mode === 'host' ? '127.0.0.1 (this machine)' : 'the host';
    setCheck('#checkHosts', hostsOn && !foreign.length,
        foreign.length
            ? `old entry outside the launcher: "${foreign[0]}" - the game goes to `
              + `${state.hosts.effective_ip || '?'}; TURN ON replaces it`
            : hostsOn ? `gosredirector.ea.com -> ${state.hosts.ip || '?'}`
                      : `the game still looks for EA servers - will point at ${hostsTarget}`);
    const btnHosts = $('#btnHosts');
    if (!btnHosts.dataset.pending) {
        btnHosts.textContent = hostsOn ? 'TURN OFF' : 'TURN ON';
    }
    btnHosts.classList.toggle('off', hostsOn);

    /* Missing rules leave the dot neutral, not red: the row is not in the count below. */
    const firewallOn = !!state.firewall[state.mode];
    $('#checkFirewall').classList.toggle('ok', firewallOn);
    $('#checkFirewall').querySelector('.check-dot').classList.toggle('neutral', !firewallOn);
    $('#firewallNote').textContent = state.mode === 'host'
        ? 'TCP 42127,14219,17502 + UDP 17502-17503, 3659'
        : 'UDP 3659 (player-to-player traffic)';
    const btnFirewall = $('#btnFirewall');
    if (!btnFirewall.dataset.pending) {
        btnFirewall.textContent = firewallOn ? 'REMOVE' : 'ADD';
    }
    btnFirewall.classList.toggle('off', firewallOn);

    /* Count only the checks that actually apply: the certificate is the host's
       business alone. Folding it in as "cert || client" used to hand the
       joining player a free point and print 3/3 next to a red EA APP row. */
    const hostsOk = hostsOn && !foreign.length;
    const checks = state.mode === 'host'
        ? [state.admin, state.eaApp, state.cert, hostsOk]
        : [state.admin, state.eaApp, hostsOk];
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
    renderSave();
    renderAvatar();
    renderOnline();
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

/* The game loads its career from this save, and the host's server has to log it in under the
   same id - otherwise progress goes to a file the game never reads (proto-lab/ea_identity.py). */
function renderSave() {
    const { id, user, source } = state.save;
    /* The EA App's profile or the save files name the save the game loads; the last resort,
       the account's user id, is a guess (ea_identity.resolve). */
    const guessed = source === 'EA App user id (guess)';
    const hint = $('#saveHint');
    $('#saveId').value = !state.known ? '--' : (id ? String(id) : 'not found');
    hint.classList.toggle('alert', state.known && (!id || guessed));
    hint.textContent = !state.known ? ' '
        : !id ? 'No EA App account found on this PC - the host cannot save your progress.'
        : !guessed ? `Found (${source}) - sent to the host on connect, so your progress sticks. EA App account ${user}.`
        : 'Guessed - no save of this EA account found, your progress may not stick. Start the game '
          + 'once through the EA App, close it, then connect again.';
}

/* =======================================================================
   PICTURE AND ONLINE NOW
   The picture is kept on this machine and sent to the host's server, which hands every
   launcher in the session the list of who is logged in, with pictures (commands.py).
   ======================================================================= */
/* Two copies: a small PNG for the launchers, a JPEG for the game (the server answers its ByteVault
   profile picture requests with it - the game links libjpeg). The first size, or quality, that
   fits the format's limit wins. The game's copy stays within 16 KB: the pictures known to work
   were 8-15 KB, and up to 1.0.9 a bigger one (a detailed photo made 20-40 KB) went out as one
   oversized TLS record and dropped the game a few seconds into a session. */
const AVATAR_MAX = 64 * 1024;
const AVATAR_PNG = { type: 'image/png', sizes: [128, 96, 64], qualities: [undefined],
                     max: AVATAR_MAX };
const AVATAR_JPEG = { type: 'image/jpeg', sizes: [256, 192, 128, 96],
                      qualities: [0.85, 0.7, 0.55, 0.4], max: 16 * 1024 };

function avatarImg(src) {
    const img = document.createElement('img');
    img.src = src;
    img.alt = '';
    return img;
}

function renderAvatar() {
    $$('[data-avatar-pick]').forEach((button) => button.replaceChildren(
        state.avatar ? avatarImg(state.avatar) : document.createTextNode('+')));
    $('#brandIcon').replaceChildren(
        state.avatar ? avatarImg(state.avatar) : document.createTextNode('TR'));
}

function loadImage(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onerror = () => reject(new Error('could not read the file'));
        reader.onload = () => {
            const img = new Image();
            img.onerror = () => reject(new Error('not an image the launcher can read'));
            img.onload = () => resolve(img);
            img.src = reader.result;
        };
        reader.readAsDataURL(file);
    });
}

/* Scaled and centre-cropped here, so nothing but a small square picture ever leaves this machine
   - whatever size or format the photo was. */
function squareImage(img, format) {
    const side = Math.min(img.width, img.height);
    for (const size of format.sizes) {
        for (const quality of format.qualities) {
            const canvas = document.createElement('canvas');
            canvas.width = canvas.height = size;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#000';             // JPEG has no transparency
            ctx.fillRect(0, 0, size, size);
            ctx.drawImage(img, (img.width - side) / 2, (img.height - side) / 2, side, side,
                          0, 0, size, size);
            const url = canvas.toDataURL(format.type, quality);
            if ((url.length - url.indexOf(',') - 1) * 3 / 4 <= format.max) return url;
        }
    }
    throw new Error('the picture is too detailed - try another one');
}

async function pickAvatar(file) {
    if (!file) return;
    let png;
    let jpg;
    try {
        const img = await loadImage(file);
        png = squareImage(img, AVATAR_PNG);
        jpg = squareImage(img, AVATAR_JPEG);
    } catch (e) {
        return toast(e.message, 'bad');
    }
    const result = await callApi('save_avatar', png, jpg);
    if (!result.ok) return toast(result.error, 'bad');
    state.avatar = result.avatar;
    renderAvatar();
    toast('picture set', 'good');
    const target = onlineTarget();
    if (target) sendAvatar(target);
}

/* The server files a picture under whoever it knows at the sender's address: the host once its
   own server listens (hence the retries), a guest after identify. */
async function sendAvatar(ip, attempts = 1) {
    if (!state.avatar) return;
    for (let i = 0; i < attempts; i++) {
        const result = await callApi('upload_avatar', ip);
        if (result.ok) return;
        if (i === attempts - 1) return toast(`picture not sent: ${result.error}`, 'warn');
        await new Promise((done) => setTimeout(done, 1000));
    }
}

/* A picture that did not get through used to stay missing until it was picked again: the host
   sends it only in the first seconds of its server, a guest once after identify. So whenever the
   ONLINE NOW list shows this player without one, it goes again - quietly, at most every 30 s, and
   a toast only when the same reason comes back twice. */
const AVATAR_RESEND_MS = 30000;
let avatarResentAt = 0;
let avatarResendError = '';

async function resendMissingAvatar(target, players) {
    if (!state.avatar || !players || Date.now() - avatarResentAt < AVATAR_RESEND_MS) return;
    const mine = players.find((p) => (state.mode === 'host' ? p.local : p.uid === state.save.id));
    if (!mine || mine.avatar) return;
    avatarResentAt = Date.now();
    const result = await callApi('upload_avatar', target);
    if (!result.ok && result.error === avatarResendError) {
        toast(`picture not sent: ${result.error}`, 'warn');
    }
    avatarResendError = result.ok ? '' : result.error;
}

/* Right-click on the picture: gone here, and from the host's server when connected. */
async function clearAvatar() {
    if (!state.avatar) return;
    const result = await callApi('clear_avatar', onlineTarget());
    if (result.local === false) return toast(result.error, 'bad');
    state.avatar = '';
    renderAvatar();
    toast(result.ok ? 'picture removed' : result.error, result.ok ? 'good' : 'warn');
    pollOnline();
}

/* Whose server to ask: our own while it runs, or the one this launcher connected to. */
function onlineTarget() {
    if (state.mode === 'host') return state.serverRunning ? '127.0.0.1' : '';
    return state.joinedIp;
}

function renderOnline() {
    $$('.online-list').forEach((list) => {
        list.dataset.empty = state.known ? state.onlineNote : '';
        list.replaceChildren(...(state.online || []).map((p) => {
            const row = document.createElement('li');
            row.className = 'online-row';
            const pic = document.createElement('span');
            pic.className = 'online-avatar';
            if (p.avatar) pic.append(avatarImg(p.avatar));
            else pic.textContent = (p.name || '?').slice(0, 2).toUpperCase();
            const name = document.createElement('span');
            name.className = 'online-name';
            name.textContent = p.name || `#${p.uid}`;
            row.append(pic, name);
            /* "local" is the server's own player, i.e. the host. */
            const you = state.mode === 'host' ? p.local : p.uid === state.save.id;
            const tags = [p.local ? 'HOST' : '', you ? 'YOU' : ''].filter(Boolean).join(' · ');
            if (tags) {
                const tag = document.createElement('span');
                tag.className = 'online-tag';
                tag.textContent = tags;
                row.append(tag);
            }
            return row;
        }));
    });
}

let onlineBusy = false;

async function pollOnline() {
    if (onlineBusy) return;
    const target = onlineTarget();
    if (!target) {
        state.online = null;
        state.onlineNote = state.mode === 'host' ? 'start the server to see who is in'
                                                 : 'connect to see who is in';
        return renderOnline();
    }
    onlineBusy = true;
    try {
        const result = await callApi('fetch_players', target);
        state.online = result.players;
        state.onlineNote = result.ok ? 'nobody logged in yet' : 'the server does not answer';
        if (result.ok) await resendMissingAvatar(target, result.players);
    } finally {
        onlineBusy = false;
    }
    renderOnline();
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
    state.firewall = fresh.firewall;
    state.serverRunning = fresh.server_running;
    state.maxGuests = fresh.max_guests;
    state.addresses = fresh.addresses;
    state.eaApp = fresh.ea_app;
    state.save = fresh.save;
    state.avatar = fresh.avatar || '';
    $('#appVersion').textContent = fresh.version ? '· v' + fresh.version : '';
    state.players = await callApi('get_players');

    const config = fresh.config;
    state.mode = config.mode || 'host';
    /* No name yet: offer the EA nickname the EA App last gave the game (ea_identity.ea_profile). */
    const name = config.local_persona || (fresh.save && fresh.save.persona) || '';
    $('#persona').value = name;
    $('#guestName').value = name;
    if (fresh.save && fresh.save.persona) {
        $('#persona').placeholder = fresh.save.persona;
        $('#guestName').placeholder = fresh.save.persona;
    }
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

    /* With an old line outside the block, "on" is not really on - TURN ON
       (hosts_on) is what takes that line out. */
    if (state.hosts.active && !(state.hosts.foreign || []).length) {
        const result = await callApi('hosts_off');
        if (!result.ok) return toast(result.error, 'bad');
        toastRemoved(result);
        toast('hosts restored, DNS cache flushed', 'good');
    } else {
        if (!ip) return toast('enter the server address', 'bad');
        const result = await callApi('hosts_on', ip);
        if (!result.ok) return toast(result.error, 'bad');
        toastRemoved(result);
        toast(`gosredirector.ea.com -> ${ip}`, 'good');
    }
    state.hosts = await callApi('hosts_status');
}

function toastRemoved(result) {
    (result.removed || []).forEach((line) =>
        toast(`removed an old hosts entry: ${line}`, 'warn'));
}

async function toggleFirewall() {
    if (state.firewall[state.mode]) {
        /* Every launcher rule, both modes - the P2P one is shared between them anyway. */
        const result = await callApi('firewall_off');
        if (!result.ok) return toast(result.error, 'bad');
        toast(`rules removed: ${result.removed.length}`, 'good');
    } else {
        /* A host's rules cover only the address the players reach it on (localip),
           when it is one of this PC's - commands.firewall_commands checks that. */
        const localIp = state.mode === 'host' ? $('#publicIp').value.trim() : '';
        const result = await callApi('firewall_rules', state.mode, localIp);
        if (!result.ok) return toast(result.error, 'bad');
        toast(`rules added: ${result.rules.length}`, 'good');
    }
    state.firewall = await callApi('firewall_status');
}

async function makeCert() {
    const result = await callApi('make_cert');
    if (!result.ok) return toast(result.error, 'bad');
    state.cert = true;
    toast('certificate ready', 'good');
}

async function toggleServer() {
    if (state.serverRunning) {
        serverStopRequested = true;
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
    if (result.log) appendLog([`--- the whole run is saved to ${result.log} (LOGS) ---`]);
    toast(`server up (PID ${result.pid})`, 'good');
    persist();
    sendAvatar('127.0.0.1', 10);        // the server takes a moment to listen
}

async function connectAsClient() {
    const ip = $('#serverIp').value.trim();
    if (!ip) return toast('enter the server address from the host', 'bad');
    /* The server cannot learn it anywhere else - the game never sends its EA nickname. */
    const name = $('#guestName').value.trim();
    if (!name) return toast('enter your name - the other players see you under it', 'warn');

    if (!state.hosts.active || state.hosts.ip !== ip || (state.hosts.foreign || []).length) {
        const result = await callApi('hosts_on', ip);
        if (!result.ok) return toast(result.error, 'bad');
        toastRemoved(result);
        state.hosts = await callApi('hosts_status');
    }
    persist();

    /* The launcher talks to the host by address, the game by name - so the
       launcher reaching the host proves nothing about the game. Ask Windows what
       the game will get. */
    const resolved = await callApi('resolved_redirector');
    if (resolved[0] !== ip) {
        return toast(`the game would go to ${resolved[0] || 'nowhere'}, not to ${ip} - `
                     + 'another gosredirector.ea.com entry in hosts wins; game not started', 'bad');
    }

    /* Before the game starts: its first login has to find the id already registered. A failure
       is not fatal - the game still runs, only its progress will not stick. */
    const ident = await callApi('identify', ip, name);
    state.save = { id: ident.id, user: ident.user, saves: ident.saves,
                   source: ident.source, persona: ident.persona };
    toast(ident.ok ? `career save ${ident.id} and name ${name} sent to the host`
                   : `${ident.error} - progress may not be saved`,
          ident.ok ? 'good' : 'warn');
    state.joinedIp = ip;
    if (ident.ok) sendAvatar(ip);       // filed under the id identify just registered
    pollOnline();

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
    onPending('[data-action="firewall-toggle"]', toggleFirewall);
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
    $('#btnOpenLogs').onclick = openLogs;

    ['#persona', '#publicIp', '#serverIp'].forEach((sel) => {
        $(sel).oninput = () => { renderAddressChips(); renderIpHint(); renderCommandPreview(); persist(); };
    });
    /* One name per machine: hosting or joining, it is the same player. The host field is what
       persist() reads, so the guest field writes through to it. */
    $('#guestName').oninput = () => {
        $('#persona').value = $('#guestName').value;
        $('#persona').oninput();
    };
    const syncHostName = $('#persona').oninput;
    $('#persona').oninput = () => { $('#guestName').value = $('#persona').value; syncHostName(); };

    $$('[data-avatar-pick]').forEach((button) => {
        button.onclick = () => $('#avatarFile').click();
        button.oncontextmenu = (e) => { e.preventDefault(); clearAvatar(); };
    });
    $('#avatarFile').onchange = (e) => {
        pickAvatar(e.target.files[0]);
        e.target.value = '';            // the same file picked again still fires
    };
}

const ONLINE_POLL_MS = 3000;

/* Bind and paint immediately - the bridge catches up on its own. */
runLoader();
bind();
render();
whenReady.then(refreshState).then(() => {
    pollOnline();
    setInterval(pollOnline, ONLINE_POLL_MS);
});
