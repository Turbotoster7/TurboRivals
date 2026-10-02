/* =========================================
   TURBORIVALS LAUNCHER - interface logic

   Nothing here waits on the Python bridge to become usable. pywebview only
   injects it once navigation completes, so the UI binds and paints first, and
   every backend call queues behind `whenReady`. The first answer is a quick
   snapshot; the slow checks (tasklist, ipconfig, netsh, the EA App's log)
   arrive one by one as "probe" events and fill the window in as they land.

   Work is kept to what can be seen: renders are batched per frame, the log is
   only drawn while its page is open, and nothing polls while the window is
   hidden or minimized.
   ========================================= */
'use strict';

const C = window.TRCore;
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const PROCESS_POLL_MS = 8000;      // EA App / game running - players start the EA App late
const ONLINE_POLL_MS = 3000;
const FOCUS_REFRESH_MS = 5000;     // at most one look at processes/adapters per window focus burst
const LOG_KEEP = 6000;             // lines held for filtering and copying
const LOG_RENDER = 1500;           // lines in the DOM at once
const EVENTS_KEEP = 40;

const state = {
    ready: false,
    version: '',
    windows: true,
    mode: 'host',
    page: 'session',
    hidden: false,                 // minimized or otherwise not visible: no polling, no drawing
    admin: null,
    canEditHosts: false,
    processes: null,               // {known, ea_app, game}
    addresses: null,               // [{ip, adapter, kind}]
    suggested: '',
    save: null,                    // ea_identity.resolve(), with the pick from Career save
    savePicking: false,            // a choose_save call is out
    firewall: null,                // {supported, ok, rules}
    ports: null,                   // {ok, ports, server?}
    hosts: {},
    cert: false,
    server: { running: false },
    serverStarting: false,
    players: [],
    maxGuests: 5,
    avatar: '',
    config: {},
    name: '',
    publicIp: '',
    serverIp: '',
    recent: [],
    hostTest: null,                // {ip, result, running}
    online: null,                  // ONLINE NOW, null = nobody to ask
    onlineError: '',
    joinedIp: '',
    connect: { running: false, steps: {} },
    logView: 'key',
    logTab: 'server',
    logDirty: false,               // lines arrived while the log was not drawn
    setupOpen: null,               // null: open while something needs doing; true/false: the player's choice
    follow: true,
    search: '',
    counts: { warn: 0, error: 0 },
    events: [],
    activity: [],
    projectUrl: 'https://github.com/Turbotoster7/TurboRivals',
};

/* =======================================================================
   BRIDGE
   ======================================================================= */
const whenReady = new Promise((resolve) => {
    if (window.pywebview && window.pywebview.api) {
        resolve(window.pywebview.api);
    } else {
        window.addEventListener('pywebviewready', () => resolve(window.pywebview.api), { once: true });
    }
});

const lastError = { text: '', at: 0 };

/* Every backend call goes through here, so a click landing before the bridge is up
   queues instead of throwing on a null api - and a Python exception becomes a toast
   (once: the same error from a timer every few seconds is not news). */
async function api(name, ...args) {
    const bridge = await whenReady;
    try {
        return await bridge[name](...args);
    } catch (e) {
        const message = (e && e.message) || String(e);
        logActivity('error', `${name}: ${message}`);
        const text = `Something went wrong (${name}): ${message}`;
        if (text !== lastError.text || Date.now() - lastError.at > 30000) toast(text, 'error');
        Object.assign(lastError, { text, at: Date.now() });
        throw Object.assign(e instanceof Error ? e : new Error(message), { reported: true });
    }
}

/* The packaged launcher has no developer tools: a script error lands in the launcher log, and
   with it in the bug report. A failed api() call is in there already. */
window.addEventListener('error', (e) => {
    logActivity('error', `script error: ${e.message} (${String(e.filename || '').split('/').pop()}:${e.lineno})`);
});
window.addEventListener('unhandledrejection', (e) => {
    if (e.reason && e.reason.reported) return;
    logActivity('error', `script error: ${(e.reason && e.reason.message) || e.reason}`);
});

/* Events pushed from Python: window.TR.on(event, payload). */
window.TR = {
    on(event, payload) {
        if (event === 'probe') applyProbe(payload.name, payload.value);
        else if (event === 'log') appendLog(payload);
        else if (event === 'server-exit') onServerExit(payload);
        else if (event === 'window') setHidden(!!payload.hidden);
    },
};

/* =======================================================================
   SMALL HELPERS
   ======================================================================= */
const now = () => new Date().toLocaleTimeString([], { hour12: false });
const svg = (name, cls = 'ico') => `<svg class="${cls}"><use href="#i-${name}"/></svg>`;

function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
        if (key === 'class') node.className = value;
        else if (key === 'html') node.innerHTML = value;
        else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
        else if (value !== undefined && value !== null && value !== false) node.setAttribute(key, value);
    }
    for (const child of children) {
        if (child === null || child === undefined || child === false) continue;
        node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
}

function escapeHtml(text) {
    return String(text).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function toast(message, tone = 'info', ms = 4600) {
    const icon = { ok: 'check', warn: 'alert', error: 'alert', info: 'info' }[tone] || 'info';
    const node = el('div', { class: 'toast', 'data-tone': tone, html: svg(icon) }, el('span', {}, message));
    $('#toasts').append(node);
    while ($('#toasts').childElementCount > 4) $('#toasts').firstElementChild.remove();
    setTimeout(() => {
        node.classList.add('out');
        setTimeout(() => node.remove(), 200);
    }, ms);
}

function logActivity(level, text) {
    state.activity.push({ time: now(), level, text });
    if (state.activity.length > 300) state.activity.shift();
    if (state.page === 'logs' && state.logTab === 'activity' && !state.hidden) renderActivity();
}

function addEvent(level, text) {
    state.events.unshift({ time: now().slice(0, 5), level, text });
    state.events.length = Math.min(state.events.length, EVENTS_KEEP);
    render();
}

/* Disables a button for the length of a slow action, so a second click cannot start it twice
   and the button says that something is happening. */
async function busy(button, fn) {
    if (!button || button.dataset.busy) return undefined;
    button.dataset.busy = '1';
    button.classList.add('pending');
    button.disabled = true;
    try {
        return await fn();
    } finally {
        delete button.dataset.busy;
        button.classList.remove('pending');
        button.disabled = false;
        render();
    }
}

async function copyText(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (e) { /* not a secure context - fall back below */ }
    const area = el('textarea', { style: 'position:fixed;opacity:0;left:-9999px' });
    area.value = text;
    document.body.append(area);
    area.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    area.remove();
    return ok;
}

let persistTimer = null;
/* Debounced: typing a name should not write config.json on every keystroke. Only the fields
   typed here - the player list lives in Python and is saved there. */
function persist() {
    clearTimeout(persistTimer);
    persistTimer = setTimeout(() => {
        api('save_config', {
            mode: state.mode,
            local_persona: state.name.trim(),
            public_ip: state.publicIp.trim(),
            server_ip: state.serverIp.trim(),
            log_view: state.logView,
        }).catch(() => {});
    }, 400);
}

/* =======================================================================
   STATE IN
   ======================================================================= */
function applySnapshot(snap) {
    state.ready = true;
    state.version = snap.version;
    state.windows = snap.windows;
    state.config = snap.config;
    state.mode = snap.config.mode;
    state.admin = snap.admin;
    state.canEditHosts = snap.can_edit_hosts;
    state.hosts = snap.hosts;
    state.cert = snap.cert;
    state.server = snap.server;
    state.avatar = snap.avatar || '';
    state.players = snap.players;
    state.maxGuests = snap.max_guests;
    state.recent = snap.config.recent_servers || [];
    state.name = snap.config.local_persona || '';
    state.publicIp = snap.config.public_ip || '';
    state.serverIp = snap.config.server_ip || '';
    state.logView = C.LOG_VIEWS[snap.config.log_view] ? snap.config.log_view : 'key';
    state.logTab = state.mode === 'client' && !state.server.running ? 'activity' : 'server';
    state.projectUrl = snap.project_url || state.projectUrl;
    $('#nameInput').value = state.name;
    $('#publicIp').value = state.publicIp;
    $('#serverIp').value = state.serverIp;
    $('#appVersion').textContent = state.version ? `v${state.version}` : '';
    $('#aboutVersion').textContent = state.version ? `v${state.version}` : '';
    if (state.server.running) {
        state.ports = { ok: true, server: true, ports: [] };
        appendLog([`--- the server was already running (PID ${state.server.pid}) ---`]);
    }
}

function applyProbe(name, value) {
    performance.mark(`probe ${name}`);       // startup timing, read by app.py --self-test
    if (!value || value.error) {
        logActivity('warn', `check "${name}" failed: ${(value && value.error) || 'no answer'}`);
        if (name === 'ports') state.ports = null;
        return render();
    }
    if (name === 'processes') {
        const was = state.processes;
        state.processes = value;
        if (was && was.known && was.ea_app !== value.ea_app) {
            logActivity(value.ea_app ? 'ok' : 'warn', value.ea_app ? 'EA App started' : 'EA App closed');
        }
    } else if (name === 'addresses') {
        state.addresses = value.list;
        state.suggested = value.suggested;
        if (!state.publicIp && value.suggested) {
            state.publicIp = value.suggested;
            $('#publicIp').value = value.suggested;
            persist();
        }
    } else if (name === 'save') {
        state.save = value;
        /* No name yet: offer the EA nickname the EA App last gave the game (ea_identity.ea_profile). */
        if (!state.name && value.persona) {
            state.name = value.persona;
            $('#nameInput').value = value.persona;
            persist();
        }
        $('#nameInput').placeholder = value.persona || 'Nickname';
    } else if (name === 'firewall') {
        state.firewall = value;
    } else if (name === 'ports') {
        state.ports = value;
    }
    return render();
}

async function refresh(names) {
    try {
        const result = await api('refresh', names || null);
        if (result.hosts) state.hosts = result.hosts;
        if (typeof result.admin === 'boolean') state.admin = result.admin;
        for (const [name, value] of Object.entries(result)) {
            if (!['hosts', 'admin'].includes(name)) applyProbe(name, value);
        }
    } catch (e) { /* already reported */ }
    render();
}

/* =======================================================================
   RENDER - batched: any number of render() calls in one task paint once
   ======================================================================= */
let renderQueued = false;

function render() {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => {
        renderQueued = false;
        renderNow();
    });
}

function checkInput() {
    return {
        mode: state.mode, admin: state.admin, processes: state.processes, cert: state.cert,
        hosts: state.hosts, firewall: state.firewall, ports: state.ports, serverIp: state.serverIp,
    };
}

function blockerInput() {
    return {
        mode: state.mode, name: state.name, cert: state.cert, publicIp: state.publicIp,
        ports: state.ports, server: state.server, serverIp: state.serverIp,
    };
}

function renderNow() {
    document.body.dataset.mode = state.mode;
    document.body.dataset.page = state.page;
    document.body.dataset.live = String(state.mode === 'host' && !!state.server.running);
    const list = C.checks(checkInput());
    renderNav(list);
    if (state.page === 'session') {
        renderHeader(list);
        renderChecks(list);
        renderSession();
        renderStatus();
        renderRoster();
        renderEvents();
    } else if (state.page === 'logs') {
        renderLogsPage();
    } else if (state.page === 'settings') {
        renderSettings();
    }
}

/* --- sidebar --------------------------------------------------------- */
function overallStatus(list) {
    const sum = C.summary(list);
    const online = (state.online || []).length;
    if (!state.ready) return ['', 'Starting\u2026'];
    if (state.mode === 'host' && state.server.running) return ['live', `Server live \u00b7 ${online} online`];
    if (state.mode === 'client' && state.joinedIp) return ['live', `Connected \u00b7 ${online} online`];
    if (sum.pending) return ['', 'Checking\u2026'];
    if (sum.problems) return ['warn', `${sum.problems} to fix`];
    return ['ok', state.mode === 'host' ? 'Ready to host' : 'Ready to join'];
}

function renderNav(list) {
    $$('.nav-item').forEach((item) => {
        const nav = item.dataset.nav;
        const active = state.page === 'session' ? nav === state.mode : nav === state.page;
        item.classList.toggle('active', active);
        item.setAttribute('aria-current', active ? 'page' : 'false');
    });
    const problems = state.counts.warn + state.counts.error;
    const badge = $('#navLogBadge');
    badge.hidden = !problems;
    badge.textContent = problems;
    badge.classList.toggle('error', state.counts.error > 0);
    const [tone, label] = overallStatus(list);
    $('#profileDot').dataset.tone = tone;
    $('#profileStatus').textContent = label;
    $('#profileName').textContent = C.cleanName(state.name) || 'Set your name';
    $('#profileAvatar').replaceChildren(state.avatar ? avatarNode(state.avatar) : document.createTextNode(initials(state.name)));
}

/* --- page header and banner ------------------------------------------ */
function renderHeader(list) {
    const host = state.mode === 'host';
    const blockers = C.blockers(blockerInput());
    const running = state.server.running;
    $('#pageTitle').textContent = host ? 'Host a session' : 'Join a session';
    let sub;
    if (host) {
        sub = running ? `Server live \u00b7 players connect to ${state.publicIp.trim() || 'this PC'}`
            : 'Run the server on this PC - your friends join you over your network or a VPN.';
    } else {
        sub = state.joinedIp ? `Connected to ${state.joinedIp}` : 'Connect to a friend who hosts - over your network or a VPN.';
    }
    $('#pageSub').textContent = sub;

    const serverButton = $('#btnServer');
    if (!serverButton.dataset.busy) {
        serverButton.className = `btn ${running ? 'btn-danger' : 'btn-primary'} host-only`;
        serverButton.innerHTML = running ? `${svg('stop', 'ico ico-fill')}<span>Stop server</span>`
            : `${svg('play', 'ico ico-fill')}<span>${state.serverStarting ? 'Starting\u2026' : 'Start server'}</span>`;
        serverButton.disabled = !running && blockers.length > 0;
        serverButton.title = !running && blockers.length ? blockers.join(' \u00b7 ') : '';
    }
    const connectButton = $('#btnConnect');
    if (!connectButton.dataset.busy) {
        connectButton.innerHTML = state.joinedIp ? `${svg('refresh')}<span>Reconnect</span>`
            : `${svg('play', 'ico ico-fill')}<span>Connect &amp; play</span>`;
        connectButton.disabled = blockers.length > 0 || state.connect.running;
        connectButton.title = blockers.length ? blockers.join(' \u00b7 ') : '';
    }
    const game = state.processes && state.processes.game;
    const gameButton = $('#btnGame');
    if (!gameButton.dataset.busy) {
        gameButton.disabled = !!game;
        gameButton.querySelector('span').textContent = game ? 'Game running' : 'Launch game';
    }

    /* the banner: what stops the big button, or the most common silent failure */
    const banner = $('#banner');
    const fixable = fixPlan(list);
    const eaMissing = state.processes && state.processes.known && !state.processes.ea_app;
    if (blockers.length && !(host && running)) {
        banner.hidden = false;
        banner.dataset.tone = 'warn';
        $('#bannerText').innerHTML = `<b>Before you can ${host ? 'start' : 'connect'}:</b> <span>${blockers.map(escapeHtml).join(' \u00b7 ')}</span>`;
    } else if (eaMissing) {
        banner.hidden = false;
        banner.dataset.tone = 'warn';
        $('#bannerText').innerHTML = '<b>The EA App is not running.</b> <span>Start it and sign in - without it the game cannot log in.</span>';
    } else {
        banner.hidden = true;
    }
    const bannerFix = $('#bannerFix');
    if (!bannerFix.dataset.busy) bannerFix.hidden = banner.hidden || !fixable.length;
}

/* --- setup ----------------------------------------------------------- */
function checkCopy(check) {
    const s = check.status;
    const hosts = state.hosts || {};
    const host = state.mode === 'host';
    switch (check.id) {
    case 'admin':
        return { detail: s === 'pending' ? 'Checking\u2026' : s === 'ok' ? 'Running elevated'
            : 'Needed for the hosts file and the firewall', action: s === 'ok' ? null : 'Restart as admin' };
    case 'eaApp':
        return { detail: { pending: 'Checking\u2026', ok: 'Running - the game can log in',
            warn: 'Not running - start it and sign in', na: "Can't check on this system" }[s],
        tip: s === 'warn' ? 'Without the EA App the game gets no Origin token: it connects, then drops before logging in. Checked again every few seconds.' : '' };
    case 'cert':
        return { detail: s === 'ok' ? 'Ready' : 'Missing - generate it once', action: s === 'ok' ? null : 'Generate' };
    case 'hosts': {
        if (hosts.error) return { detail: `Can't read the hosts file: ${hosts.error}`, action: null };
        if ((hosts.foreign || []).length) {
            return { detail: `An old entry sends the game to ${hosts.effective_ip || '?'}`,
                tip: `"${hosts.foreign.join('", "')}" sits outside the launcher's block and wins over it. Fix removes it (a backup is made).`, action: 'Fix' };
        }
        if (!host && !check.target && !hosts.active) {
            return { detail: "Enter the host's address first", action: 'Turn on', disabled: true };
        }
        if (!hosts.active) {
            return { detail: host ? 'Off - the game still looks for EA\u2019s servers' : `Off - will point at ${check.target}`,
                action: host ? 'Turn on' : 'Point at host' };
        }
        if (check.target && hosts.ip !== check.target) {
            return { detail: `Points at ${hosts.ip}, not ${host ? 'this PC' : check.target}`, action: host ? 'Fix' : 'Point at host' };
        }
        return { detail: `gosredirector.ea.com \u2192 ${hosts.ip}`, tip: hosts.path ? `Written to ${hosts.path}` : '', action: 'Turn off', ghost: true };
    }
    case 'firewall': {
        if (s === 'pending') return { detail: 'Checking\u2026' };
        if (s === 'na') return { detail: 'Windows only' };
        const rules = state.firewall.rules || [];
        const bad = rules.filter((r) => r.state !== 'ok');
        const tip = rules.map((r) => `${r.name}: ${r.proto} ${r.ports} - ${r.state}`).join('\n');
        const scope = state.firewall.scope ? ` on ${state.firewall.scope}` : '';
        if (!bad.length) return { detail: rules.length === 1 ? 'Game traffic allowed (UDP 3659)' : `All ${rules.length} rules in place${scope}`, tip, action: 'Remove', ghost: true };
        const outdated = bad.some((r) => r.state === 'outdated');
        return { detail: `${bad.length} of ${rules.length} ${outdated ? 'missing or outdated' : 'missing'}`, tip, action: outdated ? 'Update' : 'Add rules' };
    }
    case 'ports': {
        if (s === 'pending') return { detail: 'Checking\u2026', action: null };
        if (state.ports.server) return { detail: 'In use by your server', action: null };
        const tip = state.ports.ports.map((p) => `${p.proto} ${p.port} (${p.purpose}): ${p.free ? 'free' : p.process ? `taken by ${p.process}` : 'taken'}`).join('\n');
        if (s === 'ok') return { detail: `All ${state.ports.ports.length} free`, tip, action: null };
        const taken = state.ports.ports.filter((p) => !p.free && !p.own);
        const first = taken[0];
        const who = first.closing ? 'still closing' : first.process || 'another program';
        return { detail: `${first.proto} ${first.port}: ${who}${taken.length > 1 ? ` (+${taken.length - 1} more)` : ''}`, tip, action: 'Check again', ghost: true };
    }
    default:
        return { detail: '' };
    }
}

function renderChecks(list) {
    const ids = new Set(list.map((c) => c.id));
    for (const row of $$('#checkList .check')) {
        const check = list.find((c) => c.id === row.dataset.check);
        row.hidden = !ids.has(row.dataset.check);
        if (!check) continue;
        row.dataset.status = check.status;
        const copy = checkCopy(check);
        row.querySelector('.check-detail').textContent = copy.detail || '';
        row.title = copy.tip || copy.detail || '';
        const button = row.querySelector('[data-fix]');
        if (button && !button.dataset.busy) {
            button.hidden = !copy.action;
            if (copy.action) button.textContent = copy.action;
            button.className = `btn btn-sm ${copy.ghost ? 'btn-ghost' : 'btn-secondary'}`;
            button.disabled = !!copy.disabled;
        }
    }
    const sum = C.summary(list);
    const allSet = state.ready && !sum.pending && !sum.problems;
    $('#setupCount').textContent = !state.ready ? '\u2013' : allSet ? 'All set' : `${sum.ready} of ${sum.total} ready`;
    const bar = $('#setupBar');
    bar.style.width = `${sum.total ? (100 * sum.ready) / sum.total : 0}%`;
    bar.parentElement.dataset.tone = allSet ? 'ok' : '';
    /* While a session runs only a red check reopens setup - warnings would push "Online now"
       below the fold, and the banner still names a missing EA App. */
    const live = state.mode === 'host' ? !!state.server.running : !!state.joinedIp;
    const broken = list.some((c) => c.status === 'error');
    const open = state.setupOpen === null ? (live ? broken : !allSet) : state.setupOpen;
    $('#setupCard').classList.toggle('collapsed', !open);
    $('#setupToggle').setAttribute('aria-expanded', String(open));
    const fixable = fixPlan(list);
    const fixAll = $('#btnFixAll');
    if (!fixAll.dataset.busy) fixAll.disabled = !fixable.length;
    fixAll.title = fixable.length ? `Will: ${fixable.map((f) => f.label).join(', ')}` : 'Nothing to fix';
}

/* --- you / session --------------------------------------------------- */
function avatarNode(src) {
    const img = el('img', { alt: '' });
    img.src = src;
    return img;
}

function initials(name) {
    const clean = C.cleanName(name) || '?';
    return clean.replace(/[^A-Za-z0-9]/g, '').slice(0, 2).toUpperCase() || clean.slice(0, 2);
}

function renderSession() {
    const host = state.mode === 'host';
    const typed = state.name.trim();
    const seen = C.cleanName(typed);
    const note = $('#nameNote');
    const persona = state.save && state.save.persona;
    note.dataset.tone = '';
    if (!typed) {
        note.dataset.tone = 'warn';
        note.innerHTML = persona ? `Needed - <button class="link" data-use-persona>use your EA name ${escapeHtml(persona)}</button>`
            : 'Needed - the other players see you under it';
    } else if (!seen) {
        note.dataset.tone = 'error';
        note.textContent = 'No letters the game can show - use Latin letters or digits';
    } else if (seen !== typed) {
        note.innerHTML = `Others see you as <span class="mono">${escapeHtml(seen)}</span> (the game shows plain ASCII)`;
    } else if (persona && typed !== persona) {
        note.innerHTML = `Your EA name is ${escapeHtml(persona)} - <button class="link" data-use-persona>use it</button>`;
    } else {
        note.textContent = host ? 'What the other players see' : 'Sent to the host when you connect';
    }
    /* The host's name goes to the server when it starts; a change now would only show later. */
    const locked = host && state.server.running;
    $('#nameInput').disabled = locked;
    if (locked) {
        note.dataset.tone = '';
        note.textContent = 'Fixed while the server runs - stop it to change your name';
    }
    $('#nameInput').setAttribute('aria-invalid', String(!!typed && !seen));
    $('#avatarImg').replaceChildren(state.avatar ? avatarNode(state.avatar) : document.createTextNode(initials(state.name)));
    if (host) {
        renderAdapters();
        renderIpNote();
        renderGuests();
    } else {
        renderRecent();
        renderHostNote();
    }
    renderSave();
}

const KIND_ICON = { vpn: 'lock', lan: 'lan', virtual: 'ghost' };
const KIND_TAG = { vpn: 'VPN', lan: 'Network', virtual: 'Virtual' };

function renderAdapters() {
    const box = $('#adapterList');
    const key = JSON.stringify([state.addresses, state.publicIp.trim()]);
    if (box.dataset.key === key) return;
    box.dataset.key = key;
    if (!state.addresses) {
        box.replaceChildren(el('div', { class: 'options-empty' }, 'Looking at your network adapters\u2026'));
        return;
    }
    if (!state.addresses.length) {
        box.replaceChildren(el('div', { class: 'options-empty' }, 'No network adapter with an IPv4 address found - type the address below.'));
        return;
    }
    box.replaceChildren(...state.addresses.map((a) => {
        const selected = a.ip === state.publicIp.trim();
        return el('button', {
            class: 'option' + (selected ? ' selected' : ''), 'data-kind': a.kind, type: 'button', role: 'radio',
            'aria-checked': String(selected), title: a.kind === 'virtual' ? 'A virtual adapter - no other PC can reach it' : `Use ${a.ip}`,
            html: svg(KIND_ICON[a.kind] || 'lan'),
            onclick: () => {
                state.publicIp = a.ip;
                $('#publicIp').value = a.ip;
                persist();
                render();
            },
        }, el('span', { class: 'option-name' }, a.adapter), el('span', { class: 'option-ip' }, a.ip), el('span', { class: 'option-radio' }));
    }));
}

function renderIpNote() {
    const note = $('#ipNote');
    const value = state.publicIp.trim();
    const picked = (state.addresses || []).find((a) => a.ip === value);
    note.dataset.tone = '';
    $('#publicIp').setAttribute('aria-invalid', String(!!value && !C.validIPv4(value)));
    if (!value) {
        note.textContent = 'Pick the adapter the other players reach you on, or type an address.';
    } else if (!C.validIPv4(value)) {
        note.dataset.tone = 'error';
        note.textContent = 'Not an IPv4 address - it looks like 26.48.21.54 or 192.168.1.10.';
    } else if (!picked) {
        note.textContent = 'Typed by hand - it has to be an address every player can reach: the one your VPN shows, or your network card\u2019s on a shared network.';
    } else if (picked.kind === 'virtual') {
        note.dataset.tone = 'warn';
        note.textContent = `${picked.adapter} is a virtual adapter - no other PC can reach it. Pick your network card or VPN.`;
    } else if (picked.kind === 'vpn') {
        note.textContent = `Players join over ${picked.adapter} - everyone needs that VPN running and connected to you.`;
    } else {
        note.textContent = `Same-network play over ${picked.adapter} - everyone on this network, no VPN needed.`;
    }
}

function renderGuests() {
    const list = $('#guestList');
    const key = JSON.stringify(state.players);
    $('#slotsPill').textContent = `${state.players.length}/${state.maxGuests}`;
    $('#btnAddPlayer').disabled = state.players.length >= state.maxGuests;
    if (list.dataset.key === key) return;
    list.dataset.key = key;
    if (state.players.length) $('#guestFold').open = true;
    list.replaceChildren(...state.players.map(([ip, nick]) => el('li', { class: 'row' },
        el('span', { class: 'avatar avatar-sm' }, initials(nick)),
        el('span', { class: 'row-text' }, el('span', { class: 'row-name', title: nick }, nick), el('span', { class: 'row-sub mono' }, ip)),
        el('button', { class: 'btn btn-ghost btn-icon', title: `Remove ${nick}`, html: svg('x'), onclick: () => removePlayer(nick) }))));
}

function renderRecent() {
    const box = $('#recentList');
    const current = state.serverIp.trim();
    const key = JSON.stringify([state.recent, current]);
    if (box.dataset.key === key) return;
    box.dataset.key = key;
    box.replaceChildren(...state.recent.map((ip) => el('button', {
        class: 'chip' + (ip === current ? ' selected' : ''), type: 'button', title: 'Used before',
        onclick: () => {
            state.serverIp = ip;
            $('#serverIp').value = ip;
            onServerIpChanged();
        },
    }, ip)));
}

function renderHostNote() {
    const note = $('#hostNote');
    const ip = state.serverIp.trim();
    const test = state.hostTest;
    note.dataset.tone = '';
    $('#serverIp').setAttribute('aria-invalid', String(!!ip && !C.validIPv4(ip)));
    if (!ip) {
        note.textContent = 'The host reads it out from their launcher.';
    } else if (!C.validIPv4(ip)) {
        note.dataset.tone = 'error';
        note.textContent = 'Not an IPv4 address - it looks like 26.48.21.54.';
    } else if (test && test.ip === ip && test.running) {
        note.textContent = `Looking for a TurboRivals server at ${ip}\u2026`;
    } else if (test && test.ip === ip && test.result) {
        const r = test.result;
        note.dataset.tone = r.ok ? 'ok' : r.reason === 'refused' ? 'warn' : 'error';
        note.textContent = r.ok ? `Server found \u00b7 ${r.ms} ms \u00b7 ${r.players} online` : r.error;
    } else {
        note.textContent = 'Test shows whether the host\u2019s server answers.';
    }
}

function renderSave() {
    const card = $('#saveCard');
    const save = state.save;
    const host = state.mode === 'host';
    const kind = C.saveState(save);
    card.dataset.state = kind;
    const pill = $('#savePill');
    pill.textContent = { pending: 'Checking', missing: 'Not found', guessed: 'Guessed', chosen: 'Picked', found: 'Found' }[kind];
    pill.dataset.tone = { pending: '', missing: 'error', guessed: 'warn', chosen: 'ok', found: 'ok' }[kind];
    $('#saveId').textContent = kind === 'pending' ? '\u2014' : save.id ? String(save.id) : 'none';
    const used = host ? 'your server logs you in under it' : 'sent to the host when you connect';
    const careers = ((save && save.files) || []).filter((f) => f.kind === 'career').length;
    let text = {
        pending: 'Looking for the EA account on this PC\u2026',
        missing: `No EA App account found on this PC - ${host ? 'your server' : 'the host'} cannot save your progress.`,
        guessed: careers > 1
            ? 'More than one save here could be yours, so this is a guess and your progress may not stick. Pick yours below.'
            : 'No save of this EA account found, so this is a guess and your progress may not stick. Start the game once through the EA App, close it, then check again.',
        chosen: `Picked by you - ${used}. The others' Autolog leaves you out: the server cannot confirm a picked save.`,
        found: save && save.id ? `Found (${save.source}) - ${used}, so your progress sticks. EA account ${save.user}.` : '',
    }[kind];
    if (save && save.chosen_missing) {
        text = `The save you picked (${save.chosen_missing}) is no longer in the folder - back to automatic. ${text}`;
    }
    /* A host's pick goes to the server as --local-id when it starts, a guest's on connect. */
    if (kind !== 'pending' && (host ? state.server.running : state.joinedIp)) {
        text += host ? ' A change applies the next time you start the server.' : ' A change applies the next time you connect.';
    }
    $('#saveText').textContent = text;
    renderSaveList();
}

const SAVE_TAGS = [
    ['profile', 'EA App: your game loads this', 'ok'],
    ['suffix', 'your EA account', 'ok'],
    ['newest', 'written last', 'accent'],
    ['other', 'another EA account', 'warn'],
];
const NOT_A_SAVE = {
    server: 'made up by a TurboRivals server - the game never loads it',
    account: 'your EA App account number, written while it was guessed - the game never loads it',
};

/* "1 Oct, 16:31" - with the year when it is not this one (a save from 2013 is a different story). */
function writtenAt(epoch) {
    if (!epoch) return '';
    const date = new Date(epoch * 1000);
    const year = date.getFullYear() !== new Date().getFullYear() ? { year: 'numeric' } : { hour: '2-digit', minute: '2-digit' };
    return date.toLocaleString('en-GB', { day: 'numeric', month: 'short', ...year });
}

function saveOption(id, picked, name, detail, tags) {
    return el('button', {
        class: 'option save-option' + (picked ? ' selected' : ''), type: 'button', role: 'radio',
        'aria-checked': String(picked), disabled: state.savePicking || undefined,
        html: svg(id ? 'folder' : 'wand'),
        onclick: () => { if (!picked) chooseSave(id); },
    }, el('span', { class: 'option-name' }, name, ...tags), el('span', { class: 'option-ip' }, detail), el('span', { class: 'option-radio' }));
}

/* Career save > Pick your save: the files in the game's settings folder (ea_identity.save_files).
   Only "career" files can be picked; the rest are named with the reason, because a file like
   1100944155289.sav looks just as much like a save (02.10). */
function renderSaveList() {
    const save = state.save;
    const fold = $('#saveFold');
    fold.hidden = !save || !save.user;              // no EA App account: there is nothing to pick for
    if (fold.hidden) return;
    const files = save.files || [];
    const key = JSON.stringify([files, save.id, save.source, save.auto, state.savePicking]);
    if (fold.dataset.key === key) return;
    fold.dataset.key = key;
    const picked = save.source === C.SAVE_CHOSEN ? save.id : 0;
    const careers = files.filter((f) => f.kind === 'career');
    /* Guessed with several candidates: open it, that is what the player has to do. */
    if (C.saveState(save) === 'guessed' && careers.length > 1 && !fold.dataset.opened) {
        fold.open = true;
        fold.dataset.opened = '1';
    }
    $('#saveCount').textContent = String(careers.length);
    const auto = save.auto || {};
    const autoDetail = auto.id ? `${auto.id}${auto.source === C.SAVE_GUESS ? ' (a guess)' : ''}` : 'none';
    const options = [saveOption(0, !picked, 'Automatic', autoDetail, [])];
    careers.forEach((f) => options.push(saveOption(
        f.id, f.id === picked, el('span', { class: 'mono' }, String(f.id)),
        f.written ? `last written ${writtenAt(f.written)}` : '',
        SAVE_TAGS.filter(([flag]) => f[flag]).map(([, label, tone]) => el('span', { class: 'tag', 'data-tone': tone }, label)))));
    if (!careers.length) {
        options.push(el('div', { class: 'options-empty' }, 'No career save of your own on this PC yet - start Rivals once through the EA App with the hosts redirect off, drive until it saves, close it.'));
    }
    $('#saveList').replaceChildren(...options);
    const others = files.filter((f) => NOT_A_SAVE[f.kind]);
    $('#saveOthers').replaceChildren(...(others.length ? [el('b', {}, 'Not career saves:')] : []),
        ...others.map((f) => el('div', {}, el('span', { class: 'mono' }, `${f.id}.sav`), ` - ${NOT_A_SAVE[f.kind]}`)));
}

async function chooseSave(id) {
    if (state.savePicking) return;
    state.savePicking = true;
    render();
    try {
        const result = await api('choose_save', id);
        if (!result || !result.ok) {
            toast((result && result.error) || 'could not pick that save', 'error');
            return;
        }
        state.save = result.save;
        const when = state.mode === 'host' ? 'next server start' : 'next connect';
        logActivity('ok', id ? `career save ${id} picked - used from the ${when}` : 'career save back to automatic');
        toast(id ? `Save ${id} picked` : 'Career save: automatic', 'ok');
    } finally {
        state.savePicking = false;
        render();
    }
}

/* --- server / connection --------------------------------------------- */
function renderStatus() {
    const host = state.mode === 'host';
    const pill = $('#serverPill');
    const blockers = C.blockers(blockerInput());
    if (host) {
        const running = state.server.running;
        $('#statusTitle').textContent = 'Server';
        $('#serverCard').dataset.state = running ? 'live' : 'off';
        pill.dataset.tone = running ? 'live' : state.serverStarting ? 'warn' : '';
        $('#serverState').textContent = running ? 'Running' : state.serverStarting ? 'Starting' : 'Stopped';
        $('#serverAddr').textContent = state.publicIp.trim() || '\u2014';
        $('#hostBlockers').replaceChildren(...(running ? [] : blockers).map((b) => el('li', {}, b)));
        tickUptime();
    } else {
        const joined = !!state.joinedIp;
        $('#statusTitle').textContent = 'Connection';
        pill.dataset.tone = joined ? 'live' : state.connect.running ? 'warn' : '';
        $('#serverState').textContent = joined ? 'Connected' : state.connect.running ? 'Connecting' : 'Not connected';
        $('#joinBlockers').replaceChildren(...blockers.map((b) => el('li', {}, b)));
        renderSteps();
    }
}

function renderSteps() {
    for (const li of $$('#connectSteps li')) {
        const step = state.connect.steps[li.dataset.step];
        li.dataset.status = step ? step.status : '';
        li.querySelector('.step-note').textContent = step ? step.note || '' : '';
    }
}

function tickUptime() {
    if (state.hidden || state.page !== 'session') return;
    const up = $('#serverUptime');
    up.textContent = state.server.running && state.server.started_at
        ? C.formatUptime(Date.now() / 1000 - state.server.started_at) : '\u2014';
}

function renderRoster() {
    const list = $('#roster');
    const players = state.online || [];
    $('#onlineCount').textContent = players.length ? `${players.length} of 6` : '';
    const key = JSON.stringify([players.map((p) => [p.uid, p.name, p.avatar ? p.avatar.length : 0, p.local]), state.mode, state.onlineError, onlineTarget()]);
    if (list.dataset.key === key) return;
    list.dataset.key = key;
    if (!players.length) {
        const target = onlineTarget();
        const text = !target ? (state.mode === 'host' ? 'Start the server to see who is in.' : 'Connect to see who is in.')
            : state.onlineError ? `The server does not answer: ${state.onlineError}`
                : 'Nobody is in yet - a game shows up here once it is online.';
        list.replaceChildren(el('li', { class: 'empty' }, text));
        return;
    }
    list.replaceChildren(...players.map((p) => {
        const you = state.mode === 'host' ? p.local : state.save && p.uid === state.save.id;
        const pic = el('span', { class: 'avatar avatar-sm' }, p.avatar ? avatarNode(p.avatar) : initials(p.name || `#${p.uid}`));
        const tags = el('span', { class: 'row-tags' },
            p.local ? el('span', { class: 'tag', 'data-tone': 'accent' }, 'Host') : null,
            you ? el('span', { class: 'tag' }, 'You') : null);
        return el('li', { class: 'row' }, pic, el('span', { class: 'row-name', title: p.name }, p.name || `#${p.uid}`), tags);
    }));
}

function renderEvents() {
    const list = $('#eventList');
    const key = `${state.events.length}:${state.events[0] ? state.events[0].time + state.events[0].text : ''}`;
    if (list.dataset.key === key) return;
    list.dataset.key = key;
    if (!state.events.length) {
        list.replaceChildren(el('li', { class: 'empty' }, 'Joins, leaves and the server\u2019s hints show up here.'));
        return;
    }
    list.replaceChildren(...state.events.map((e) => el('li', { 'data-level': e.level, title: e.text }, el('time', {}, e.time), el('span', {}, e.text))));
}

/* --- logs and settings pages ----------------------------------------- */
function renderLogsPage() {
    const running = state.server.running;
    const problems = state.counts.warn + state.counts.error;
    $('#logsSub').textContent = state.logTab === 'activity' ? 'Every change the launcher made, newest last'
        : running ? `Server live \u00b7 ${logLines.length} lines \u00b7 every run is also saved to the log folder`
            : logLines.length ? `Server stopped \u00b7 ${logLines.length} lines` : 'The server is not running';
    $$('#logTabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === state.logTab));
    $$('#logViews button').forEach((b) => b.classList.toggle('active', b.dataset.view === state.logView));
    $('#logViews').hidden = state.logTab !== 'server';
    $('#logView').hidden = state.logTab !== 'server';
    $('#activityView').hidden = state.logTab !== 'activity';
    const count = $('#countProblems');
    count.hidden = !problems;
    count.textContent = problems;
    $('#cmdPreview').textContent = state.mode === 'host' ? C.commandPreview({ name: state.name, publicIp: state.publicIp.trim(), players: state.players }) : '';
    $('#btnClearLog').title = state.logTab === 'server' ? 'Clear the window - the log file keeps everything' : 'Clear the activity list';
    if (state.logDirty) {
        state.logDirty = false;
        if (state.logTab === 'server') rebuildLog();
        else renderActivity();
    }
}

function renderSettings() {
    $$('#restorePref button').forEach((b) => b.classList.toggle('active', b.dataset.pref === (state.config.restore_hosts_on_exit || 'ask')));
    $('#keepCaptures').checked = !!state.config.keep_captures;
}

/* =======================================================================
   NAVIGATION AND VISIBILITY
   ======================================================================= */
function setPage(page) {
    if (page === state.page) return;
    state.page = page;
    if (page === 'logs') state.logDirty = true;          // drawn on demand, see appendLog
    $('#main').scrollTop = 0;
    render();
}

async function setMode(mode) {
    const changed = mode !== state.mode;
    state.mode = mode;
    setPage('session');
    if (!changed) return;
    state.firewall = null;
    previousRoster = null;
    if (!state.server.running) state.logTab = mode === 'client' ? 'activity' : 'server';
    render();
    /* Saved before the refresh, not debounced: the firewall probe reads the mode from it. */
    await api('save_config', { mode });
    refresh(['firewall']);
    pollOnline();
    if (mode === 'client' && C.validIPv4(state.serverIp) && !state.hostTest) testHost();
}

/* Minimized (pushed from Python) or hidden (the page's own visibility): nothing polls and
   nothing draws; coming back catches up in one go. */
function setHidden(hidden) {
    if (hidden === state.hidden) return;
    state.hidden = hidden;
    if (hidden) return;
    state.logDirty = true;
    render();
    refreshOnReturn();
    pollOnline();
}

let lastFocusRefresh = 0;
function refreshOnReturn() {
    if (!state.ready || Date.now() - lastFocusRefresh < FOCUS_REFRESH_MS) return;
    lastFocusRefresh = Date.now();
    refresh(['processes', 'addresses']);
}

/* =======================================================================
   SERVER LOG
   ======================================================================= */
const logLines = [];               // {time, text, level}

function logVisible() {
    return state.page === 'logs' && state.logTab === 'server' && !state.hidden;
}

function renderLogEmpty() {
    const text = state.mode === 'host'
        ? (state.server.running ? 'Waiting for the server\u2026' : 'The server is not running. Start it, and its log appears here - also saved to a file for bug reports.')
        : 'Joining players have no server log - the host has it. Your launcher\u2019s own steps are under "Launcher".';
    $('#logView').replaceChildren(el('div', { class: 'log-empty' }, text));
}

function lineMatches(line) {
    if (!C.inView(line.level, state.logView)) return false;
    return !state.search || line.text.toLowerCase().includes(state.search);
}

function lineNode(line) {
    return el('div', { class: 'ln', 'data-level': line.level }, el('time', {}, line.time), line.text || ' ');
}

/* Python hands over a batch every 100 ms. The lines are classified and kept; the DOM is only
   touched while the log is on screen - otherwise the page draws them when it is opened. */
function appendLog(batch) {
    const lines = Array.isArray(batch) ? batch : [batch];
    if (!lines.length) return;
    const time = now();
    const fresh = [];
    for (const text of lines) {
        const line = { time, text, level: C.classifyLine(text) };
        logLines.push(line);
        fresh.push(line);
        if (line.level === 'error') state.counts.error++;
        if (line.level === 'warn' || line.level === 'hint') state.counts.warn++;
        const insight = C.insightFrom(text);
        if (insight) {
            addEvent(insight.level, insight.text);
            if (insight.level !== 'warn') toast(insight.text, insight.level === 'error' ? 'error' : 'warn', 7000);
        }
    }
    if (logLines.length > LOG_KEEP) logLines.splice(0, logLines.length - LOG_KEEP);
    if (!logVisible()) {
        state.logDirty = true;
        render();                      // the sidebar badge
        return;
    }
    const view = $('#logView');
    const empty = view.querySelector('.log-empty');
    if (empty) empty.remove();
    const stuck = view.scrollHeight - view.scrollTop - view.clientHeight < 40;
    const fragment = document.createDocumentFragment();
    fresh.filter(lineMatches).forEach((line) => fragment.append(lineNode(line)));
    view.append(fragment);
    for (let over = view.childElementCount - LOG_RENDER; over > 0; over--) view.firstElementChild.remove();
    if (state.follow && stuck) view.scrollTop = view.scrollHeight;
    render();
}

function rebuildLog() {
    const view = $('#logView');
    if (!logLines.length) return renderLogEmpty();
    const matching = logLines.filter(lineMatches).slice(-LOG_RENDER);
    if (!matching.length) {
        view.replaceChildren(el('div', { class: 'log-empty' }, state.search ? `No line contains "${state.search}".` : 'Nothing in this view yet.'));
        return undefined;
    }
    const fragment = document.createDocumentFragment();
    matching.forEach((line) => fragment.append(lineNode(line)));
    view.replaceChildren(fragment);
    view.scrollTop = view.scrollHeight;
    return undefined;
}

function clearLog() {
    logLines.length = 0;
    state.counts = { warn: 0, error: 0 };
    renderLogEmpty();
    render();
}

function renderActivity() {
    const view = $('#activityView');
    const shown = state.activity.filter((a) => !state.search || a.text.toLowerCase().includes(state.search));
    if (!shown.length) {
        view.replaceChildren(el('div', { class: 'log-empty' }, state.activity.length ? `No entry contains "${state.search}".`
            : 'Nothing yet - every change the launcher makes (hosts, firewall, connecting) is listed here.'));
        return;
    }
    const level = (l) => ({ ok: 'ok', warn: 'warn', error: 'error' }[l] || 'event');
    view.replaceChildren(...shown.map((a) => el('div', { class: 'ln', 'data-level': level(a.level) }, el('time', {}, a.time), a.text)));
    view.scrollTop = view.scrollHeight;
}

/* =======================================================================
   ACTIONS - SETUP
   ======================================================================= */
function hostsTarget() {
    return state.mode === 'host' ? '127.0.0.1' : (C.validIPv4(state.serverIp) ? state.serverIp.trim() : '');
}

/* Hosting, the redirect points at 127.0.0.1 - your own game has to reach the server on this
   machine. The --public-ip address is a different thing entirely: it is what the server hands
   to OTHER players. Sending your own hosts entry there makes the server see you arriving from
   a LAN address, treat you as a remote player and name you Player_<last octet> instead of your
   own name (lobby.py LOCAL_IPS). */
async function setRedirect(on) {
    const target = hostsTarget();
    if (on && !target) return toast("Enter the host's address first", 'warn');
    const result = on ? await api('hosts_on', target) : await api('hosts_off');
    if (result.status) state.hosts = result.status;
    if (!result.ok) {
        toast(result.error, 'error');
        logActivity('error', `hosts: ${result.error}`);
        if (result.needs_admin) offerAdmin();
        return render();
    }
    (result.removed || []).forEach((line) => {
        toast(`Removed an old hosts entry: ${line}`, 'warn');
        logActivity('warn', `hosts: removed an old entry "${line}"`);
    });
    logActivity('ok', on ? `redirect on: gosredirector.ea.com \u2192 ${target}` : 'redirect off, hosts restored');
    toast(on ? `Redirect on \u2192 ${target}` : 'Redirect off - hosts restored', 'ok');
    return render();
}

/* A host's rules are limited to the address it picked - the VPN or LAN the players share, not
   every network this PC is on (commands.firewall_scope). */
async function addFirewallRules() {
    const result = await api('firewall_rules', state.mode, state.mode === 'host' ? state.publicIp.trim() : '');
    if (!result.ok) {
        toast(result.error, 'error');
        logActivity('error', `firewall: ${result.error}`);
        if (result.needs_admin) offerAdmin();
        return;
    }
    if (result.status) state.firewall = result.status;
    const added = result.rules || [];
    logActivity('ok', added.length ? `firewall rules added: ${added.join(', ')}` : 'firewall rules already in place');
    toast(added.length ? `Firewall: ${added.length} rule${added.length > 1 ? 's' : ''} added` : 'Firewall rules already in place', 'ok');
}

/* Every launcher rule, either mode - when done playing, or before switching to a PC that hosts. */
async function removeFirewallRules() {
    const result = await api('firewall_off');
    if (!result.ok) {
        toast(result.error, 'error');
        if (result.needs_admin) offerAdmin();
        return;
    }
    const removed = result.removed || [];
    logActivity('ok', removed.length ? `firewall rules removed: ${removed.join(', ')}` : 'no firewall rules to remove');
    toast(removed.length ? 'Firewall rules removed' : 'No firewall rules to remove', 'ok');
    await refresh(['firewall']);
}

async function makeCert() {
    const result = await api('make_cert');
    if (!result.ok) {
        toast(result.error, 'error');
        logActivity('error', result.error);
        return;
    }
    state.cert = true;
    logActivity('ok', 'server certificate generated');
    toast('Certificate ready', 'ok');
}

async function relaunchAsAdmin() {
    const result = await api('relaunch_as_admin');
    if (!result.ok) toast(result.error, 'warn');
}

function offerAdmin() {
    if (state.admin) return;
    toast('That needs administrator rights - use "Restart as admin" in Setup.', 'warn', 6000);
    const row = $('[data-check="admin"]');
    row.animate([{ background: 'rgba(255,157,0,.14)' }, { background: 'transparent' }], { duration: 1400 });
}

/* What "Fix all" will do, in order. Without administrator rights only what does not need
   them - the rest waits for the restart. */
function fixPlan(list) {
    const status = Object.fromEntries(list.map((c) => [c.id, c.status]));
    const plan = [];
    if (status.cert === 'warn') plan.push({ id: 'cert', label: 'generate the certificate' });
    const needsAdmin = [];
    if ((status.hosts === 'warn' || status.hosts === 'error') && hostsTarget() && !(state.hosts || {}).error) {
        needsAdmin.push({ id: 'hosts', label: 'turn the redirect on' });
    }
    if (status.firewall === 'warn') needsAdmin.push({ id: 'firewall', label: 'add the firewall rules' });
    if (needsAdmin.length && !state.canEditHosts && !state.admin) plan.push({ id: 'admin', label: 'restart as administrator' });
    else plan.push(...needsAdmin);
    return plan;
}

async function fixEverything() {
    const plan = fixPlan(C.checks(checkInput()));
    for (const step of plan) {
        if (step.id === 'cert') await makeCert();
        if (step.id === 'hosts') await setRedirect(true);
        if (step.id === 'firewall') await addFirewallRules();
        if (step.id === 'admin') return relaunchAsAdmin();
        render();
    }
    await refresh(['firewall', 'ports']);
    return undefined;
}

async function runFix(id, button) {
    await busy(button, async () => {
        if (id === 'admin') return relaunchAsAdmin();
        if (id === 'cert') return makeCert();
        if (id === 'firewall') return state.firewall && state.firewall.ok ? removeFirewallRules() : addFirewallRules();
        if (id === 'ports') return refresh(['ports']);
        if (id === 'hosts') {
            const check = C.checks(checkInput()).find((c) => c.id === 'hosts');
            return setRedirect(check.status !== 'ok');
        }
        return undefined;
    });
}

/* =======================================================================
   ACTIONS - SESSION
   ======================================================================= */
async function addPlayer() {
    const nick = $('#newNick').value.trim();
    const ip = $('#newIp').value.trim();
    const result = await api('add_player', nick, ip);
    if (!result.ok) return toast(result.error, 'warn');
    state.players = result.players;
    logActivity('ok', `player listed: ${nick} at ${ip}`);
    $('#newNick').value = '';
    $('#newIp').value = '';
    $('#newNick').focus();
    return render();
}

async function removePlayer(nick) {
    const result = await api('remove_player', nick);
    state.players = result.players;
    logActivity('ok', `player removed: ${nick}`);
    render();
}

let hostTestTimer = null;
function onServerIpChanged() {
    state.serverIp = $('#serverIp').value;
    persist();
    clearTimeout(hostTestTimer);
    const ip = state.serverIp.trim();
    if (C.validIPv4(ip) && (!state.hostTest || state.hostTest.ip !== ip)) {
        hostTestTimer = setTimeout(() => testHost(), 900);
    }
    render();
}

async function testHost() {
    const ip = state.serverIp.trim();
    if (!C.validIPv4(ip)) return render();
    state.hostTest = { ip, running: true };
    render();
    const result = await api('test_host', ip);
    if (state.serverIp.trim() !== ip) return undefined;      // typed on meanwhile
    state.hostTest = { ip, result };
    logActivity(result.ok ? 'ok' : 'warn', result.ok ? `host ${ip} answers (${result.ms} ms)` : `host ${ip}: ${result.error}`);
    return render();
}

/* --- picture ---------------------------------------------------------------
   The picture is kept on this machine and sent to the host's server, which hands every
   launcher in the session the list of who is logged in, with pictures (commands.py).
   Two copies: a small PNG for the launchers, a JPEG for the game (the server answers its
   ByteVault profile picture requests with it - the game links libjpeg). The first size, or
   quality, that fits the format's limit wins. The game's copy stays within 16 KB: the pictures
   known to work were 8-15 KB, and up to 1.0.9 a bigger one (a detailed photo made 20-40 KB)
   went out as one oversized TLS record and dropped the game a few seconds into a session. */
const AVATAR_MAX = 64 * 1024;
const AVATAR_PNG = { type: 'image/png', sizes: [128, 96, 64], qualities: [undefined], max: AVATAR_MAX };
const AVATAR_JPEG = { type: 'image/jpeg', sizes: [256, 192, 128, 96],
                      qualities: [0.85, 0.7, 0.55, 0.4], max: 16 * 1024 };

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

/* Scaled and centre-cropped here, so nothing but a small square picture ever leaves this
   machine - whatever size or format the photo was. */
function squareImage(img, format) {
    const side = Math.min(img.width, img.height);
    for (const size of format.sizes) {
        for (const quality of format.qualities) {
            const canvas = document.createElement('canvas');
            canvas.width = canvas.height = size;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#000';             // JPEG has no transparency
            ctx.fillRect(0, 0, size, size);
            ctx.drawImage(img, (img.width - side) / 2, (img.height - side) / 2, side, side, 0, 0, size, size);
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
        toast(e.message, 'error');
        return;
    }
    const result = await api('save_avatar', png, jpg);
    if (!result.ok) {
        toast(result.error, 'error');
        return;
    }
    state.avatar = result.avatar;
    render();
    toast('Picture set', 'ok');
    logActivity('ok', 'picture changed');
    const target = onlineTarget();
    if (target) sendAvatar(target);
}

/* The server files a picture under whoever it knows at the sender's address: the host once
   its own server listens (hence the retries), a guest after identify. */
async function sendAvatar(ip, attempts = 1) {
    if (!state.avatar) return;
    for (let i = 0; i < attempts; i++) {
        const result = await api('upload_avatar', ip);
        if (result.ok) return;
        if (i === attempts - 1) {
            toast(`Picture not sent: ${result.error}`, 'warn');
            return;
        }
        await new Promise((done) => setTimeout(done, 1000));
    }
}

/* =======================================================================
   ACTIONS - PLAY
   ======================================================================= */
async function toggleServer() {
    if (state.server.running) {
        const result = await api('stop_server');
        if (!result.ok) toast(result.error, 'error');
        return;
    }
    state.serverStarting = true;
    render();
    let result;
    try {
        result = await api('start_server', state.name.trim(), state.publicIp.trim(), 'online');
    } finally {
        state.serverStarting = false;
    }
    if (!result.ok) {
        if (result.ports) state.ports = result.ports;
        toast(result.error, 'error', 8000);
        logActivity('error', result.error);
        addEvent('error', result.error);
        render();
        return;
    }
    state.server = { running: true, pid: result.pid, started_at: Date.now() / 1000, log_path: result.log_path };
    state.ports = { ok: true, server: true, ports: [] };
    state.online = [];
    state.logTab = 'server';
    clearLog();
    appendLog([`--- start: ${C.commandPreview({ name: state.name, publicIp: state.publicIp.trim(), players: state.players })} ---`]);
    logActivity('ok', `server started (PID ${result.pid})${result.log_path ? `, log: ${result.log_path}` : ''}`);
    addEvent('live', 'Server started');
    toast('Server is up - start the game when you are ready', 'ok');
    render();
    sendAvatar('127.0.0.1', 10);        // the server takes a moment to listen
    setTimeout(pollOnline, 1500);
}

/* payload: {code, requested} - a server stopped from here exits non-zero as well
   (TerminateProcess leaves 1), so only an exit nobody asked for is a crash. */
function onServerExit(payload) {
    const code = payload && typeof payload === 'object' ? payload.code : payload;
    const crashed = !(payload && payload.requested) && code !== 0;
    state.server = { running: false, exit_code: code };
    state.online = null;
    previousRoster = null;
    appendLog([crashed ? `--- server exited (code ${code}) ---` : '--- server stopped ---']);
    addEvent(crashed ? 'error' : 'event', crashed ? `Server stopped unexpectedly (code ${code})` : 'Server stopped');
    toast(crashed ? `The server stopped (code ${code}) - the log says why` : 'Server stopped', crashed ? 'error' : 'info', crashed ? 8000 : 2500);
    logActivity(crashed ? 'error' : 'ok', crashed ? `server exited with code ${code}` : 'server stopped');
    if (crashed) {
        state.logTab = 'server';
        setPage('logs');
    }
    refresh(['ports']);
    render();
}

async function launchGame() {
    const result = await api('launch_game');
    if (!result.ok) {
        toast(result.error, 'error');
        logActivity('error', result.error);
        return result;
    }
    logActivity('ok', result.running ? 'the game is already running' : `game launched via ${result.via}`);
    toast(result.running ? 'The game is already running' : `Launching via ${result.via}`, 'ok');
    setTimeout(() => refresh(['processes']), 5000);
    return result;
}

async function connect() {
    const ip = state.serverIp.trim();
    const name = state.name.trim();
    if (C.blockers(blockerInput()).length || state.connect.running) return;
    state.connect = { running: true, steps: {} };
    const step = (id, status, note = '') => {
        state.connect.steps[id] = { status, note };
        render();
    };
    render();
    /* the checklist is the answer to the click - bring it into view */
    $('#connectCard').closest('.card').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    try {
        /* 1. hosts - also takes out an older line that would win over the block */
        step('redirect', 'run');
        const hosts = state.hosts || {};
        if (!hosts.active || hosts.ip !== ip || (hosts.foreign || []).length) {
            const result = await api('hosts_on', ip);
            if (result.status) state.hosts = result.status;
            if (!result.ok) {
                step('redirect', 'fail', result.error);
                if (result.needs_admin) offerAdmin();
                logActivity('error', `connect: ${result.error}`);
                return;
            }
            (result.removed || []).forEach((line) => logActivity('warn', `hosts: removed an old entry "${line}"`));
            logActivity('ok', `redirect on: gosredirector.ea.com \u2192 ${ip}`);
        }
        step('redirect', 'ok', `gosredirector.ea.com \u2192 ${ip}`);

        /* 2. The launcher talks to the host by address, the game by name - so the launcher
           reaching the host proves nothing about the game. Ask Windows what the game gets. */
        step('dns', 'run');
        const resolved = await api('resolved_redirector');
        if (resolved[0] !== ip) {
            step('dns', 'fail', `The game would reach ${resolved[0] || 'nothing'}, not ${ip} - another entry wins. Game not started.`);
            logActivity('error', `connect: the name resolves to ${resolved[0] || 'nothing'}`);
            return;
        }
        step('dns', 'ok', `The game will reach ${ip}`);

        /* 3. Before the game starts: its first login has to find the id already registered. A
           failure is not fatal - the game still runs, only its progress will not stick. */
        step('identify', 'run');
        const ident = await api('identify', ip, name);
        if (ident.id !== undefined) {
            const { ok, error, reason, backup, ...save } = ident;     // the rest is save_identity()
            state.save = save;
        }
        if (ident.ok) {
            step('identify', 'ok', `Save ${ident.id} as ${C.cleanName(name)}`);
            state.recent = [ip, ...state.recent.filter((r) => r !== ip)].slice(0, 6);
            logActivity('ok', `career save ${ident.id} and name ${C.cleanName(name)} sent to ${ip}`);
        } else {
            step('identify', 'warn', `${ident.error} - progress may not be saved`);
            logActivity('warn', `identify: ${ident.error}`);
        }
        state.joinedIp = ip;
        previousRoster = null;
        addEvent('live', `Connected to ${ip}`);
        pollOnline();

        /* 4. picture - filed under the id identify just registered */
        if (!state.avatar) step('picture', 'skip', 'No picture set');
        else if (!ident.ok) step('picture', 'skip', 'Skipped - the host does not know you yet');
        else {
            step('picture', 'run');
            const up = await api('upload_avatar', ip);
            step('picture', up.ok ? 'ok' : 'warn', up.ok ? 'Everyone sees it' : up.error);
        }

        /* 5. the game */
        step('launch', 'run');
        const launched = await api('launch_game');
        if (launched.ok) {
            step('launch', 'ok', launched.running ? 'Already running' : `Via ${launched.via}`);
            logActivity('ok', launched.running ? 'the game is already running' : `game launched via ${launched.via}`);
            toast('Redirect active - the game is starting. In the game: Search for session.', 'ok', 6000);
            setTimeout(() => refresh(['processes']), 5000);
        } else {
            step('launch', 'fail', launched.error);
            logActivity('error', launched.error);
        }
    } catch (e) {
        Object.entries(state.connect.steps).forEach(([id, s]) => { if (s.status === 'run') step(id, 'fail', 'Interrupted'); });
    } finally {
        state.connect.running = false;
        render();
    }
}

/* A picture that did not get through used to stay missing until it was picked again: the host
   sends it only in the first seconds of its server, a guest once after identify. So whenever
   ONLINE NOW shows this player without one, it goes again - quietly, at most every 30 s, and a
   toast only when the same reason comes back twice. */
const AVATAR_RESEND_MS = 30000;
let avatarResentAt = 0;
let avatarResendError = '';

async function resendMissingAvatar(target, players) {
    if (!state.avatar || !players || Date.now() - avatarResentAt < AVATAR_RESEND_MS) return;
    const myId = state.save && state.save.id;
    const mine = players.find((p) => (state.mode === 'host' ? p.local : p.uid === myId));
    if (!mine || mine.avatar) return;
    avatarResentAt = Date.now();
    let result;
    try {
        result = await api('upload_avatar', target);
    } catch (e) {
        return;                                        // reported by api()
    }
    if (!result.ok && result.error === avatarResendError) toast(`Picture not sent: ${result.error}`, 'warn');
    avatarResendError = result.ok ? '' : result.error;
}

/* Right-click on the picture: gone here, and from the host's server when connected. */
async function clearAvatar() {
    if (!state.avatar) return;
    const result = await api('clear_avatar', onlineTarget() || '');
    if (result.local === false) {
        toast(result.error, 'error');
        return;
    }
    state.avatar = '';
    render();
    toast(result.ok ? 'Picture removed' : result.error, result.ok ? 'ok' : 'warn');
    logActivity('ok', 'picture removed');
    pollOnline();
}

/* --- ONLINE NOW --------------------------------------------------------- */
/* Whose server to ask: our own while it runs, or the one this launcher connected to. */
function onlineTarget() {
    if (state.mode === 'host') return state.server.running ? '127.0.0.1' : '';
    return state.joinedIp;
}

let onlineBusy = false;
let previousRoster = null;

async function pollOnline() {
    if (onlineBusy || !state.ready || state.hidden) return;
    const target = onlineTarget();
    if (!target) {
        if (state.online !== null) {
            state.online = null;
            render();
        }
        return;
    }
    onlineBusy = true;
    try {
        const result = await api('fetch_players', target);
        if (target !== onlineTarget()) return;
        state.online = result.players;
        state.onlineError = result.ok ? '' : result.error;
        if (result.ok) {
            if (previousRoster) {
                const diff = C.rosterDiff(previousRoster, result.players);
                diff.joined.forEach((p) => {
                    addEvent('ok', `${p.name || `#${p.uid}`} joined`);
                    if (!(state.mode === 'host' && p.local)) toast(`${p.name || `#${p.uid}`} joined the session`, 'ok', 3500);
                });
                diff.left.forEach((p) => addEvent('event', `${p.name || `#${p.uid}`} left`));
            }
            previousRoster = result.players;
            resendMissingAvatar(target, result.players);
        }
    } catch (e) {
        /* reported by api() */
    } finally {
        onlineBusy = false;
    }
    render();
}

/* =======================================================================
   DIALOGS
   ======================================================================= */
let modalOpener = null;            // focus goes back there when the last dialog closes

function openModal(id) {
    const modal = document.getElementById(id);
    if (!topModal()) modalOpener = document.activeElement;
    modal.hidden = false;
    const focus = modal.querySelector('.btn-primary, .choice, button');
    if (focus) setTimeout(() => focus.focus(), 30);
}

function closeModal(id) {
    document.getElementById(id).hidden = true;
    if (!topModal() && modalOpener && document.contains(modalOpener)) modalOpener.focus();
}

function topModal() {
    return $$('.modal').filter((m) => !m.hidden).pop();
}

/* Tab and Shift+Tab go round inside an open dialog instead of into the page behind it. */
function keepFocusIn(modal, e) {
    const items = $$('button:not([disabled]), input:not([disabled]), textarea, [tabindex]:not([tabindex="-1"])', modal)
        .filter((node) => node.offsetParent !== null);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (!modal.contains(document.activeElement)) {
        e.preventDefault();
        first.focus();
    } else if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
    }
}

async function openReport() {
    openModal('reportModal');
    const area = $('#reportText');
    area.value = 'Gathering\u2026';
    try {
        const diag = await api('diagnostics');
        const log = logLines.filter((l) => l.level !== 'noise').map((l) => l.text);
        area.value = C.buildReport(diag, { activity: state.activity, log });
    } catch (e) {
        area.value = 'Could not gather the diagnostics.';
    }
}

function requestClose() {
    const pref = state.config.restore_hosts_on_exit || 'ask';
    const active = !!(state.hosts && state.hosts.active);
    if (active && pref === 'ask') {
        $('#closeText').innerHTML = `<span class="mono">gosredirector.ea.com</span> still points at <span class="mono">${escapeHtml(state.hosts.ip || '?')}</span>. `
            + 'Left in place it breaks the EA App and other EA games until it is removed. Keep it only if you are still playing.';
        $('#closeRemember').checked = false;
        openModal('closeModal');
        return;
    }
    quit(active && pref === 'always');
}

async function quit(restore) {
    const result = await api('quit', restore);
    if (result && !result.ok) toast(result.error, 'error');
}

async function closeWith(restore) {
    if ($('#closeRemember').checked) {
        await api('save_config', { restore_hosts_on_exit: restore ? 'always' : 'never' });
        state.config.restore_hosts_on_exit = restore ? 'always' : 'never';
    }
    closeModal('closeModal');
    quit(restore);
}

async function saveSetting(changes) {
    Object.assign(state.config, changes);
    render();
    await api('save_config', changes);
}

/* =======================================================================
   BINDING
   ======================================================================= */
function bind() {
    $('#btnMinimize').onclick = () => api('minimize');
    $('#btnClose').onclick = requestClose;
    $$('.nav-item').forEach((item) => {
        item.onclick = () => {
            const nav = item.dataset.nav;
            if (nav === 'host' || nav === 'client') setMode(nav);
            else if (nav === 'help') openReport();
            else setPage(nav);
        };
    });
    $('#profileCard').onclick = () => {
        setPage('session');
        setTimeout(() => $('#nameInput').focus(), 50);
    };

    /* setup */
    $$('[data-fix]').forEach((button) => { button.onclick = () => runFix(button.dataset.fix, button); });
    $('#btnFixAll').onclick = (e) => busy(e.currentTarget, fixEverything);
    $('#bannerFix').onclick = (e) => busy(e.currentTarget, fixEverything);
    $('#btnRecheck').onclick = (e) => busy(e.currentTarget, () => refresh());

    /* you */
    $('#nameInput').oninput = () => { state.name = $('#nameInput').value; persist(); render(); };
    $('#publicIp').oninput = () => { state.publicIp = $('#publicIp').value; persist(); render(); };
    $('#serverIp').oninput = onServerIpChanged;
    $('#serverIp').onkeydown = (e) => { if (e.key === 'Enter') testHost(); };
    $('#btnTestHost').onclick = (e) => busy(e.currentTarget, testHost);
    $('#btnCopyIp').onclick = async () => {
        const ip = state.publicIp.trim();
        if (!C.validIPv4(ip)) return toast('Pick or type a valid address first', 'warn');
        return toast(await copyText(ip) ? `${ip} copied - send it to your players` : 'Could not copy - select the address and press Ctrl+C', 'ok');
    };
    $('#btnAddPlayer').onclick = addPlayer;
    $('#newIp').onkeydown = (e) => { if (e.key === 'Enter') addPlayer(); };
    $('#newNick').onkeydown = (e) => { if (e.key === 'Enter') $('#newIp').focus(); };
    $('#avatarPick').onclick = () => $('#avatarFile').click();
    $('#avatarPick').oncontextmenu = (e) => {
        e.preventDefault();
        clearAvatar();
    };
    $('#avatarFile').onchange = (e) => {
        pickAvatar(e.target.files[0]);
        e.target.value = '';            // the same file picked again still fires
    };
    document.addEventListener('click', (e) => {
        if (e.target.closest('[data-use-persona]') && state.save && state.save.persona) {
            state.name = state.save.persona;
            $('#nameInput').value = state.name;
            persist();
            render();
        }
    });

    /* play */
    $('#btnServer').onclick = (e) => busy(e.currentTarget, toggleServer);
    $('#btnConnect').onclick = (e) => busy(e.currentTarget, connect);
    $('#btnGame').onclick = (e) => busy(e.currentTarget, launchGame);
    $('#serverLogLink').onclick = () => api('open_folder', 'logs');
    $('#btnCopyAddr').onclick = async () => {
        const ip = state.publicIp.trim();
        if (!C.validIPv4(ip)) return toast('Pick the address players connect to first', 'warn');
        return toast(await copyText(ip) ? `${ip} copied - send it to your players` : 'Could not copy', 'ok');
    };
    $('#setupToggle').onclick = () => {
        state.setupOpen = $('#setupCard').classList.contains('collapsed');
        render();
    };

    /* logs */
    $$('#logTabs button').forEach((b) => {
        b.onclick = () => { state.logTab = b.dataset.tab; state.logDirty = true; render(); };
    });
    $$('#logViews button').forEach((b) => {
        b.onclick = () => { state.logView = b.dataset.view; state.logDirty = true; persist(); render(); };
    });
    let searchTimer = null;
    $('#logSearch').oninput = () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => { state.search = $('#logSearch').value.trim().toLowerCase(); state.logDirty = true; render(); }, 150);
    };
    $('#followLog').onchange = () => { state.follow = $('#followLog').checked; };
    $('#btnClearLog').onclick = () => {
        if (state.logTab === 'activity') {
            state.activity = [];
            renderActivity();
            return;
        }
        clearLog();
        toast('Window cleared - the log file still has everything', 'info', 2500);
    };
    $('#btnLogFolder').onclick = () => api('open_folder', 'logs');
    $('#btnCopyLog').onclick = async () => {
        const source = state.logTab === 'server' ? logLines.map((l) => l.text) : state.activity.map((a) => `${a.time} ${a.text}`);
        if (!source.length) return toast('Nothing to copy yet', 'info', 2000);
        return toast(await copyText(source.join('\n')) ? `${source.length} lines copied` : 'Could not copy', 'ok', 2500);
    };

    /* settings */
    $$('#restorePref button').forEach((b) => { b.onclick = () => saveSetting({ restore_hosts_on_exit: b.dataset.pref }); });
    $('#keepCaptures').onchange = () => saveSetting({ keep_captures: $('#keepCaptures').checked });
    $$('[data-folder]').forEach((b) => {
        b.onclick = async () => {
            const result = await api('open_folder', b.dataset.folder);
            if (!result.ok) toast(result.error, 'warn');
        };
    });
    $$('[data-link]').forEach((b) => { b.onclick = () => api('open_url', state.projectUrl + b.dataset.link); });

    /* dialogs */
    $$('[data-close]').forEach((b) => { b.onclick = () => closeModal(b.closest('.modal').id); });
    $$('.modal').forEach((m) => m.addEventListener('mousedown', (e) => { if (e.target === m && m.id !== 'welcomeModal') closeModal(m.id); }));
    $$('[data-choose]').forEach((b) => {
        b.onclick = () => {
            closeModal('welcomeModal');
            setMode(b.dataset.choose);
            api('save_config', { onboarded: true, mode: b.dataset.choose });
        };
    });
    $('#btnReportCopy').onclick = async () => toast(await copyText($('#reportText').value) ? 'Report copied - paste it into the issue' : 'Could not copy - select the text and press Ctrl+C', 'ok');
    $('#btnReportIssue').onclick = () => api('open_url', `${state.projectUrl}/issues/new/choose`);
    $('#btnReportLogs').onclick = () => api('open_folder', 'logs');
    $('#btnCloseKeep').onclick = () => closeWith(false);
    $('#btnCloseRestore').onclick = () => closeWith(true);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const modal = topModal();
            if (modal && modal.id !== 'welcomeModal') closeModal(modal.id);
        }
        if (e.key === 'Tab' && topModal()) keepFocusIn(topModal(), e);
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l') {
            e.preventDefault();
            setPage(state.page === 'logs' ? 'session' : 'logs');
        }
    });
    document.addEventListener('visibilitychange', () => setHidden(document.hidden));
    window.addEventListener('focus', refreshOnReturn);
}

/* =======================================================================
   BOOT SCREEN (the 1.0 launcher's)
   ======================================================================= */
/* The bar creeps towards 90% while waiting and jumps to 100 when the first snapshot is in: it
   tracks readiness instead of inventing progress. Returns finish(); a floor of 600 ms so it does
   not flash, a ceiling of 4 s so a bridge or snapshot that never comes does not trap anyone. */
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
        setTimeout(() => $('#loader').classList.add('done'),
                   Math.max(0, 600 - (Date.now() - started)));
    };
    setTimeout(finish, 4000);
    return finish;
}

/* =======================================================================
   STARTUP
   ======================================================================= */
const loaderDone = runLoader();
bind();
render();

whenReady.then(async () => {
    let snap;
    try {
        snap = await api('get_snapshot');
    } catch (e) {
        // api() has already shown the error. Without this the page stayed "booting" for good:
        // placeholders instead of values and nothing to click.
        document.body.classList.remove('booting');
        loaderDone();
        return;
    }
    applySnapshot(snap);
    document.body.classList.remove('booting');
    loaderDone();
    performance.mark('snapshot');
    render();
    if (snap.first_run) openModal('welcomeModal');
    logActivity('event', `launcher ${snap.version} started${snap.admin ? ' as administrator' : ''}`);
    if (state.mode === 'client' && C.validIPv4(state.serverIp)) testHost();
    lastFocusRefresh = Date.now();
    await refresh();
    setInterval(() => { if (!state.hidden) refresh(['processes']); }, PROCESS_POLL_MS);
    setInterval(tickUptime, 1000);
    setInterval(pollOnline, ONLINE_POLL_MS);
    pollOnline();
});
