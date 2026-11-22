'use strict';

// ------------------------------------------------------------------ helpers

// replaceChildren() would render null as "null" and arrays as text.
function setContent(el, ...nodes) {
  el.replaceChildren(...nodes.flat(Infinity).filter((n) => n != null && n !== false));
}

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value' || k === 'checked' || k === 'selected') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  return el;
}

const MODES = {
  'full': { label: 'Vollzugriff', desc: 'Lesen, Schreiben, Löschen (forget/prune)' },
  'append-only': { label: 'Nur anhängen', desc: 'Lesen und neue Backups, kein Löschen – Schutz vor Ransomware' },
  'read-only': { label: 'Nur lesen', desc: 'Snapshots ansehen und wiederherstellen' },
};
const ROLES = { admin: 'Administrator', user: 'Benutzer' };

const state = { me: null, users: [], shares: [], repos: [], reposInfo: null };

async function api(method, path, body) {
  const opts = { method, headers: { 'X-Requested-With': 'rsui' }, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch('/api' + path, opts);
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty */ }
  if (res.status === 401 && path !== '/login' && path !== '/me') {
    state.me = null;
    renderLogin('Sitzung abgelaufen – bitte erneut anmelden.');
    throw new Error('Sitzung abgelaufen');
  }
  if (!res.ok) throw new Error((data && data.error) || res.statusText);
  return data;
}

function toast(msg, isError) {
  const t = h('div', { class: 'toast' + (isError ? ' error' : '') }, msg);
  document.getElementById('toasts').append(t);
  setTimeout(() => t.remove(), isError ? 6000 : 3000);
}

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1);
  return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0).replace('.', ',') + ' ' + u[i];
}

function fmtDate(s) {
  if (!s) return '–';
  const d = new Date(s);
  return d.toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' });
}

function fmtAgo(s) {
  if (!s) return '–';
  const sec = (Date.now() - new Date(s).getTime()) / 1000;
  if (sec < 90) return 'gerade eben';
  const min = sec / 60;
  if (min < 90) return `vor ${Math.round(min)} Min.`;
  const hrs = min / 60;
  if (hrs < 36) return `vor ${Math.round(hrs)} Std.`;
  const days = hrs / 24;
  return `vor ${Math.round(days)} Tagen`;
}

function genPassword(len = 24) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const buf = new Uint32Array(len);
  crypto.getRandomValues(buf);
  return Array.from(buf, (x) => chars[x % chars.length]).join('');
}

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = h('textarea', { class: 'offscreen' });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    toast('In die Zwischenablage kopiert');
  } catch (e) {
    toast('Kopieren fehlgeschlagen', true);
  }
}

function gatewayBase() {
  if (state.me && state.me.publicUrl) return state.me.publicUrl;
  // No PUBLIC_URL: same host as the UI, with the HTTP or HTTPS gateway port.
  const tls = location.protocol === 'https:';
  const me = state.me || {};
  const port = tls ? (me.gatewayTlsPort || '8444') : (me.gatewayPort || '8000');
  return `${location.protocol}//${location.hostname}:${port}`;
}

function repoUrl(user, path, password) {
  const base = new URL(gatewayBase());
  const auth = encodeURIComponent(user) + ':' + (password ? encodeURIComponent(password) : '<PASSWORT>');
  const p = String(path).split('/').map(encodeURIComponent).join('/');
  return `rest:${base.protocol}//${auth}@${base.host}${base.pathname.replace(/\/$/, '')}/${p}/`;
}

function modeBadge(m) { return h('span', { class: 'badge ' + m, title: MODES[m] ? MODES[m].desc : '' }, MODES[m] ? MODES[m].label : m); }

function codeBox(value) {
  const input = h('input', { type: 'text', readonly: true, value, onfocus: (e) => e.target.select() });
  return h('div', { class: 'codebox' }, input, h('button', { type: 'button', onclick: () => copyText(value) }, 'Kopieren'));
}

function modeSelect(name, value, extra) {
  return h('select', { name, ...extra },
    Object.entries(MODES).map(([k, v]) => h('option', { value: k, selected: k === value }, `${v.label} – ${v.desc}`)));
}

function passwordField(name, label, opts = {}) {
  const input = h('input', { type: 'text', name, autocomplete: 'new-password', required: !opts.optional, minlength: 8, spellcheck: 'false', class: 'mono' });
  return h('label', { class: 'field' }, h('span', {}, label),
    h('div', { class: 'input-row' }, input,
      h('button', { type: 'button', onclick: () => { input.value = genPassword(); input.focus(); } }, 'Generieren')),
    h('small', {}, opts.hint || 'Mindestens 8 Zeichen. Dies ist das Login für den REST-Server, nicht das Repository-Passwort von restic.'));
}

// ------------------------------------------------------------------ dialog

function openDialog({ title, body, submitLabel = 'Speichern', danger = false, onSubmit, cancelLabel = 'Abbrechen', noCancel = false }) {
  const err = h('p', { class: 'error-text', hidden: true });
  const submit = h('button', { type: 'submit', class: danger ? 'danger solid' : 'primary' }, submitLabel);
  const form = h('form', { method: 'dialog' },
    h('header', {}, h('h3', {}, title)),
    h('div', { class: 'dlg-body' }, err, body),
    h('footer', {},
      noCancel ? null : h('button', { type: 'button', onclick: () => dlg.close() }, cancelLabel),
      submit));
  const dlg = h('dialog', {}, form);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!onSubmit) { dlg.close(); return; }
    submit.disabled = true;
    err.hidden = true;
    try {
      const keepOpen = await onSubmit(new FormData(form), form);
      if (!keepOpen) dlg.close();
    } catch (ex) {
      err.textContent = ex.message;
      err.hidden = false;
    } finally {
      submit.disabled = false;
    }
  });
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  const first = form.querySelector('input:not([readonly]),select,textarea');
  if (first) first.focus();
  return dlg;
}

function confirmDialog(title, message, label, action) {
  openDialog({ title, body: h('p', {}, message), submitLabel: label, danger: true, onSubmit: action });
}

function showCredentials(user, path, password) {
  const url = repoUrl(user, path, password);
  const snippet =
`export RESTIC_REPOSITORY="${url}"
export RESTIC_PASSWORD="<Repository-Passwort>"
restic init      # nur beim ersten Mal
restic backup ~/Dokumente`;
  openDialog({
    title: `Zugang für ${user}`,
    submitLabel: 'Schließen', noCancel: true,
    body: [
      password ? h('div', { class: 'callout warn' }, 'Das Passwort wird nur jetzt im Klartext angezeigt. Bitte sicher übermitteln.') : null,
      h('label', { class: 'field' }, h('span', {}, 'Repository-URL'), codeBox(url)),
      h('label', { class: 'field' }, h('span', {}, 'Beispiel (Linux/macOS)'), h('pre', { class: 'snippet' }, snippet)),
      h('p', { class: 'hint' }, 'Weitere Repositories des Benutzers sind als Unterpfad möglich, z. B. ',
        h('code', {}, repoUrl(user, `${user}/laptop`)), '.'),
    ],
  });
}

// ------------------------------------------------------------------ login

function renderLogin(message) {
  const app = document.getElementById('app');
  const err = h('p', { class: 'error-text', hidden: !message }, message || '');
  const btn = h('button', { type: 'submit', class: 'primary' }, 'Anmelden');
  const form = h('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      btn.disabled = true;
      const fd = new FormData(form);
      try {
        await api('POST', '/login', { username: fd.get('username'), password: fd.get('password') });
        await boot();
      } catch (ex) {
        err.textContent = ex.message; err.hidden = false;
      } finally { btn.disabled = false; }
    },
  },
  err,
  h('label', { class: 'field' }, h('span', {}, 'Benutzername'), h('input', { type: 'text', name: 'username', autocomplete: 'username', required: true, autofocus: true })),
  h('label', { class: 'field' }, h('span', {}, 'Passwort'), h('input', { type: 'password', name: 'password', autocomplete: 'current-password', required: true })),
  btn);
  app.replaceChildren(h('div', { class: 'login-wrap' },
    h('div', { class: 'card login' }, h('div', { class: 'card-body' },
      h('div', { class: 'brand' }, h('img', { src: 'favicon.svg', alt: '' }), 'Restic Server UI'),
      form))));
  form.querySelector('input').focus();
}

// ------------------------------------------------------------------ shell

const ROUTES = {
  users: { title: 'Benutzer', admin: true, render: renderUsers },
  shares: { title: 'Freigaben', admin: true, render: renderShares },
  repos: { title: 'Repositories', admin: true, render: renderRepos },
  tls: { title: 'TLS', admin: true, render: renderTLS },
  account: { title: 'Mein Konto', admin: false, render: renderAccount },
};

function isAdmin() { return state.me && state.me.user.role === 'admin'; }

function currentRoute() {
  let r = location.hash.replace(/^#\/?/, '');
  if (!ROUTES[r] || (ROUTES[r].admin && !isAdmin())) r = isAdmin() ? 'users' : 'account';
  return r;
}

function renderShell() {
  const route = currentRoute();
  const nav = h('nav', {}, Object.entries(ROUTES)
    .filter(([, v]) => !v.admin || isAdmin())
    .map(([k, v]) => h('a', { href: '#/' + k, class: k === route ? 'active' : '' }, v.title)));
  const main = h('main', {});
  setContent(document.getElementById('app'),
    h('div', { class: 'topbar' }, h('div', { class: 'topbar-inner' },
      h('div', { class: 'brand' }, h('img', { src: 'favicon.svg', alt: '' }), 'Restic Server UI'),
      nav,
      h('div', { class: 'userbox' },
        h('span', { class: 'who' }, state.me.user.name),
        h('button', { class: 'small', onclick: logout }, 'Abmelden')))),
    main);
  document.title = `${ROUTES[route].title} – Restic Server UI`;
  ROUTES[route].render(main).catch((e) => toast(e.message, true));
}

async function logout() {
  try { await api('POST', '/logout'); } catch (_) { /* ignore */ }
  state.me = null;
  renderLogin();
}

function pageHead(title, subtitle, ...actions) {
  return h('div', { class: 'page-head' },
    h('div', {}, h('h1', {}, title), subtitle ? h('p', {}, subtitle) : null),
    h('div', { class: 'actions' }, actions));
}

async function loadAdminData() {
  const [users, shares, repos] = await Promise.all([api('GET', '/users'), api('GET', '/shares'), api('GET', '/repos')]);
  state.users = users;
  state.shares = shares;
  state.reposInfo = repos;
  state.repos = repos.repos || [];
}

function reposOf(owner) { return state.repos.filter((r) => r.owner === owner); }

// ------------------------------------------------------------------ users

async function renderUsers(main) {
  await loadAdminData();
  const filter = h('input', { type: 'search', class: 'filter', placeholder: 'Filtern…', oninput: () => draw() });
  const tableHost = h('div', {});
  const totalSize = state.repos.reduce((a, r) => a + r.size, 0);

  setContent(main,
    pageHead('Benutzer', 'Jeder Benutzer hat ausschließlich Zugriff auf seine eigenen Repositories (/benutzer/…) und auf freigegebene.',
      filter, h('button', { class: 'primary', onclick: createUserDialog }, '+ Neuer Benutzer')),
    h('div', { class: 'stats' },
      stat('Benutzer', state.users.length),
      stat('Aktiv', state.users.filter((u) => !u.disabled).length),
      stat('Freigaben', state.shares.length),
      state.reposInfo.enabled ? stat('Belegt', fmtBytes(totalSize)) : null),
    h('div', { class: 'card' }, tableHost));

  function draw() {
    const q = filter.value.trim().toLowerCase();
    const list = state.users.filter((u) => !q || u.name.toLowerCase().includes(q) || (u.note || '').toLowerCase().includes(q));
    if (!list.length) { tableHost.replaceChildren(h('div', { class: 'empty' }, 'Keine Benutzer gefunden.')); return; }
    tableHost.replaceChildren(h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {},
        h('th', {}, 'Benutzer'), h('th', {}, 'Rolle'), h('th', {}, 'Eigene Repos'), h('th', {}, 'Status'),
        state.reposInfo.enabled ? [h('th', { class: 'num' }, 'Repos'), h('th', { class: 'num' }, 'Größe'), h('th', {}, 'Letzter Snapshot')] : null,
        h('th', {}, 'Freigaben'), h('th', {}))),
      h('tbody', {}, list.map(userRow)))));
  }
  draw();
}

function stat(label, value) {
  return h('div', { class: 'stat' }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value));
}

function userRow(u) {
  const repos = reposOf(u.name);
  const size = repos.reduce((a, r) => a + r.size, 0);
  const last = repos.map((r) => r.lastSnapshot).filter(Boolean).sort().pop();
  const incoming = state.shares.filter((s) => s.grantee === u.name).length;
  const outgoing = state.shares.filter((s) => s.path.split('/')[0] === u.name).length;
  const self = u.name === state.me.user.name;
  return h('tr', { class: u.disabled ? 'disabled' : '' },
    h('td', {}, h('strong', {}, u.name), self ? h('span', { class: 'sub' }, ' (du)') : null,
      u.note ? h('div', { class: 'sub' }, u.note) : null),
    h('td', {}, h('span', { class: 'badge ' + (u.role === 'admin' ? 'admin' : '') }, ROLES[u.role] || u.role)),
    h('td', {}, modeBadge(u.mode)),
    h('td', {}, u.disabled ? h('span', { class: 'badge off' }, 'Deaktiviert') : h('span', { class: 'badge full' }, 'Aktiv')),
    state.reposInfo.enabled ? [
      h('td', { class: 'num' }, repos.length),
      h('td', { class: 'num' }, fmtBytes(size)),
      h('td', { class: 'nowrap', title: last ? fmtDate(last) : '' }, fmtAgo(last)),
    ] : null,
    h('td', { class: 'sub nowrap', title: 'erhalten / vergeben' }, `${incoming} erhalten · ${outgoing} vergeben`),
    h('td', { class: 'row-actions' },
      h('button', { class: 'small ghost', onclick: () => showCredentials(u.name, u.name) }, 'Zugang'),
      h('button', { class: 'small ghost', onclick: () => passwordDialog(u) }, 'Passwort'),
      h('button', { class: 'small ghost', onclick: () => editUserDialog(u) }, 'Bearbeiten'),
      h('button', { class: 'small ghost danger', onclick: () => deleteUserDialog(u) }, 'Löschen')));
}

function createUserDialog() {
  openDialog({
    title: 'Neuer Benutzer',
    submitLabel: 'Anlegen',
    body: [
      h('label', { class: 'field' }, h('span', {}, 'Benutzername'),
        h('input', { type: 'text', name: 'name', required: true, maxlength: 64, pattern: '[A-Za-z0-9][A-Za-z0-9@._\\-]*', autocomplete: 'off', spellcheck: 'false' }),
        h('small', {}, 'Wird auch der Pfad des Repositories: /benutzername/. Erlaubt: A–Z, a–z, 0–9, @ . _ -')),
      passwordField('password', 'Passwort'),
      h('label', { class: 'field' }, h('span', {}, 'Zugriff auf eigene Repositories'), modeSelect('mode', 'full'),
        h('small', {}, '„Nur anhängen“ verhindert, dass ein kompromittierter Client Backups löscht. forget/prune dann nur durch einen Benutzer mit Vollzugriff (Freigabe).')),
      h('label', { class: 'field' }, h('span', {}, 'Rolle'),
        h('select', { name: 'role' }, h('option', { value: 'user' }, 'Benutzer – nur Backups & eigenes Konto'), h('option', { value: 'admin' }, 'Administrator – darf diese Oberfläche verwalten'))),
      h('label', { class: 'field' }, h('span', {}, 'Notiz (optional)'), h('input', { type: 'text', name: 'note', maxlength: 200, placeholder: 'z. B. Laptop Anna' })),
    ],
    onSubmit: async (fd) => {
      const body = { name: fd.get('name').trim(), password: fd.get('password'), mode: fd.get('mode'), role: fd.get('role'), note: fd.get('note') };
      await api('POST', '/users', body);
      toast(`Benutzer ${body.name} angelegt`);
      await refresh();
      showCredentials(body.name, body.name, body.password);
    },
  });
}

function editUserDialog(u) {
  openDialog({
    title: `Benutzer ${u.name} bearbeiten`,
    body: [
      h('label', { class: 'field' }, h('span', {}, 'Zugriff auf eigene Repositories'), modeSelect('mode', u.mode)),
      h('label', { class: 'field' }, h('span', {}, 'Rolle'),
        h('select', { name: 'role' },
          h('option', { value: 'user', selected: u.role === 'user' }, 'Benutzer'),
          h('option', { value: 'admin', selected: u.role === 'admin' }, 'Administrator'))),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'disabled', checked: u.disabled }),
        'Deaktiviert (kein Login, keine Backups – Daten bleiben erhalten)'),
      h('label', { class: 'field' }, h('span', {}, 'Notiz'), h('input', { type: 'text', name: 'note', maxlength: 200, value: u.note || '' })),
    ],
    onSubmit: async (fd) => {
      await api('PATCH', '/users/' + encodeURIComponent(u.name), {
        mode: fd.get('mode'), role: fd.get('role'), disabled: fd.get('disabled') === 'on', note: fd.get('note'),
      });
      toast('Gespeichert');
      await refresh();
    },
  });
}

function passwordDialog(u) {
  openDialog({
    title: `Passwort für ${u.name} setzen`,
    body: [passwordField('password', 'Neues Passwort'),
      h('p', { class: 'hint' }, 'Alle Clients des Benutzers müssen danach mit dem neuen Passwort konfiguriert werden.')],
    onSubmit: async (fd) => {
      const pw = fd.get('password');
      await api('POST', `/users/${encodeURIComponent(u.name)}/password`, { password: pw });
      toast('Passwort geändert');
      showCredentials(u.name, u.name, pw);
    },
  });
}

function deleteUserDialog(u) {
  const repos = reposOf(u.name);
  confirmDialog(`Benutzer ${u.name} löschen?`,
    [`Der Benutzer und alle zugehörigen Freigaben werden entfernt. `,
      h('strong', {}, 'Die Backup-Daten bleiben auf dem Server erhalten'),
      repos.length ? ` (${repos.length} Repository/s, ${fmtBytes(repos.reduce((a, r) => a + r.size, 0))})` : '',
      '. Wird später ein Benutzer mit gleichem Namen angelegt, erhält er Zugriff auf diese Daten.'],
    'Löschen',
    async () => {
      await api('DELETE', '/users/' + encodeURIComponent(u.name));
      toast(`Benutzer ${u.name} gelöscht`);
      if (u.name === state.me.user.name) { location.reload(); return; }
      await refresh();
    });
}

// ------------------------------------------------------------------ shares

async function renderShares(main) {
  await loadAdminData();
  const host = h('div', { class: 'card' });
  setContent(main,
    pageHead('Freigaben', 'Erlaubt einem Benutzer den Zugriff auf Repositories eines anderen Benutzers – mit seinen eigenen Zugangsdaten.',
      h('button', { class: 'primary', onclick: () => createShareDialog(), disabled: state.users.length < 2 }, '+ Neue Freigabe')),
    h('div', { class: 'callout' },
      'Der Empfänger nutzt seine eigenen Zugangsdaten und den Pfad des Besitzers, z. B. ',
      h('code', {}, repoUrl('bob', 'alice/laptop')),
      '. Die effektive Berechtigung ist nie höher als die des Besitzers selbst.'),
    host);
  if (!state.shares.length) {
    host.append(h('div', { class: 'empty' }, 'Noch keine Freigaben vorhanden.'));
    return;
  }
  host.append(h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, 'Repository'), h('th', {}, 'Besitzer'), h('th', {}, 'Empfänger'), h('th', {}, 'Modus'), h('th', {}, 'Notiz'), h('th', {}, 'Erstellt'), h('th', {}))),
    h('tbody', {}, state.shares.map((s) => {
      const [owner, sub] = s.path.split('/');
      return h('tr', {},
        h('td', {}, h('code', {}, '/' + s.path + '/'), h('div', { class: 'sub' }, sub ? 'einzelnes Repository' : 'alle Repositories des Besitzers')),
        h('td', {}, owner),
        h('td', {}, h('strong', {}, s.grantee)),
        h('td', {}, modeBadge(s.mode)),
        h('td', { class: 'sub' }, s.note || ''),
        h('td', { class: 'sub nowrap' }, fmtDate(s.createdAt)),
        h('td', { class: 'row-actions' },
          h('button', { class: 'small ghost', onclick: () => showCredentials(s.grantee, s.path) }, 'URL'),
          h('button', { class: 'small ghost', onclick: () => editShareDialog(s) }, 'Bearbeiten'),
          h('button', { class: 'small ghost danger', onclick: () => confirmDialog('Freigabe entfernen?',
            `${s.grantee} verliert den Zugriff auf /${s.path}/.`, 'Entfernen', async () => {
              await api('DELETE', '/shares/' + s.id);
              toast('Freigabe entfernt');
              await refresh();
            }) }, 'Entfernen')));
    })))));
}

function createShareDialog(preOwner) {
  const users = state.users.map((u) => u.name);
  const ownerSel = h('select', { name: 'owner', required: true }, users.map((n) => h('option', { value: n, selected: n === preOwner }, n)));
  const repoSel = h('select', { name: 'repo' });
  const customRepo = h('input', { type: 'text', name: 'custom', placeholder: 'Unterverzeichnis, z. B. laptop', hidden: true, spellcheck: 'false' });
  const granteeSel = h('select', { name: 'grantee', required: true });

  function syncOwner() {
    const owner = ownerSel.value;
    const subs = reposOf(owner).map((r) => r.path.split('/')[1]).filter(Boolean);
    setContent(repoSel,
      h('option', { value: '' }, `Alle Repositories von ${owner} (/${owner}/…)`),
      subs.map((s) => h('option', { value: s }, `/${owner}/${s}/`)),
      h('option', { value: '*' }, 'Anderes Unterverzeichnis…'));
    customRepo.hidden = true;
    const prev = granteeSel.value;
    granteeSel.replaceChildren(...users.filter((n) => n !== owner).map((n) => h('option', { value: n, selected: n === prev }, n)));
  }
  ownerSel.addEventListener('change', syncOwner);
  repoSel.addEventListener('change', () => { customRepo.hidden = repoSel.value !== '*'; if (!customRepo.hidden) customRepo.focus(); });
  syncOwner();

  openDialog({
    title: 'Neue Freigabe',
    submitLabel: 'Freigeben',
    body: [
      h('label', { class: 'field' }, h('span', {}, 'Besitzer'), ownerSel),
      h('label', { class: 'field' }, h('span', {}, 'Repository'), repoSel, customRepo,
        h('small', {}, 'Eine Freigabe auf /besitzer/ umfasst auch alle Unterverzeichnisse wie /besitzer/laptop/.')),
      h('label', { class: 'field' }, h('span', {}, 'Empfänger'), granteeSel),
      h('label', { class: 'field' }, h('span', {}, 'Berechtigung'), modeSelect('mode', 'read-only')),
      h('label', { class: 'field' }, h('span', {}, 'Notiz (optional)'), h('input', { type: 'text', name: 'note', maxlength: 200 })),
    ],
    onSubmit: async (fd) => {
      const owner = fd.get('owner');
      let sub = fd.get('repo');
      if (sub === '*') sub = (fd.get('custom') || '').trim().replace(/^\/+|\/+$/g, '');
      const path = sub ? `${owner}/${sub}` : owner;
      await api('POST', '/shares', { path, grantee: fd.get('grantee'), mode: fd.get('mode'), note: fd.get('note') });
      toast(`/${path}/ für ${fd.get('grantee')} freigegeben`);
      await refresh();
    },
  });
}

function editShareDialog(s) {
  openDialog({
    title: `Freigabe /${s.path}/ → ${s.grantee}`,
    body: [
      h('label', { class: 'field' }, h('span', {}, 'Berechtigung'), modeSelect('mode', s.mode)),
      h('label', { class: 'field' }, h('span', {}, 'Notiz'), h('input', { type: 'text', name: 'note', maxlength: 200, value: s.note || '' })),
    ],
    onSubmit: async (fd) => {
      await api('PATCH', '/shares/' + s.id, { mode: fd.get('mode'), note: fd.get('note') });
      toast('Gespeichert');
      await refresh();
    },
  });
}

// ------------------------------------------------------------------ repos

async function renderRepos(main, force) {
  const info = await api('GET', '/repos' + (force ? '?refresh=1' : ''));
  const users = new Set((await api('GET', '/users')).map((u) => u.name));
  const head = pageHead('Repositories', info.enabled ? `Stand: ${fmtDate(info.scannedAt)}` : null,
    info.enabled ? h('button', { onclick: (e) => { e.target.disabled = true; renderRepos(main, true).catch((x) => toast(x.message, true)); } }, 'Neu einlesen') : null);
  if (!info.enabled) {
    setContent(main, head, h('div', { class: 'card' }, h('div', { class: 'card-body' },
      h('p', {}, 'Das Datenverzeichnis des REST-Servers ist nicht eingebunden.'),
      h('p', { class: 'hint' }, 'Binde das Datenverzeichnis read-only unter /data in den UI-Container ein (siehe docker-compose.yml), um Größen und Snapshots zu sehen.'))));
    return;
  }
  const repos = info.repos || [];
  setContent(main, head,
    info.error ? h('div', { class: 'callout warn' }, 'Fehler beim Einlesen: ' + info.error) : null,
    h('div', { class: 'stats' },
      stat('Repositories', repos.length),
      stat('Gesamtgröße', fmtBytes(repos.reduce((a, r) => a + r.size, 0))),
      stat('Snapshots', repos.reduce((a, r) => a + r.snapshots, 0))),
    h('div', { class: 'card' }, repos.length ? h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Pfad'), h('th', {}, 'Besitzer'), h('th', { class: 'num' }, 'Größe'), h('th', { class: 'num' }, 'Dateien'),
        h('th', { class: 'num' }, 'Snapshots'), h('th', {}, 'Letzter Snapshot'), h('th', { class: 'num' }, 'Locks'))),
      h('tbody', {}, repos.map((r) => h('tr', {},
        h('td', {}, h('code', {}, '/' + r.path + '/')),
        h('td', {}, r.owner, users.has(r.owner) ? null : h('span', { class: 'badge off', title: 'Kein Benutzer mit diesem Namen – Daten sind verwaist' }, ' verwaist')),
        h('td', { class: 'num' }, fmtBytes(r.size)),
        h('td', { class: 'num' }, r.files),
        h('td', { class: 'num' }, r.snapshots),
        h('td', { class: 'nowrap', title: fmtDate(r.lastSnapshot) }, fmtAgo(r.lastSnapshot)),
        h('td', { class: 'num' }, r.locks ? h('span', { class: 'badge append-only', title: 'Aktive oder verwaiste Locks' }, r.locks) : '0')))))) :
      h('div', { class: 'empty' }, 'Noch keine Repositories vorhanden. Sie entstehen mit „restic init“.')));
}

// ------------------------------------------------------------------ tls

const CAS = {
  production: "Let's Encrypt (Produktion)",
  staging: "Let's Encrypt Staging (nur zum Testen – Browser vertrauen diesen Zertifikaten nicht)",
  custom: 'Andere ACME-CA (eigene Verzeichnis-URL)',
};

let tlsPoll = null;

function tlsStatusView(d) {
  const s = d.status;
  const c = s.cert;
  const days = c ? Math.floor((new Date(c.notAfter).getTime() - Date.now()) / 864e5) : null;
  let state = h('span', { class: 'badge off' }, 'Aus');
  if (s.active) state = h('span', { class: 'badge full' }, 'Aktiv');
  else if (s.enabled) state = h('span', { class: 'badge append-only' }, 'Wartet auf Zertifikat');
  const run = s.lastRun;
  return [
    s.external ? h('div', { class: 'callout' },
      'TLS wird über die Umgebungsvariablen ', h('code', {}, 'TLS_CERT'), ' / ', h('code', {}, 'TLS_KEY'),
      ' gesteuert. Die Einstellungen unten sind in diesem Modus ohne Wirkung. Entferne die Variablen, um Let’s Encrypt zu nutzen.') : null,
    h('div', { class: 'stats' },
      h('div', { class: 'stat' }, h('div', { class: 'label' }, 'TLS'), h('div', { class: 'value' }, state)),
      stat('Zertifikat gültig bis', c ? `${fmtDate(c.notAfter)}` : '–'),
      stat('Verbleibend', c ? (days < 0 ? 'abgelaufen' : `${days} Tage`) : '–'),
      stat('Aussteller', c ? c.issuer : '–')),
    c ? h('p', { class: 'hint' }, 'Domains im Zertifikat: ', c.domains.map((n, i) => [i ? ', ' : '', h('code', {}, n)]),
      s.external ? null : ` · automatische Erneuerung ab ${fmtDate(c.renewAfter)}`) : null,
    s.needsIssue && !s.running ? h('div', { class: 'callout warn' }, s.needsIssue + ' ',
      s.nextAttempt ? `Nächster automatischer Versuch: ${fmtDate(s.nextAttempt)}.` : 'Ein Zertifikat wird angefordert, sobald die Einstellungen vollständig sind.') : null,
    s.running ? h('div', { class: 'callout' }, 'Zertifikat wird angefordert … (kann einige Minuten dauern)') : null,
    run && !s.running && !run.ok ? h('div', { class: 'callout warn' }, 'Letzte Anforderung fehlgeschlagen: ', run.error) : null,
    run && run.ok && !s.running ? h('div', { class: 'callout' }, `Letzte Anforderung erfolgreich (${fmtDate(run.finished)}).`) : null,
    run ? h('details', { open: s.running || !run.ok }, h('summary', {}, `Protokoll der letzten Anforderung (${run.trigger}, ${fmtDate(run.started)})`),
      h('pre', { class: 'snippet log' }, (run.log || []).join('\n') || '…')) : null,
  ];
}

async function renderTLS(main) {
  clearTimeout(tlsPoll);
  const data = await api('GET', '/tls');
  const statusHost = h('div', {});
  const draw = (d) => setContent(statusHost, tlsStatusView(d));
  draw(data);
  const schedule = () => {
    clearTimeout(tlsPoll);
    tlsPoll = setTimeout(async () => {
      if (!document.body.contains(statusHost)) return;
      try {
        const d = await api('GET', '/tls');
        const wasActive = data.status.active;
        draw(d);
        data.status = d.status;
        if (d.status.active && !wasActive) tlsActiveHint(d);
        if (d.status.running) schedule();
      } catch (_) {
        // Most likely TLS has just been switched on and this page is still plain HTTP.
        if (document.body.contains(statusHost)) tlsActiveHint(data, true);
      }
    }, 3000);
  };
  if (data.status.running) schedule();

  const f = data.config;
  const p = f.powerdns;
  const ext = data.status.external;
  const customUrl = h('input', { type: 'text', name: 'customDirectory', value: f.customDirectory || '', placeholder: 'https://acme.example.com/directory', spellcheck: 'false' });
  const customField = h('label', { class: 'field', hidden: f.ca !== 'custom' }, h('span', {}, 'ACME-Verzeichnis-URL'), customUrl);
  const caSel = h('select', { name: 'ca', onchange: (e) => { customField.hidden = e.target.value !== 'custom'; } },
    Object.entries(CAS).map(([k, v]) => h('option', { value: k, selected: k === f.ca }, v)));

  const err = h('p', { class: 'error-text', hidden: true });
  const form = h('form', { onsubmit: (e) => e.preventDefault() });
  const readForm = () => {
    const fd = new FormData(form);
    const num = (k) => parseInt(fd.get(k), 10) || 0;
    return {
      enabled: fd.get('enabled') === 'on',
      domains: String(fd.get('domains')).split(/[\s,;]+/).filter(Boolean),
      email: fd.get('email'),
      ca: fd.get('ca'),
      customDirectory: fd.get('customDirectory'),
      acceptTos: fd.get('acceptTos') === 'on',
      renewBeforeDays: num('renewBeforeDays'),
      powerdns: {
        url: fd.get('pdnsUrl'), apiKey: fd.get('pdnsKey'), serverId: fd.get('pdnsServer'), zone: fd.get('pdnsZone'),
        ttl: num('pdnsTtl'), propagationSeconds: num('pdnsWait'), dnsServer: fd.get('pdnsDns'),
      },
    };
  };
  const busy = (btn, on) => { for (const b of form.querySelectorAll('button')) b.disabled = on; if (btn) btn.dataset.busy = on ? '1' : ''; };
  const run = (btn, fn) => async () => {
    err.hidden = true;
    busy(btn, true);
    try { await fn(); } catch (ex) { err.textContent = ex.message; err.hidden = false; err.scrollIntoView({ block: 'nearest' }); } finally { busy(btn, false); }
  };
  const save = async () => {
    const d = await api('PUT', '/tls', readForm());
    data.status = d.status;
    data.apiKeySet = d.apiKeySet;
    form.querySelector('[name=pdnsKey]').value = '';
    return d;
  };

  const saveBtn = h('button', { type: 'button', class: 'primary' }, 'Speichern');
  saveBtn.onclick = run(saveBtn, async () => {
    const d = await save();
    draw(d); schedule();
    toast('Gespeichert');
  });
  const issueBtn = h('button', { type: 'button' }, 'Speichern & Zertifikat jetzt anfordern');
  issueBtn.onclick = run(issueBtn, async () => {
    await save();
    const d = await api('POST', '/tls/issue');
    draw(d); schedule();
    toast('Zertifikatsanforderung gestartet');
  });
  const checkBtn = h('button', { type: 'button' }, 'DNS-Zugriff testen');
  checkBtn.onclick = run(checkBtn, async () => {
    const res = await api('POST', '/tls/check', readForm());
    const ok = res.domains.every((x) => !x.error);
    openDialog({
      title: ok ? 'PowerDNS-Zugriff funktioniert' : 'PowerDNS-Zugriff: Probleme gefunden',
      submitLabel: 'Schließen', noCancel: true,
      body: [h('p', { class: 'hint' }, 'Die API ist erreichbar und der Key wird akzeptiert. Für jede Domain wurde die Zone ermittelt, in der der Eintrag _acme-challenge angelegt wird.'),
        h('div', { class: 'table-wrap' }, h('table', {}, h('tbody', {}, res.domains.map((x) => h('tr', {},
          h('td', {}, h('code', {}, x.domain)),
          h('td', {}, x.error ? h('span', { class: 'badge off' }, x.error) : h('span', { class: 'badge full' }, 'Zone ' + x.zone)))))))],
    });
  });

  const field = (label, input, hint) => h('label', { class: 'field' }, h('span', {}, label), input, hint ? h('small', {}, hint) : null);
  const text = (name, value, extra) => h('input', { type: 'text', name, value: value ?? '', spellcheck: 'false', autocomplete: 'off', ...extra });

  setContent(form,
    err,
    h('fieldset', { class: 'plain', disabled: ext },
      h('div', { class: 'grid-2' },
        h('div', {},
          h('h2', {}, 'Zertifikat'),
          h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'enabled', checked: f.enabled }),
            h('span', {}, h('strong', {}, 'TLS aktivieren'), ' – Weboberfläche und restic-Gateway werden verschlüsselt')),
          field('Domains', h('textarea', { name: 'domains', rows: 3, spellcheck: 'false', placeholder: 'backup.example.com' }, (f.domains || []).join('\n')),
            'Eine pro Zeile. Wildcards wie *.example.com sind möglich (DNS-Challenge). Ein Zertifikat gilt für Oberfläche und restic-Gateway.'),
          field('E-Mail-Adresse', text('email', f.email, { type: 'text', placeholder: 'admin@example.com' }),
            'Für Ablaufwarnungen der Zertifizierungsstelle (empfohlen).'),
          field('Zertifizierungsstelle', caSel), customField,
          h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'acceptTos', checked: f.acceptTos }),
            h('span', {}, 'Ich akzeptiere die Nutzungsbedingungen der Zertifizierungsstelle ',
              h('a', { href: 'https://letsencrypt.org/repository/', target: '_blank', rel: 'noopener noreferrer' }, '(Let’s Encrypt Subscriber Agreement)'))),
          field('Erneuern, wenn weniger als … Tage gültig', text('renewBeforeDays', f.renewBeforeDays, { type: 'text', inputmode: 'numeric' }),
            'Let’s Encrypt-Zertifikate sind 90 Tage gültig; die Erneuerung läuft automatisch im Hintergrund.')),
        h('div', {},
          h('h2', {}, 'DNS-Challenge über PowerDNS'),
          field('API-URL', text('pdnsUrl', p.url, { placeholder: 'http://pdns:8081' }), 'Basis-Adresse der PowerDNS-Authoritative-API (webserver + api aktiviert).'),
          field('API-Key', h('input', { type: 'password', name: 'pdnsKey', autocomplete: 'new-password', placeholder: data.apiKeySet ? '•••••••• (gespeichert – leer lassen zum Behalten)' : '' }),
            'Wert von api-key in pdns.conf. Wird im Konfigurationsverzeichnis gespeichert und nie wieder angezeigt.'),
          h('div', { class: 'grid-2' },
            field('Server-ID', text('pdnsServer', p.serverId, { placeholder: 'localhost' })),
            field('Zone (optional)', text('pdnsZone', p.zone, { placeholder: 'automatisch' }))),
          h('div', { class: 'grid-2' },
            field('TTL der TXT-Einträge (s)', text('pdnsTtl', p.ttl, { inputmode: 'numeric' })),
            field('Wartezeit auf DNS (s)', text('pdnsWait', p.propagationSeconds, { inputmode: 'numeric' }))),
          field('DNS-Server für Vorabprüfung (optional)', text('pdnsDns', p.dnsServer, { placeholder: 'ns1.example.com oder 192.0.2.53:53' }),
            'Wenn angegeben, wartet die Anforderung, bis die TXT-Einträge dort sichtbar sind. Am besten ein autoritativer Nameserver der Zone.')))),
    h('div', { class: 'actions' }, saveBtn, issueBtn, checkBtn));

  setContent(main,
    pageHead('TLS / Let’s Encrypt', 'Verschlüsselt die Weboberfläche und die Verbindung der restic-Clients mit einem automatisch erneuerten Zertifikat.'),
    h('div', { class: 'card' }, h('div', { class: 'card-body' }, statusHost)),
    h('div', { class: 'card' }, h('div', { class: 'card-body' },
      h('div', { class: 'callout' },
        'Ablauf: Für jede Domain wird per PowerDNS-API ein TXT-Eintrag ', h('code', {}, '_acme-challenge.<domain>'),
        ' gesetzt, von Let’s Encrypt geprüft und danach wieder entfernt. Es muss kein Port aus dem Internet erreichbar sein. ',
        'Erst wenn ein Zertifikat vorliegt, schaltet der Server um: HTTPS läuft auf eigenen Ports (Oberfläche ',
        h('code', {}, ':' + (data.uiTlsPort || '8443')), ', restic ', h('code', {}, ':' + (data.gatewayTlsPort || '8444')),
        '). Die Oberfläche leitet vom HTTP-Port auf HTTPS um; der HTTP-Port des restic-Gateways wird geschlossen – restic-Clients benötigen ',
        h('code', {}, 'rest:https://…'), '.'),
      form)));
}

function tlsActiveHint(d, connectionLost) {
  const dom = (d.config.domains || []).find((n) => !n.startsWith('*.')) || (d.status.cert && d.status.cert.domains[0]);
  const port = d.uiTlsPort && d.uiTlsPort !== '443' ? ':' + d.uiTlsPort : '';
  const url = dom ? `https://${dom}${port}/` : null;
  openDialog({
    title: connectionLost ? 'Verbindung unterbrochen – TLS ist vermutlich aktiv' : 'TLS ist jetzt aktiv',
    submitLabel: 'Schließen', noCancel: true,
    body: [h('p', {}, 'Neue Verbindungen werden verschlüsselt. Diese Seite ist noch über HTTP geladen (der HTTP-Port leitet künftig automatisch um) – öffne die Oberfläche über HTTPS:'),
      url ? codeBox(url) : null,
      h('p', { class: 'hint' }, 'Passe auch die URLs in deinen restic-Clients an (rest:https://…). Bei Problemen kann die Datei tls.json im Konfigurationsverzeichnis gelöscht werden – dann läuft nach einem Neustart alles wieder unverschlüsselt.')],
  });
}

// ------------------------------------------------------------------ account

async function renderAccount(main) {
  const me = await api('GET', '/me');
  state.me = me;
  const u = me.user;
  const repos = me.repos || [];
  setContent(main,
    pageHead('Mein Konto', `Angemeldet als ${u.name} · ${ROLES[u.role]}`),
    h('div', { class: 'card' }, h('div', { class: 'card-body' },
      h('h2', {}, 'Meine Zugänge'),
      h('p', { class: 'hint' }, 'Ersetze <PASSWORT> durch dein Passwort. Statt es in die URL zu schreiben, kannst du auch RESTIC_REST_USERNAME / RESTIC_REST_PASSWORD setzen (restic ≥ 0.17).'),
      h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Pfad'), h('th', {}, 'Art'), h('th', {}, 'Berechtigung'), h('th', {}, 'URL'))),
        h('tbody', {}, me.grants.map((g) => h('tr', {},
          h('td', {}, h('code', {}, '/' + g.path + '/')),
          h('td', {}, g.own ? 'Eigene Repositories' : 'Freigabe', g.note ? h('div', { class: 'sub' }, g.note) : null),
          h('td', {}, modeBadge(g.mode)),
          h('td', { class: 'url-cell' }, codeBox(repoUrl(u.name, g.path)))))))))),
    me.dataEnabled ? h('div', { class: 'card' }, h('div', { class: 'card-body' },
      h('h2', {}, 'Repositories'),
      repos.length ? h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Pfad'), h('th', { class: 'num' }, 'Größe'), h('th', { class: 'num' }, 'Snapshots'), h('th', {}, 'Letzter Snapshot'))),
        h('tbody', {}, repos.map((r) => h('tr', {},
          h('td', {}, h('code', {}, '/' + r.path + '/')),
          h('td', { class: 'num' }, fmtBytes(r.size)),
          h('td', { class: 'num' }, r.snapshots),
          h('td', { title: fmtDate(r.lastSnapshot) }, fmtAgo(r.lastSnapshot))))))) :
        h('p', { class: 'hint' }, 'Noch keine Repositories. Lege eines mit „restic init“ an.'))) : null,
    h('div', { class: 'card' }, h('div', { class: 'card-body' }, h('h2', {}, 'Passwort ändern'), ownPasswordForm())));
}

function ownPasswordForm() {
  const err = h('p', { class: 'error-text', hidden: true });
  const btn = h('button', { type: 'submit', class: 'primary' }, 'Passwort ändern');
  const form = h('form', {
    class: 'narrow-form',
    onsubmit: async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      err.hidden = true;
      if (fd.get('new') !== fd.get('repeat')) { err.textContent = 'Die neuen Passwörter stimmen nicht überein.'; err.hidden = false; return; }
      btn.disabled = true;
      try {
        await api('POST', '/me/password', { current: fd.get('current'), new: fd.get('new') });
        form.reset();
        toast('Passwort geändert – bitte auch in allen Backup-Clients anpassen.');
      } catch (ex) { err.textContent = ex.message; err.hidden = false; } finally { btn.disabled = false; }
    },
  },
  err,
  h('label', { class: 'field' }, h('span', {}, 'Aktuelles Passwort'), h('input', { type: 'password', name: 'current', autocomplete: 'current-password', required: true })),
  h('label', { class: 'field' }, h('span', {}, 'Neues Passwort'), h('input', { type: 'password', name: 'new', autocomplete: 'new-password', minlength: 8, required: true })),
  h('label', { class: 'field' }, h('span', {}, 'Neues Passwort wiederholen'), h('input', { type: 'password', name: 'repeat', autocomplete: 'new-password', minlength: 8, required: true })),
  btn);
  return form;
}

// ------------------------------------------------------------------ boot

async function refresh() {
  const main = document.querySelector('main');
  if (!main) return;
  await ROUTES[currentRoute()].render(main);
}

async function boot() {
  try {
    state.me = await api('GET', '/me');
  } catch (_) {
    renderLogin();
    return;
  }
  renderShell();
}

window.addEventListener('hashchange', () => { if (state.me) renderShell(); });
boot();
