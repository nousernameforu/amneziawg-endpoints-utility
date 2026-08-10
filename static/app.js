'use strict';

/* ------------------------------------------------------------------ state */

const S = {
  config: null,      // full sing-box config, edited in place
  vault: null,       // sidecar: keys + client defaults, never sent to sing-box
  meta: {},
  sel: 0,            // index into S.config.endpoints
  dirty: false,
  lang: 'en',
  strings: {},       // active locale
  fallback: {},      // English, for keys a locale has not translated yet
};

/* ------------------------------------------------------------------- i18n */

const LANG_KEY = 'awg-endpoints-lang';

/** Look up a key, filling {placeholders}. Falls back to English, then the key. */
function t(key, vars) {
  let s = S.strings[key];
  if (s === undefined) s = S.fallback[key];
  if (s === undefined) return key;
  if (!vars) return s;
  return s.replace(/\{(\w+)\}/g, (m, name) => (name in vars ? String(vars[name]) : m));
}

async function fetchLocale(code) {
  const res = await fetch('/i18n/' + encodeURIComponent(code) + '.json');
  if (!res.ok) throw new Error('no locale ' + code);
  return res.json();
}

async function setLanguage(code, remember) {
  try {
    S.strings = await fetchLocale(code);
    S.lang = code;
  } catch {
    S.strings = S.fallback;      // unknown locale: stay in English
    S.lang = 'en';
  }
  if (remember) localStorage.setItem(LANG_KEY, S.lang);
  document.documentElement.lang = S.lang;
  applyStaticText();
  if (S.config) render();       // re-render everything the JS built
}

/** Translate the markup: textContent for data-i18n, title for data-i18n-title. */
function applyStaticText() {
  document.querySelectorAll('[data-i18n]').forEach((n) => {
    n.textContent = t(n.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-title]').forEach((n) => {
    n.title = t(n.dataset.i18nTitle);
  });
}

function renderLanguagePicker() {
  const sel = $('#lang');
  sel.innerHTML = '';
  (S.meta.languages || [{ code: 'en', name: 'English' }]).forEach((l) => {
    const o = el('option', null, l.name);
    o.value = l.code;
    if (l.code === S.lang) o.selected = true;
    sel.appendChild(o);
  });
  sel.classList.toggle('hidden', (S.meta.languages || []).length < 2);
}

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

const CLIENT_DEFAULTS = () => ({
  endpoint_host: '',
  dns: '',
  allowed_ips: '0.0.0.0/0, ::/0',
  mtu: '',
  persistent_keepalive: 25,
  i1: '', i2: '', i3: '', i4: '', i5: '',
});

/* ------------------------------------------------------------- model bits */

const endpoints = () => (S.config && Array.isArray(S.config.endpoints)) ? S.config.endpoints : [];
const isWg = (ep) => ep && ep.type === 'wireguard';
const ep = () => endpoints()[S.sel];

function vaultEp(tag) {
  if (!S.vault.endpoints[tag]) {
    S.vault.endpoints[tag] = { server_public_key: '', client: CLIENT_DEFAULTS(), peers: {} };
  }
  const v = S.vault.endpoints[tag];
  // Fill gaps in place — replacing v.client would detach the object that the
  // already-rendered field closures write through.
  if (!v.client) v.client = CLIENT_DEFAULTS();
  const defaults = CLIENT_DEFAULTS();
  for (const k of Object.keys(defaults)) {
    if (!(k in v.client)) v.client[k] = defaults[k];
  }
  if (!v.peers) v.peers = {};
  return v;
}
const vEp = () => vaultEp(ep().tag || '');

function vaultPeer(pub) {
  const peers = vEp().peers;
  if (!peers[pub]) peers[pub] = { name: '', private_key: '' };
  return peers[pub];
}

/* --------------------------------------------------------------- ip utils */

const ip4ToInt = (s) => s.split('.').reduce((a, o) => (a << 8 >>> 0) + (parseInt(o, 10) & 255), 0) >>> 0;
const intToIp4 = (n) => [24, 16, 8, 0].map((sh) => (n >>> sh) & 255).join('.');
const isIp4 = (s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every((o) => +o >= 0 && +o <= 255);

function v6Groups(addr) {
  if (addr.split('::').length > 2) return null;
  if (addr.indexOf('::') >= 0) {
    const [h, t] = addr.split('::');
    const head = h ? h.split(':') : [];
    const tail = t ? t.split(':') : [];
    const fillLen = 8 - head.length - tail.length;
    if (fillLen < 0) return null;
    return head.concat(new Array(fillLen).fill('0'), tail).map((g) => parseInt(g || '0', 16));
  }
  const g = addr.split(':');
  return g.length === 8 ? g.map((x) => parseInt(x, 16)) : null;
}
function isIp6(s) {
  if (!/^[0-9a-fA-F:]+$/.test(s) || !s.includes(':')) return false;
  const g = v6Groups(s);
  return !!g && g.every((x) => Number.isFinite(x) && x >= 0 && x <= 0xffff);
}

function v6ToBig(s) {
  return v6Groups(s).reduce((acc, g) => (acc << 16n) + BigInt(g), 0n);
}
function bigToV6(n) {
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  let best = { start: -1, len: 0 }, cur = { start: -1, len: 0 };
  g.forEach((v, i) => {
    if (v === 0) {
      if (cur.start < 0) cur = { start: i, len: 1 }; else cur.len++;
      if (cur.len > best.len) best = { start: cur.start, len: cur.len };
    } else cur = { start: -1, len: 0 };
  });
  const hex = g.map((v) => v.toString(16));
  if (best.len < 2) return hex.join(':');
  return (hex.slice(0, best.start).join(':') + '::' + hex.slice(best.start + best.len).join(':'))
    .replace(/:::+/, '::');
}

function parseCidr(s) {
  const t = String(s || '').trim();
  const m = t.match(/^([^/]+)\/(\d+)$/);
  if (!m) return null;
  const addr = m[1].trim(), prefix = parseInt(m[2], 10);
  if (isIp4(addr) && prefix >= 0 && prefix <= 32) return { v: 4, addr, prefix };
  if (isIp6(addr) && prefix >= 0 && prefix <= 128) return { v: 6, addr, prefix };
  return null;
}

/** Lowest offset >= 2 whose v4 and v6 host addresses are both unused. */
function nextFreeAddresses(e) {
  const list = asList(e.address);
  const c4 = list.map(parseCidr).find((c) => c && c.v === 4);
  const c6 = list.map(parseCidr).find((c) => c && c.v === 6);

  const used4 = new Set(), used6 = new Set();
  const note = (cidr) => {
    const c = parseCidr(cidr);
    if (!c) return;
    if (c.v === 4) used4.add(ip4ToInt(c.addr));
    else used6.add(v6ToBig(c.addr).toString());
  };
  list.forEach(note);
  (Array.isArray(e.peers) ? e.peers : []).forEach(
    (p) => asList(p.allowed_ips).forEach(note));

  const net4 = c4 ? (ip4ToInt(c4.addr) & (c4.prefix === 0 ? 0 : (-1 << (32 - c4.prefix)) >>> 0)) >>> 0 : null;
  const max4 = c4 ? (c4.prefix >= 31 ? 0 : Math.pow(2, 32 - c4.prefix) - 2) : 0;
  const net6 = c6 ? (v6ToBig(c6.addr) >> BigInt(128 - c6.prefix)) << BigInt(128 - c6.prefix) : null;

  for (let k = 2; k < 65536; k++) {
    const a4 = net4 === null ? null : (net4 + k) >>> 0;
    const a6 = net6 === null ? null : net6 + BigInt(k);
    if (c4 && k > max4) break;
    if (a4 !== null && used4.has(a4)) continue;
    if (a6 !== null && used6.has(a6.toString())) continue;
    const out = [];
    if (a4 !== null) out.push(intToIp4(a4) + '/32');
    if (a6 !== null) out.push(bigToV6(a6) + '/128');
    return out;
  }
  return [];
}

/* ------------------------------------------------------------- api client */

async function api(path, body) {
  const opt = body === undefined
    ? {}
    : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  const res = await fetch(path, opt);
  const ctype = res.headers.get('Content-Type') || '';
  if (ctype.includes('application/json')) {
    const data = await res.json();
    if (!res.ok) {
      const err = new Error(data.error || ('HTTP ' + res.status));
      err.check = data.check;         // sing-box's own output, if it refused
      throw err;
    }
    return data;
  }
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res;
}

let toastTimer = null;
function toast(msg, kind) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = kind || '';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), kind === 'err' ? 9000 : 4000);
}

/* ----------------------------------------------------------------- fields */

/**
 * One labelled input bound to a model getter/setter. Built once per render so
 * typing never rebuilds the DOM under the cursor.
 */
function field(parent, opt) {
  const wrap = el('div', 'field' + (opt.wide ? ' wide' : ''));
  const label = el('label');
  label.appendChild(el('span', null, opt.label));
  if (opt.hint) label.appendChild(el('span', 'hint', opt.hint));
  wrap.appendChild(label);

  const row = el('div', 'row');
  const input = el(opt.multiline ? 'textarea' : 'input');
  input.className = opt.mono === false ? '' : 'mono';
  if (opt.placeholder) input.placeholder = opt.placeholder;
  if (opt.multiline) input.rows = opt.rows || 2;
  input.value = opt.get() ?? '';
  input.addEventListener('input', () => { opt.set(input.value); touch(); });
  row.appendChild(input);

  (opt.buttons || []).forEach((b) => {
    const btn = el('button', 'ghost tiny', b.label);
    btn.title = b.title || '';
    btn.addEventListener('click', async () => {
      await b.onClick(input);
      touch();
    });
    row.appendChild(btn);
  });

  wrap.appendChild(row);
  if (opt.footer) wrap.appendChild(opt.footer);
  parent.appendChild(wrap);
  return input;
}

const num = (v) => {
  const t = String(v).trim();
  if (t === '') return undefined;
  const n = Number(t);
  return Number.isFinite(n) ? n : t;
};

/**
 * sing-box accepts a bare value anywhere it accepts a list, so "10.3.2.2/32"
 * and ["10.3.2.2/32"] are both legal in the file. Everything here works in
 * arrays; this is the funnel.
 */
function asList(v) {
  if (v === undefined || v === null || v === '') return [];
  if (Array.isArray(v)) return v.filter((x) => x !== null && x !== undefined);
  if (typeof v === 'object') return [v];
  return String(v).split(',').map((x) => x.trim()).filter(Boolean);
}

const listGet = (v) => asList(v).join(', ');
const listSet = (s) => String(s).split(',').map((x) => x.trim()).filter(Boolean);

/** Coerce the listable fields we touch, so the rest of the code can assume arrays. */
function normalizeConfig() {
  endpoints().forEach((e) => {
    if (!isWg(e)) return;
    e.address = asList(e.address);
    if (!Array.isArray(e.peers)) e.peers = e.peers ? [e.peers] : [];
    e.peers.forEach((p) => { p.allowed_ips = asList(p.allowed_ips); });
  });
}

/* ----------------------------------------------------------------- render */

function renderTabs() {
  const nav = $('#endpoint-tabs');
  nav.innerHTML = '';
  endpoints().forEach((e, i) => {
    if (!isWg(e)) return;
    const b = el('button', i === S.sel ? 'active' : '', e.tag || '(untagged)');
    b.addEventListener('click', () => { S.sel = i; render(); });
    nav.appendChild(b);
  });
  const add = el('button', 'ghost', t('iface.add_endpoint'));
  add.addEventListener('click', addEndpoint);
  nav.appendChild(add);

  const others = endpoints().filter((e) => !isWg(e)).length;
  if (others) {
    const note = el('span', 'sub', t('iface.others_untouched', { n: others }));
    note.style.alignSelf = 'center';
    nav.appendChild(note);
  }
}

function renderInterface() {
  const g = $('#iface-grid');
  g.innerHTML = '';
  const e = ep();

  field(g, {
    label: 'tag', mono: false, get: () => e.tag,
    set: (v) => {
      const old = e.tag || '';
      if (v === old) return;
      const entry = S.vault.endpoints[old];
      if (entry) { delete S.vault.endpoints[old]; S.vault.endpoints[v] = entry; }
      e.tag = v;
      renderTabs();
    },
  });
  field(g, { label: 'listen_port', get: () => e.listen_port, set: (v) => { e.listen_port = num(v); } });
  field(g, { label: 'mtu', get: () => e.mtu, set: (v) => { e.mtu = num(v); } });

  field(g, {
    label: 'address', hint: t('hint.comma'), wide: true,
    placeholder: '10.3.2.1/24, fd42:3:2::1/64',
    get: () => listGet(e.address), set: (v) => { e.address = listSet(v); },
  });

  const pubLine = el('div', 'derived');
  const renderPub = () => {
    const pub = vEp().server_public_key;
    pubLine.innerHTML = '';
    pubLine.appendChild(el('span', null, t('iface.pubkey')));
    pubLine.appendChild(el('b', null, pub || t('iface.pubkey_missing')));
  };
  renderPub();

  field(g, {
    label: 'private_key', hint: t('hint.server'), wide: true,
    get: () => e.private_key,
    set: (v) => { e.private_key = v.trim(); },
    footer: pubLine,
    buttons: [
      {
        label: t('common.generate'), title: t('iface.generate_title'),
        onClick: async (input) => {
          const kp = await api('/api/keypair', {});
          e.private_key = kp.private_key;
          vEp().server_public_key = kp.public_key;
          input.value = kp.private_key;
          renderPub();
          renderPeers();
        },
      },
      {
        label: t('iface.derive'), title: t('iface.derive_title'),
        onClick: async (input) => {
          try {
            const kp = await api('/api/keypair', { private_key: input.value.trim() });
            vEp().server_public_key = kp.public_key;
            renderPub();
            renderPeers();
          } catch (err) { toast(String(err.message || err), 'err'); }
        },
      },
    ],
  });
}

const AWG_NUMS = ['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4'];
const AWG_HDRS = ['h1', 'h2', 'h3', 'h4'];

function renderAwg() {
  const e = ep();
  const g = $('#awg-grid');
  g.innerHTML = '';
  AWG_NUMS.forEach((k) => field(g, { label: k, get: () => e[k], set: (v) => { e[k] = num(v); } }));
  AWG_HDRS.forEach((k) => field(g, {
    label: k, hint: t('hint.range'), placeholder: '39602205-139602204',
    get: () => e[k], set: (v) => { e[k] = v.trim() === '' ? undefined : v.trim(); },
  }));

  const gi = $('#awg-i-grid');
  gi.innerHTML = '';
  ['i1', 'i2', 'i3', 'i4', 'i5'].forEach((k) => field(gi, {
    label: k, placeholder: '<b 0xcd00000001><r 12><r 40>',
    get: () => e[k], set: (v) => { e[k] = v.trim() === '' ? undefined : v; },
  }));
}

function renderClient() {
  const c = vEp().client;
  const g = $('#client-grid');
  g.innerHTML = '';
  field(g, {
    label: t('fields.endpoint_host'), hint: t('hint.goes_in_conf'),
    placeholder: 'vpn.example.com',
    get: () => c.endpoint_host, set: (v) => { c.endpoint_host = v.trim(); },
  });
  field(g, { label: 'DNS', placeholder: '10.3.2.1', get: () => c.dns, set: (v) => { c.dns = v.trim(); } });
  field(g, { label: 'MTU', placeholder: '1280', get: () => c.mtu, set: (v) => { c.mtu = v.trim(); } });
  field(g, {
    label: 'PersistentKeepalive', placeholder: '25',
    get: () => c.persistent_keepalive, set: (v) => { c.persistent_keepalive = v.trim(); },
  });
  field(g, {
    label: 'AllowedIPs', hint: t('hint.client_side'), wide: true,
    placeholder: '0.0.0.0/0, ::/0',
    get: () => c.allowed_ips, set: (v) => { c.allowed_ips = v; },
  });

  const gi = $('#client-i-grid');
  gi.innerHTML = '';
  ['i1', 'i2', 'i3', 'i4', 'i5'].forEach((k) => field(gi, {
    label: k.toUpperCase(), placeholder: '<b 0xcd00000001><r 12><r 40>',
    get: () => c[k], set: (v) => { c[k] = v; },
  }));
}

function renderPeers() {
  const e = ep();
  if (!Array.isArray(e.peers)) e.peers = [];
  const host = $('#peers');
  host.innerHTML = '';
  $('#peer-count').textContent = e.peers.length
    ? t('clients.count', { n: e.peers.length })
    : t('clients.none');

  e.peers.forEach((p, i) => {
    const ready = !!vaultPeer(p.public_key || '').private_key && !!vEp().server_public_key;
    const box = el('div', 'peer' + (ready ? '' : ' incomplete'));
    const head = el('div', 'peer-head');

    const left = el('div', 'peer-left');
    left.appendChild(el('span', 'idx', '#' + (i + 1)));
    const name = el('input', 'name');
    name.placeholder = t('common.name');
    name.value = vaultPeer(p.public_key || '').name || '';
    name.addEventListener('input', () => { vaultPeer(p.public_key || '').name = name.value; touch(); });
    left.appendChild(name);
    if (!ready) {
      left.appendChild(el('span', 'tag-warn',
        t(vEp().server_public_key ? 'peer.no_privkey' : 'peer.no_serverkey')));
    }
    head.appendChild(left);

    const btns = el('div', 'btns');
    const mk = (label, cls, fn) => {
      const b = el('button', cls + ' tiny', label);
      b.addEventListener('click', fn);
      btns.appendChild(b);
      return b;
    };
    mk(t('peer.copy_conf'), 'primary', () => copyText(buildConf(i))).disabled = !ready;
    mk(t('common.download'), 'ghost',
       () => download(peerLabel(p, i) + '.conf', buildConf(i))).disabled = !ready;
    mk(t('common.view'), 'ghost', () => showConf(i)).disabled = !ready;
    mk(t('peer.rekey'), 'ghost', async () => {
      try {
        const kp = await api('/api/keypair', {});
        const peers = vEp().peers;
        const old = p.public_key || '';
        const meta = peers[old] || { name: name.value, private_key: '' };
        delete peers[old];
        p.public_key = kp.public_key;
        peers[kp.public_key] = { name: meta.name || '', private_key: kp.private_key };
        renderPeers(); touch();
      } catch (err) { toast(String(err.message || err), 'err'); }
    });
    mk(t('common.delete'), 'danger ghost', () => {
      const label = vaultPeer(p.public_key || '').name || t('v.peer_label', { n: i + 1 });
      if (!confirm(t('confirm.remove', { name: label }))) return;
      delete vEp().peers[p.public_key || ''];
      e.peers.splice(i, 1);
      renderPeers(); touch();
    });
    head.appendChild(btns);
    box.appendChild(head);

    const addr = el('div', 'peer-addr');
    const showAddr = () => {
      addr.innerHTML = '';
      const ips = asList(p.allowed_ips);
      (ips.length ? ips : [t('peer.no_address')])
        .forEach((a) => addr.appendChild(el('span', null, a)));
    };
    showAddr();
    box.appendChild(addr);

    const det = el('details');
    det.appendChild(el('summary', null, t('peer.details')));
    const g = el('div', 'grid');
    field(g, {
      label: 'public_key', wide: true,
      get: () => p.public_key,
      set: (v) => {
        const old = p.public_key || '';
        const nv = v.trim();
        const peers = vEp().peers;
        if (old !== nv && peers[old]) { peers[nv] = peers[old]; delete peers[old]; }
        p.public_key = nv;
      },
    });
    field(g, {
      label: t('fields.private_key'), hint: t('hint.sidecar_only'), wide: true,
      placeholder: t('hint.privkey_ph'),
      get: () => vaultPeer(p.public_key || '').private_key,
      set: (v) => { vaultPeer(p.public_key || '').private_key = v.trim(); },
    });
    field(g, {
      label: 'pre_shared_key', wide: true,
      get: () => p.pre_shared_key,
      set: (v) => { if (v.trim()) p.pre_shared_key = v.trim(); else delete p.pre_shared_key; },
      buttons: [{
        label: t('common.new'), title: t('hint.new_psk_title'),
        onClick: async (input) => {
          const r = await api('/api/psk', {});
          p.pre_shared_key = r.pre_shared_key;
          input.value = r.pre_shared_key;
        },
      }],
    });
    field(g, {
      label: 'allowed_ips', hint: t('hint.comma'), wide: true,
      placeholder: '10.3.2.2/32, fd42:3:2::2/128',
      get: () => listGet(p.allowed_ips), set: (v) => { p.allowed_ips = listSet(v); },
      buttons: [{
        label: t('hint.next_free'), title: t('hint.next_free_title'),
        onClick: (input) => {
          const other = Object.assign({}, e, { peers: e.peers.filter((_, j) => j !== i) });
          p.allowed_ips = nextFreeAddresses(other);
          input.value = listGet(p.allowed_ips);
          showAddr();
        },
      }],
    });
    det.appendChild(g);
    box.appendChild(det);
    host.appendChild(box);
  });
}

function render() {
  const list = endpoints();
  if (!isWg(list[S.sel])) S.sel = list.findIndex(isWg);
  renderTabs();

  const has = S.sel >= 0 && isWg(list[S.sel]);
  $('#editor').classList.toggle('hidden', !has);
  $('#empty').classList.toggle('hidden', has);
  if (!has) { $('#preview').textContent = ''; return; }

  renderInterface();
  renderAwg();
  renderClient();
  renderPeers();
  refresh();
}

/** Cheap update after any edit: preview + validation + dirty flag. */
function touch() {
  S.dirty = true;
  refresh();
}

function refresh() {
  $('#dirty').classList.toggle('hidden', !S.dirty);
  $('#preview').textContent = JSON.stringify(S.config, null, 2);
  renderIssues();
}

/* ------------------------------------------------------------- validation */

const B64_32 = /^[A-Za-z0-9+/]{43}=$/;
const isKey = (s) => typeof s === 'string' && B64_32.test(s);
const TEMPLATE = /^(<\s*[a-z]{1,2}(\s+(0x[0-9a-fA-F]+|\d+))?\s*>)+$/;

function parseHeader(v) {
  const s = String(v ?? '').trim();
  if (s === '') return null;
  const m = s.match(/^(\d+)\s*-\s*(\d+)$/);
  if (m) return { lo: Number(m[1]), hi: Number(m[2]), range: true };
  if (/^\d+$/.test(s)) return { lo: Number(s), hi: Number(s), range: false };
  return undefined;   // unparseable
}

function validate() {
  const out = [];
  const err = (m) => out.push({ kind: 'err', m });
  const warn = (m) => out.push({ kind: 'warn', m });
  const e = ep();
  if (!e) return out;
  const v = vEp();

  if (!e.tag) err(t('v.tag_empty'));
  if (endpoints().filter((x) => isWg(x) && x.tag === e.tag).length > 1) {
    err(t('v.tag_dup', { tag: e.tag }));
  }

  const addrs = asList(e.address);
  if (!addrs.length) err(t('v.addr_empty'));
  addrs.forEach((a) => { if (!parseCidr(a)) err(t('v.addr_bad', { addr: a })); });

  if (!isKey(e.private_key)) err(t('v.privkey_bad'));
  if (!v.server_public_key) warn(t('v.serverpub_unknown'));

  const port = Number(e.listen_port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) err(t('v.port_range'));
  if (e.mtu != null && (e.mtu < 576 || e.mtu > 1500)) warn(t('v.mtu_odd', { mtu: e.mtu }));

  const jc = Number(e.jc), jmin = Number(e.jmin), jmax = Number(e.jmax);
  if (Number.isFinite(jmin) && Number.isFinite(jmax) && jmin >= jmax) err(t('v.jminmax'));
  if (Number.isFinite(jc) && jc > 128) warn(t('v.jc_high'));
  if (Number.isFinite(jmax) && jmax > 1280) warn(t('v.jmax_high'));
  const s1 = Number(e.s1), s2 = Number(e.s2);
  if (Number.isFinite(s1) && Number.isFinite(s2) && s1 + 56 === s2) err(t('v.s1s2'));

  const hdrs = AWG_HDRS.map((k) => ({ k, p: parseHeader(e[k]) }));
  hdrs.forEach(({ k, p }) => {
    if (p === undefined) err(t('v.h_bad', { k }));
    else if (p === null) warn(t('v.h_empty', { k }));
    else {
      if (p.lo <= 4) err(t('v.h_low', { k }));
      if (p.hi < p.lo) err(t('v.h_inverted', { k }));
    }
  });
  for (let i = 0; i < hdrs.length; i++) {
    for (let j = i + 1; j < hdrs.length; j++) {
      const a = hdrs[i].p, b = hdrs[j].p;
      if (a && b && a.lo <= b.hi && b.lo <= a.hi) {
        err(t('v.h_overlap', { a: hdrs[i].k, b: hdrs[j].k }));
      }
    }
  }

  ['i1', 'i2', 'i3', 'i4', 'i5'].forEach((k) => {
    if (e[k] && !TEMPLATE.test(String(e[k]))) warn(t('v.i_server_bad', { k }));
    const cv = v.client[k];
    if (cv && !TEMPLATE.test(String(cv))) warn(t('v.i_client_bad', { k: k.toUpperCase() }));
  });
  const anyServerI = ['i1', 'i2', 'i3', 'i4', 'i5'].some((k) => e[k]);
  const anyClientI = ['i1', 'i2', 'i3', 'i4', 'i5'].some((k) => v.client[k]);
  if (anyServerI && !anyClientI) warn(t('v.i_client_missing'));

  if (!v.client.endpoint_host) warn(t('v.host_unset'));

  const seenKeys = new Map(), seenIps = new Map();
  (Array.isArray(e.peers) ? e.peers : []).forEach((p, i) => {
    const peer = t('v.peer_label', { n: i + 1 });
    if (!isKey(p.public_key)) err(t('v.peer_pubkey_bad', { peer }));
    else if (seenKeys.has(p.public_key)) {
      err(t('v.peer_pubkey_dup', { peer, n: seenKeys.get(p.public_key) + 1 }));
    } else seenKeys.set(p.public_key, i);

    if (p.pre_shared_key && !isKey(p.pre_shared_key)) err(t('v.peer_psk_bad', { peer }));
    if (!p.pre_shared_key) warn(t('v.peer_psk_missing', { peer }));

    const ips = asList(p.allowed_ips);
    if (!ips.length) err(t('v.peer_ips_empty', { peer }));
    ips.forEach((a) => {
      const c = parseCidr(a);
      if (!c) { err(t('v.peer_ip_bad', { peer, addr: a })); return; }
      if ((c.v === 4 && c.prefix !== 32) || (c.v === 6 && c.prefix !== 128)) {
        warn(t('v.peer_ip_nothost', { peer, addr: a }));
      }
      if (seenIps.has(a)) err(t('v.peer_ip_dup', { peer, addr: a, n: seenIps.get(a) + 1 }));
      else seenIps.set(a, i);
    });

    if (!vaultPeer(p.public_key || '').private_key) warn(t('v.peer_no_privkey', { peer }));
  });

  return out;
}

function renderIssues() {
  const ul = $('#issues');
  ul.innerHTML = '';
  const issues = validate();
  issues.forEach((i) => ul.appendChild(el('li', i.kind, i.m)));

  $('#no-issues').classList.toggle('hidden', issues.length > 0);

  const errs = issues.filter((i) => i.kind === 'err').length;
  const warns = issues.length - errs;
  const badge = $('#issue-badge');
  badge.classList.toggle('hidden', !issues.length);
  badge.classList.toggle('bad', errs > 0);
  badge.textContent = !errs
    ? t('badge.warnings', { n: warns })
    : (warns ? t('badge.both', { e: errs, w: warns }) : t('badge.errors', { n: errs }));

  const e = ep();
  $('#summary-hint').textContent = e
    ? `${e.tag || 'untagged'} · port ${e.listen_port ?? '—'} · ${(e.address || []).join(', ')}`
    : '';
}

/* --------------------------------------------------------- .conf building */

function peerLabel(p, i) {
  const name = (vaultPeer(p.public_key || '').name || '').trim();
  const slug = name.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  return slug || ('peer' + (i + 1));
}

function buildConf(i) {
  const e = ep(), v = vEp(), c = v.client;
  const p = e.peers[i];
  const L = [];
  const put = (k, val) => {
    if (val === undefined || val === null || String(val).trim() === '') return;
    L.push(`${k} = ${val}`);
  };

  L.push('[Interface]');
  put('PrivateKey', vaultPeer(p.public_key || '').private_key);
  put('Address', asList(p.allowed_ips).join(', '));
  put('DNS', c.dns);
  put('MTU', c.mtu || e.mtu);
  put('Jc', e.jc);
  put('Jmin', e.jmin);
  put('Jmax', e.jmax);
  put('S1', e.s1);
  put('S2', e.s2);
  put('S3', e.s3);
  put('S4', e.s4);
  put('H1', e.h1);
  put('H2', e.h2);
  put('H3', e.h3);
  put('H4', e.h4);
  put('I1', c.i1);
  put('I2', c.i2);
  put('I3', c.i3);
  put('I4', c.i4);
  put('I5', c.i5);

  L.push('');
  L.push('[Peer]');
  put('PublicKey', v.server_public_key);
  put('PresharedKey', p.pre_shared_key);
  put('AllowedIPs', c.allowed_ips);
  if (c.endpoint_host) put('Endpoint', `${c.endpoint_host}:${e.listen_port ?? ''}`.replace(/:$/, ''));
  put('PersistentKeepalive', c.persistent_keepalive);

  return L.join('\n') + '\n';
}

let modalFile = { name: 'peer.conf', text: '' };

function showConf(i) {
  const p = ep().peers[i];
  const text = buildConf(i);
  modalFile = { name: peerLabel(p, i) + '.conf', text };
  $('#modal-title').textContent = modalFile.name;
  $('#modal-body').textContent = text;
  $('#modal').classList.remove('hidden');
}

/* --------------------------------------------------------------- commands */

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type: type || 'text/plain' }));
  const a = el('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = el('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast(t('toast.copied'), 'ok');
}

function addEndpoint() {
  const e = {
    type: 'wireguard',
    tag: 'awg-server',
    address: ['10.3.2.1/24', 'fd42:3:2::1/64'],
    private_key: '',
    listen_port: 51820,
    mtu: 1280,
    jc: 5, jmin: 117, jmax: 450,
    s1: 116, s2: 141, s3: 73, s4: 72,
    h1: '', h2: '', h3: '', h4: '',
    peers: [],
  };
  let n = 1;
  const taken = new Set(endpoints().map((x) => x.tag));
  while (taken.has(e.tag)) e.tag = 'awg-server-' + (++n);
  S.config.endpoints.push(e);
  S.sel = S.config.endpoints.length - 1;
  vaultEp(e.tag);
  render();
  touch();
}

function nextClientName() {
  const taken = new Set(Object.values(vEp().peers).map((p) => (p.name || '').trim()));
  let n = 1;
  while (taken.has('client-' + n)) n++;
  return 'client-' + n;
}

/** Fully automatic: keypair, preshared key, free address pair, name. */
async function addPeers(count) {
  const e = ep();
  if (!Array.isArray(e.peers)) e.peers = [];
  let made = 0;
  try {
    for (let n = 0; n < count; n++) {
      const ips = nextFreeAddresses(e);
      if (!ips.length) {
        toast(made ? t('toast.subnet_full', { n: made }) : t('toast.no_free'), 'err');
        break;
      }
      const kp = await api('/api/keypair', {});
      const psk = await api('/api/psk', {});
      e.peers.push({
        public_key: kp.public_key,
        pre_shared_key: psk.pre_shared_key,
        allowed_ips: ips,
      });
      vEp().peers[kp.public_key] = { name: nextClientName(), private_key: kp.private_key };
      made++;
    }
  } catch (err) {
    toast(String(err.message || err), 'err');
  }
  if (made) {
    renderPeers();
    touch();
    toast(t('toast.created', { n: made }), 'ok');
  }
}

async function load() {
  const st = await api('/api/state');
  S.config = st.config;
  S.vault = st.vault;
  S.meta = st.meta;
  S.dirty = false;
  if (!S.vault.endpoints) S.vault.endpoints = {};

  $('#path-config').textContent = st.meta.config_path + (st.meta.config_exists ? '' : ' (new)');
  $('#path-vault').textContent = st.meta.vault_path + (st.meta.vault_exists ? '' : ' (new)');
  renderLanguagePicker();
  $('#comment-note').classList.toggle('hidden', !st.meta.config_has_comments);
  $('#btn-restart').classList.toggle('hidden', !st.meta.restart_enabled);
  $('#btn-restart').title = st.meta.restart_cmd;
  $('#btn-save').disabled = st.meta.read_only;
  if (st.meta.read_only) $('#btn-save').title = 'server started with --read-only';
  (st.meta.errors || []).forEach((m) => toast(m, 'err'));

  normalizeConfig();
  await syncServerKeys();
  S.sel = endpoints().findIndex(isWg);
  render();
}

/** Derive any missing server public key so clients are usable straight away. */
async function syncServerKeys() {
  for (const e of endpoints()) {
    if (!isWg(e) || !isKey(e.private_key)) continue;
    const v = vaultEp(e.tag || '');
    if (v.server_public_key) continue;
    try {
      const kp = await api('/api/keypair', { private_key: e.private_key });
      v.server_public_key = kp.public_key;
    } catch { /* validation will flag it */ }
  }
}

async function save() {
  try {
    const r = await api('/api/save', { config: S.config, vault: S.vault });
    S.dirty = false;
    refresh();
    const notes = [];
    if (r.check && r.check.status === 'ok') notes.push(t('toast.check_ok'));
    if (r.check && r.check.status === 'skipped') {
      notes.push(t('toast.check_skipped', { why: r.check.detail }));
    }
    if (r.check && (r.check.status === 'failed' || r.check.status === 'error')) {
      notes.push(t('toast.check_advisory') + '\n' + r.check.detail);
    }
    if (r.config_backup) notes.push(t('toast.backup', { path: r.config_backup }));
    if (S.meta.config_has_comments && !r.comments_preserved) {
      notes.push(t('toast.comments_lost'));
    }
    toast(t('toast.saved', { when: r.saved_at }) +
          (notes.length ? '\n' + notes.join('\n') : ''), 'ok');
  } catch (err) {
    if (err.check) {
      toast(t('toast.check_rejected') + '\n\n' + (err.check.detail || ''), 'err');
    } else {
      toast(t('toast.save_failed', { err: err.message || err }), 'err');
    }
  }
}

/* ------------------------------------------------------------------ wiring */

document.addEventListener('click', (ev) => {
  const btn = ev.target.closest('[data-copy]');
  if (btn) copyText($(btn.dataset.copy).textContent);
});

$('#btn-reload').addEventListener('click', async () => {
  if (S.dirty && !confirm(t('confirm.discard'))) return;
  await load();
  toast(t('toast.reloaded'), 'ok');
});
$('#btn-save').addEventListener('click', save);
$('#btn-restart').addEventListener('click', async () => {
  if (!confirm(t('confirm.restart'))) return;
  try {
    const r = await api('/api/restart', {});
    toast(r.ok ? t('toast.restarted')
               : t('toast.restart_failed') + '\n' + (r.stderr || r.stdout),
          r.ok ? 'ok' : 'err');
  } catch (err) {
    toast(String(err.message || err), 'err');
  }
});
$('#lang').addEventListener('change', (ev) => setLanguage(ev.target.value, true));
$('#btn-add-peer').addEventListener('click', () => {
  const n = Math.max(1, Math.min(50, parseInt($('#add-count').value, 10) || 1));
  addPeers(n);
});
$('#btn-add-endpoint-empty').addEventListener('click', addEndpoint);
$('#btn-dl-config').addEventListener('click',
  () => download('config.json', JSON.stringify(S.config, null, 2) + '\n', 'application/json'));

$('#btn-bundle').addEventListener('click', async () => {
  const e = ep();
  const files = (e.peers || [])
    .map((p, i) => ({ name: peerLabel(p, i) + '.conf', content: buildConf(i) }))
    .filter((f) => f.content.includes('PrivateKey ='));
  if (!files.length) { toast(t('toast.no_conf_peers'), 'err'); return; }
  const seen = new Set();
  files.forEach((f) => {
    let n = f.name, k = 2;
    while (seen.has(n)) n = f.name.replace(/\.conf$/, '') + '-' + (k++) + '.conf';
    f.name = n;
    seen.add(n);
  });
  try {
    const res = await api('/api/bundle', { files });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = el('a');
    a.href = url;
    a.download = (e.tag || 'awg') + '-clients.zip';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (err) {
    toast(String(err.message || err), 'err');
  }
});

$('#modal-close').addEventListener('click', () => $('#modal').classList.add('hidden'));
$('#modal').addEventListener('click', (ev) => {
  if (ev.target.id === 'modal') $('#modal').classList.add('hidden');
});
$('#modal-download').addEventListener('click', () => download(modalFile.name, modalFile.text));

document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Escape') $('#modal').classList.add('hidden');
  if ((ev.ctrlKey || ev.metaKey) && ev.key === 's') { ev.preventDefault(); save(); }
});

window.addEventListener('beforeunload', (ev) => {
  if (S.dirty) { ev.preventDefault(); ev.returnValue = ''; }
});

/**
 * English is loaded first and kept as the fallback, so a locale that is missing
 * a key still shows something. Then: an explicit choice in this browser beats
 * the server's configured default, which beats the browser's own preference.
 */
async function boot() {
  S.fallback = await fetchLocale('en').catch(() => ({}));
  S.strings = S.fallback;

  const st = await api('/api/state');       // fetched again by load(); cheap and keeps load() simple
  const available = (st.meta.languages || []).map((l) => l.code);
  const browser = (navigator.languages || [navigator.language || ''])
    .map((l) => String(l).split('-')[0].toLowerCase())
    .find((l) => available.includes(l));

  const chosen = localStorage.getItem(LANG_KEY) || st.meta.language || browser || 'en';
  await setLanguage(available.includes(chosen) ? chosen : 'en', false);

  await load();
}

boot().catch((err) => {
  applyStaticText();
  toast(t('toast.load_failed', { err: err.message || err }), 'err');
});
