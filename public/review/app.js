// bSafety reviewer page. Everything from the API is rendered with textContent: reports carry free text written by
// strangers, so nothing here ever goes through innerHTML. Images are references only, loaded on request, blurred.
const $ = (s, el = document) => el.querySelector(s);
const el = (tag, props = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k instanceof Node ? k : String(k));
  return e;
};

const K = 'bsafety.session';
const store = {
  get() { try { return JSON.parse(sessionStorage.getItem(K) || 'null'); } catch { return null; } },
  set(v) { try { v ? sessionStorage.setItem(K, JSON.stringify(v)) : sessionStorage.removeItem(K); } catch {} },
};
let session = store.get();
let tab = 'open';
let selected = null;

class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
async function api(method, path, body) {
  const headers = { 'content-type': 'application/json' };
  if (session?.token) headers.authorization = `Bearer ${session.token}`;
  const r = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (r.status === 204) return null;
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401) { session = null; store.set(null); render(); }
    throw new ApiError(r.status, j.error || `HTTP ${r.status}`);
  }
  return j;
}

function showError(e) {
  const box = $('#err');
  box.textContent = e ? e.message || String(e) : '';
  box.hidden = !e;
}

// ---- sign in with bWalletX (the same challenge/verify flow as bDriveX)
async function signIn() {
  showError(null);
  const b = $('#signin');
  b.disabled = true;
  let modal = null;
  try {
    const C = window.bWalletXConnect;
    if (!C) throw new Error('The wallet connector did not load.');
    modal = C.pairingModal ? C.pairingModal({ title: 'Sign in to review' }) : undefined;
    const r = await C.signInWithBwalletX({
      pairing: modal,
      challenge: (identityKey) => api('POST', '/v1/auth/challenge', { identityKey }),
    });
    session = await api('POST', '/v1/auth/verify', { identityKey: r.identityKey, nonce: r.nonce, signature: r.signature });
    store.set(session);
    render();
  } catch (e) {
    if (e && e.code === 'NOT_FOUND') showError(new Error('No bWalletX found in this browser.'));
    else if (!(e && e.name === 'AbortError')) showError(e);
  } finally {
    try { modal && modal.close(); } catch {}
    b.disabled = false;
  }
}
async function signOut() {
  try { await api('POST', '/v1/auth/signout'); } catch {}
  session = null; store.set(null); render();
}

// ---- formatting
const LABEL = {
  report: 'Report', copyright_notice: 'Copyright notice', counter_notice: 'Counter-notice', privacy_request: "I'm in this photo",
  complaint: 'Complaint', appeal: 'Appeal', hash_match: 'Hash match', screening_flag: 'Screening flag', hash_mismatch: 'Hash mismatch',
};
const when = (t) => (t ? new Date(t).toLocaleString() : '—');
function dueText(c) {
  if (c.status === 'closed') return `decided ${when(c.closedAt)}`;
  const ms = c.dueBy - Date.now(), h = Math.round(Math.abs(ms) / 3600e3 * 10) / 10;
  return ms < 0 ? `OVERDUE by ${h} h` : `due in ${h} h`;
}

// Actions available per case type, and what each one means for that type (mirrors ACTIONS_FOR in src/app.js).
const ACTIONS = {
  report: ['approve', 'reject', 'reject_and_report', 'ban_seller', 'restore'],
  privacy_request: ['approve', 'reject', 'reject_and_report', 'ban_seller', 'restore'],
  copyright_notice: ['approve', 'reject', 'reject_and_report', 'ban_seller', 'restore'],
  screening_flag: ['approve', 'reject', 'reject_and_report', 'ban_seller', 'restore'],
  hash_mismatch: ['approve', 'reject', 'reject_and_report', 'ban_seller', 'restore'],
  counter_notice: ['approve', 'reject'],
  complaint: ['approve', 'reject', 'extend'],
  appeal: ['approve', 'reject', 'extend'],
  hash_match: ['reject_and_report', 'ban_seller'],
};
function actionLabel(type, a) {
  if (type === 'appeal') return { approve: 'Uphold appeal (restore)', reject: 'Refuse appeal', extend: 'Need more information (14 days)' }[a];
  if (type === 'complaint') return { approve: 'Uphold complaint', reject: 'Do not uphold', extend: 'Need more information (14 days)' }[a];
  if (type === 'counter_notice') return { approve: 'Accept counter-notice (restore)', reject: 'Refuse counter-notice' }[a];
  return { approve: 'Approve (keep up / not upheld)', reject: 'Reject (policy)', reject_and_report: 'Reject and report', ban_seller: 'Ban seller', restore: 'Restore' }[a];
}

// ---- rendering
async function render() {
  const signedIn = !!session?.token;
  $('#signin').hidden = signedIn;
  $('#signout').hidden = !signedIn;
  $('#who').textContent = signedIn ? `Reviewer ${session.identityKey.slice(0, 10)}…` : '';
  $('#main').hidden = !signedIn;
  if (!signedIn) return;
  for (const b of document.querySelectorAll('.tabs button')) b.classList.toggle('on', b.dataset.tab === tab);
  try {
    if (tab === 'log') return renderLog();
    const { cases } = await api('GET', `/v1/review/cases?status=${tab}`);
    const list = $('#list');
    list.replaceChildren(...(cases.length ? cases.map(row) : [el('p', { class: 'muted row' }, tab === 'open' ? 'Nothing waiting.' : 'None.')]));
    if (selected && !cases.some((c) => c.id === selected)) { selected = null; $('#detail').replaceChildren(el('p', { class: 'muted' }, 'Choose a case.')); }
  } catch (e) { showError(e); }
}
function row(c) {
  return el('button', { type: 'button', class: `row${selected === c.id ? ' sel' : ''}`, onclick: () => openCase(c.id) },
    el('div', { class: 'l1' },
      el('span', { class: `p p${c.priority}` }, `P${c.priority}`),
      el('strong', {}, c.categoryLabel || LABEL[c.type]),
      el('span', { class: 'tag' }, c.service)),
    el('div', { class: 'l2' },
      `${LABEL[c.type]} · `, el('span', { class: c.overdue ? 'overdue' : '' }, dueText(c)), c.resolution ? ` · ${c.resolution}` : ''));
}

async function openCase(id) {
  selected = id;
  for (const r of document.querySelectorAll('.row')) r.classList.remove('sel');
  showError(null);
  try {
    const d = await api('GET', `/v1/review/cases/${id}`);
    renderDetail(d);
    render();
  } catch (e) { showError(e); }
}

function imageBox(c) {
  if (!c.viewable || !c.ref) return el('div', { class: 'none' }, c.type === 'hash_match' ? 'Hash match, quarantined. There is no image to view, ever.' : 'No image reference for this item.');
  const box = el('div', { class: 'img' });
  const load = el('button', { type: 'button' }, 'Load image (blurred)');
  load.addEventListener('click', () => {
    const img = el('img', { alt: 'Reported item, blurred', class: 'blur-heavy', referrerpolicy: 'no-referrer' });
    img.src = c.ref;
    const less = el('button', { type: 'button' }, 'Less blur');
    const show = el('button', { type: 'button' }, 'Show');
    const hide = el('button', { type: 'button' }, 'Blur again');
    const level = (cls, logLevel) => {
      img.className = cls;
      if (logLevel) api('POST', `/v1/review/cases/${c.id}/image-shown`, { level: logLevel }).catch(showError);
    };
    less.addEventListener('click', () => level('blur-light', 'partial'));
    show.addEventListener('click', () => level('', 'clear'));
    hide.addEventListener('click', () => level('blur-heavy'));
    box.replaceChildren(el('div', { class: 'frame' }, img), el('div', { class: 'btns' }, less, show, hide));
  });
  box.append(load);
  return box;
}

function renderDetail(d) {
  const c = d.case;
  const kv = (pairs) => el('dl', { class: 'kv' }, pairs.filter(([, v]) => v != null && v !== '').flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v)]));
  const det = c.details || {};
  const extra = Object.entries(det).filter(([k]) => k !== 'text').map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : String(v)]);
  const parts = [
    el('h2', {}, `${LABEL[c.type]}: ${c.categoryLabel || c.category || ''}`),
    el('div', { class: 'muted' }, `${c.id} · ${c.service} · item ${c.itemId || '—'}`),
    c.note ? el('p', { class: 'none' }, c.note) : null,
    kv([
      ['Priority', `P${c.priority}`], ['Status', c.status], ['Due by', `${when(c.dueBy)} (${dueText(c)})`], ['Opened', when(c.createdAt)],
      ['Item hidden now', c.itemHidden == null ? null : c.itemHidden ? 'yes' : 'no'], ['Resolution', c.resolution], ['Decided by', c.decidedBy],
      ['Contact', c.contact], ['Parent case', c.parentId], ['Restore possible from', c.restoreEligibleAt ? when(c.restoreEligibleAt) : null],
      ['Seller', d.seller ? `${d.seller.identityKey.slice(0, 16)}…${d.seller.banned ? ' (banned)' : ''} · upheld copyright notices: ${d.seller.upheldCopyrightNotices}` : null],
      ['Authority', d.authority], ...extra,
    ]),
    det.text ? el('div', { class: 'text' }, det.text) : null,
    imageBox(c),
    actionForm(c),
    d.related.length ? el('h3', {}, 'Other cases on this item') : null,
    d.related.length ? el('ul', {}, d.related.map((r) => el('li', {}, `${r.id} · ${LABEL[r.type]} · ${r.category || ''} · ${r.status}${r.resolution ? ` (${r.resolution})` : ''}`))) : null,
    el('h3', {}, 'Log'),
    logTable(d.actions),
  ];
  $('#detail').replaceChildren(...parts.filter(Boolean));
}

function actionForm(c) {
  const allowed = (ACTIONS[c.type] || []).filter((a) => c.status !== 'closed' || ['restore', 'ban_seller'].includes(a));
  if (!allowed.length) return el('p', { class: 'muted' }, 'Decided. Nothing more to do here.');
  const sel = el('select', { name: 'action' }, allowed.map((a) => el('option', { value: a }, actionLabel(c.type, a))));
  const reason = el('textarea', { name: 'reason', required: true, placeholder: 'Reason (recorded in the log)' });
  const authority = el('label', {}, 'Authority report reference (if you have it)', el('input', { type: 'text', name: 'authorityRef' }));
  const sameWhy = el('label', {}, 'You made the original decision? Say why nobody else can review it', el('input', { type: 'text', name: 'sameReviewerWhy' }));
  const agreed = el('label', { class: 'check' }, el('input', { type: 'checkbox', name: 'rightsHolderAgreed' }), 'The rights holder agreed to restore early');
  const sync = () => {
    authority.hidden = sel.value !== 'reject_and_report';
    sameWhy.hidden = c.type !== 'appeal';
    agreed.hidden = c.type !== 'counter_notice';
  };
  sel.addEventListener('change', sync);
  sync();
  const go = el('button', { type: 'submit', class: 'primary' }, 'Record decision');
  const form = el('form', { class: 'act' }, el('label', {}, 'Action', sel), el('label', {}, 'Reason', reason), authority, sameWhy, agreed, go);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (['ban_seller', 'reject_and_report'].includes(sel.value) && !confirm(`${actionLabel(c.type, sel.value)}? This is logged and hard to undo.`)) return;
    go.disabled = true;
    try {
      const body = { action: sel.value, reason: reason.value };
      const f = new FormData(form);
      if (f.get('authorityRef')) body.authorityRef = f.get('authorityRef');
      if (f.get('sameReviewerWhy')) body.sameReviewerWhy = f.get('sameReviewerWhy');
      if (f.get('rightsHolderAgreed')) body.rightsHolderAgreed = true;
      await api('POST', `/v1/review/cases/${c.id}/actions`, body);
      await openCase(c.id);
    } catch (e) { showError(e); } finally { go.disabled = false; }
  });
  return form;
}

function logTable(actions) {
  return el('table', { class: 'log' },
    el('tr', {}, el('th', {}, 'When'), el('th', {}, 'Who'), el('th', {}, 'Action'), el('th', {}, 'Reason')),
    actions.map((a) => el('tr', {}, el('td', {}, when(a.at)), el('td', {}, a.actor.length > 20 ? `${a.actor.slice(0, 12)}…` : a.actor),
      el('td', {}, a.action + (a.caseId && tab === 'log' ? ` · ${a.caseId}` : '')), el('td', {}, a.reason || ''))));
}
async function renderLog() {
  const { actions } = await api('GET', '/v1/review/log?limit=300');
  $('#list').replaceChildren(el('div', { class: 'row muted' }, `${actions.length} most recent actions. The log is append-only.`));
  $('#detail').replaceChildren(logTable(actions));
}

$('#signin').addEventListener('click', signIn);
$('#signout').addEventListener('click', signOut);
for (const b of document.querySelectorAll('.tabs button')) b.addEventListener('click', () => { tab = b.dataset.tab; selected = null; $('#detail').replaceChildren(el('p', { class: 'muted' }, 'Choose a case.')); render(); });
render();
