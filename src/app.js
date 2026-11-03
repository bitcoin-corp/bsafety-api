// bSafety API: the shared trust-and-safety service for bPhotosX, bDriveX and bMarketX. Phase 1 (no outside vendor).
// See README.md for the endpoints and how each marketplace plugs in. The rules live in policy.js.
//
// Three kinds of caller:
//   public    anyone (report buttons, report pages, the hidden check, the buyer's verify)   CORS *
//   service   a marketplace's own server: Authorization: Service <token> (SERVICE_TOKENS)   no CORS
//   reviewer  a named human with a bWalletX listed in REVIEWER_KEYS: Authorization: Bearer <session>
//
// Images: this service never stores, returns or logs an image. Screening reads the bytes, hashes them, passes them
// to the configured providers and drops them. Reviewers get references (URLs to a server-made preview held by the
// marketplace), which the reviewer page opens behind a blur. Known-hash matches get no reference at all.
import { createServer } from 'node:http';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createChallenge, signSession, verifySession, verifySignIn } from '@bwalletx/connect/server';
import { openDb } from './db.js';
import { AUTHORITY, REASONS, SERVICES, acknowledgement, addWorkingDays, triage } from './policy.js';
import { ImageError, dHash, degenerate, hamming, isJpeg, isPng, sha256, solidPng } from './image.js';
import { classifierProvider, hashMatchProvider, screen } from './screening.js';
import { createNotifier } from './notify.js';

const here = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(here, '../public');
const require = createRequire(import.meta.url);

const HASH = /^[0-9a-f]{64}$/;
const DHASH = /^[0-9a-f]{16}$/;
const ITEM = /^[A-Za-z0-9._:@-]{1,128}$/;
const CASE = /^cs_[0-9a-f]{16}$/;
const KEY = /^0[23][0-9a-f]{64}$/;
const EMAILISH = /^[^\s@]{1,64}@[^\s@]{1,190}$/;
const HOUR = 3600_000;

class HttpError extends Error {
  constructor(status, message, headers, extra) { super(message); this.status = status; this.headers = headers; this.extra = extra; }
}
const fail = (status, message, headers, extra) => { throw new HttpError(status, message, headers, extra); };
const same = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

function send(res, status, body, headers = {}) {
  if (body === undefined || body === null) { res.writeHead(status, headers); return res.end(); }
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}

async function readBody(req, limit) {
  let n = 0;
  const parts = [];
  for await (const c of req) {
    n += c.length;
    if (n > limit) fail(413, 'Request too large.');
    parts.push(c);
  }
  return Buffer.concat(parts);
}
async function readJson(req, limit = 32 * 1024) {
  const b = await readBody(req, limit);
  try {
    const v = JSON.parse(b.toString('utf8') || '{}');
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error();
    return v;
  } catch { fail(400, 'Bad JSON.'); }
}

// ---- small field checks
const str = (v, max, name, { required = false } = {}) => {
  if (v == null || v === '') { if (required) fail(400, `${name} is required.`); return null; }
  if (typeof v !== 'string' || v.length > max) fail(400, `${name} must be text, ${max} characters at most.`);
  return v.trim();
};
const service = (v) => { if (!Object.hasOwn(SERVICES, v)) fail(400, `service must be one of ${Object.keys(SERVICES).join(', ')}.`); return v; };
const itemId = (v, { required = true } = {}) => {
  if (v == null && !required) return null;
  if (typeof v !== 'string' || !ITEM.test(v)) fail(400, 'itemId must be 1-128 characters: letters, digits and . _ : @ -');
  return v;
};
const contact = (v, { required = false } = {}) => {
  const c = str(v, 254, 'contact', { required });
  if (c && !EMAILISH.test(c)) fail(400, 'contact must be an email address.');
  return c;
};

/**
 * @param {object} cfg  see src/server.js for how env maps onto this. providers ({ hashMatch, classifier }) can only
 *                      be passed in code (tests); the server entry point always uses the env-driven ones.
 */
export function createApp(cfg) {
  const now = cfg.now || Date.now;
  const PROD = !!cfg.prod;
  const S = openDb(cfg.dbFile);
  const REVIEWERS = new Set([...cfg.reviewerKeys].map((k) => k.toLowerCase()));
  const SERVICE_TOKENS = cfg.serviceTokens; // Map token -> service
  const notify = cfg.notify || createNotifier({ webhookUrl: cfg.webhookUrl, webhookSecret: cfg.webhookSecret, log: cfg.log || console });
  const providers = cfg.providers || { hashMatch: hashMatchProvider(), classifier: classifierProvider() };
  const LIM = { ipPerHour: 10, itemPerHour: 20, dupHours: 24, ...cfg.limits };
  const DMAX = cfg.dhashMaxDistance ?? 10;
  const SESSION_HOURS = 12;
  const ipHash = (ip) => createHmac('sha256', cfg.ipSalt).update(String(ip)).digest('hex');
  const newCaseId = () => `cs_${randomBytes(8).toString('hex')}`;

  // ---------- perceptual denylist, kept in memory for the Hamming scan (small in phase 1)
  let dhashes = S.denylist.live.all();
  const reloadDenylist = () => { dhashes = S.denylist.live.all(); };
  /** { match: 'exact' | 'perceptual', entry, distance } or null */
  function denylisted(sha, dh) {
    const exact = sha && S.denylist.bySha.get(sha);
    if (exact) return { match: 'exact', entry: exact, distance: 0 };
    if (dh && !degenerate(dh)) {
      let best = null;
      for (const e of dhashes) {
        if (degenerate(e.dhash)) continue;
        const d = hamming(dh, e.dhash);
        if (d <= DMAX && (!best || d < best.distance)) best = { match: 'perceptual', entry: e, distance: d };
      }
      return best;
    }
    return null;
  }
  function denylistAdd({ sha, dh, category, source, caseId, svc, item, by }) {
    if (!sha && !dh) return false;
    if (sha && S.denylist.bySha.get(sha)) return false;
    S.denylist.add.run(sha || null, dh || null, category || null, source, caseId || null, svc || null, item || null, now(), by);
    reloadDenylist();
    return true;
  }

  // ---------- the log
  const log = (actor, action, { caseId = null, svc = null, item = null, reason = null, detail = null } = {}) =>
    S.actions.add.run(now(), actor, caseId, svc, item, action, reason, detail == null ? null : JSON.stringify(detail));

  const isHidden = (svc, item) => !!S.items.hidden.get(svc, item).hidden;

  /**
   * Open a case. Everything that creates a case goes through here: triage (§8.2), auto-hide, acknowledgement,
   * outbox, log, and the alert for priority 1-3.
   */
  function openCase({ type, svc, item = null, category = null, details = null, contactAddr = null, ipH = null, flags = {}, parentId = null,
    sha = null, dh = null, quarantined = false, restoreEligibleAt = null, actor = 'system' }) {
    const t = now();
    const out = S.tx(() => {
      if (item) S.items.touch.run(svc, item, t, t);
      const alreadyFlagged = item ? !!S.cases.flaggedByOthers.get(svc, item, ipH ?? '') : false;
      const tri = triage({ kind: type, category, service: svc, flags, alreadyFlagged, t });
      const id = newCaseId();
      const publicKinds = ['report', 'copyright_notice', 'counter_notice', 'privacy_request', 'complaint', 'appeal'];
      const ack = publicKinds.includes(type) ? acknowledgement({ kind: type, category, caseId: id, service: svc, flags }) : null;
      S.cases.add.run({
        id, service: svc, item_id: item, type, category, priority: tri.priority, status: quarantined ? 'quarantined' : 'open',
        hides: tri.hides ? 1 : 0, viewable: quarantined ? 0 : 1, due_by: tri.dueBy, created_at: t,
        details: details ? JSON.stringify(details) : null, contact: contactAddr, ip_hash: ipH, ack, parent_id: parentId,
        restore_eligible_at: restoreEligibleAt, sha256: sha, dhash: dh,
      });
      log(actor, 'case_opened', { caseId: id, svc, item, detail: { type, category, priority: tri.priority, dueBy: tri.dueBy, quarantined } });
      if (tri.hides && item) log('system', 'auto_hide', { caseId: id, svc, item, reason: `§8.2: ${type}${category ? ` (${category})` : ''} is hidden at once` });
      if (ack) {
        log('system', 'acknowledged', { caseId: id, svc, item, detail: { stored: true, emailed: false } });
        if (contactAddr) S.outbox.add.run(id, contactAddr, ack, t);
      }
      return { id, ...tri, ack };
    });
    if (out.priority <= 3) {
      log('system', 'alert', { caseId: out.id, svc, item, detail: { category: category || type, webhook: !!cfg.webhookUrl } });
      // Fire and forget: the reporter isn't kept waiting on the webhook. The payload is minimal (see notify.js).
      Promise.resolve(notify({ caseId: out.id, category: type === 'hash_match' ? 'hash_match' : category || type, dueBy: out.dueBy, service: svc }))
        .catch((e) => (cfg.log || console).error('[bsafety] notify failed', e.message));
    }
    return out;
  }

  // ---------- rate limits. In-memory bursts per IP (as bdrivex-api), plus durable per-IP and per-item counts from
  // the cases table (the IP only ever as a salted hash).
  const windows = new Map();
  const bump = (k, perMs) => {
    const t = now();
    let w = windows.get(k);
    if (!w || t - w.start > perMs) windows.set(k, (w = { start: t, n: 0 }));
    return ++w.n;
  };
  const slowDown = (perMs, msg = 'Too many requests. Wait a while and try again.') =>
    fail(429, msg, { 'retry-after': String(Math.ceil(Math.min(perMs, HOUR) / 1000)) });
  const socketIp = (req) => (cfg.trustProxy && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
  const limit = (req, name, max, perMs) => { if (bump(`${name}|${socketIp(req)}`, perMs) > max) slowDown(perMs); };
  /** The reporter's IP: from the socket, or for a marketplace server forwarding a report, its X-Reporter-IP. */
  const reporterIp = (req) => (req.service && req.headers['x-reporter-ip'] ? String(req.headers['x-reporter-ip']).slice(0, 64) : socketIp(req));
  function reportLimits(ipH, svc, item) {
    if (S.cases.byIpSince.get(ipH, now() - HOUR).n >= LIM.ipPerHour) slowDown(HOUR, 'You have sent a lot of reports in the last hour. Try again later, or email us.');
    if (item && S.cases.byItemSince.get(svc, item, now() - HOUR).n >= LIM.itemPerHour) slowDown(HOUR, 'This item has had a lot of reports in the last hour. We have them and are looking.');
  }

  // ---------- auth
  const nonceStore = {
    put: (nonce, c) => { S.nonces.prune.run(now()); S.nonces.put.run(nonce, JSON.stringify(c), c.expiresAt); },
    take: (nonce) => {
      const row = S.nonces.get.get(String(nonce));
      if (!row) return null;
      S.nonces.del.run(String(nonce));
      return JSON.parse(row.data);
    },
  };
  function serviceFrom(req) {
    const m = /^Service (.+)$/.exec(req.headers.authorization || '');
    if (!m) return null;
    for (const [tok, svc] of SERVICE_TOKENS) if (same(m[1], tok)) return svc;
    fail(401, 'That service token is not accepted.');
  }
  async function reviewerFrom(req) {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    const s = m && (await verifySession(m[1], { secret: cfg.sessionSecret }));
    if (!s || typeof s.sid !== 'string' || S.sessions.isRevoked.get(s.sid) || s.scope !== 'reviewer') fail(401, 'Sign in with a reviewer wallet first.');
    if (req.headers.origin && s.aud && req.headers.origin !== s.aud) fail(401, 'This sign-in belongs to another site.');
    // Checked on every request, so taking a key out of REVIEWER_KEYS (and restarting) ends its live sessions too.
    if (!REVIEWERS.has(s.sub)) fail(403, 'This wallet is not a reviewer.');
    return s;
  }

  // ---------- views
  const parse = (j) => { try { return j ? JSON.parse(j) : null; } catch { return null; } };
  function refFor(c, reviewer) {
    if (!c.viewable || !c.item_id) return null;
    // Development never shows a real image: every reference is a generated solid-colour placeholder.
    if (!PROD) return `/dev/placeholder/${c.id}.png`;
    const item = S.items.get.get(c.service, c.item_id);
    const base = item?.ref || (cfg.refTemplates?.[c.service] || '').replace('{id}', encodeURIComponent(c.item_id));
    if (!base) return null;
    if (!cfg.refSecret) return base;
    // Short-lived signed reference: the marketplace checks sig = HMAC(REF_SIGNING_SECRET, `${url-without-sig}`) and
    // exp before serving the preview, so only a reviewer who opened this case can fetch it, for 10 minutes.
    const u = new URL(base);
    u.searchParams.set('case', c.id);
    u.searchParams.set('rv', reviewer.slice(0, 16));
    u.searchParams.set('exp', String(Math.floor((now() + 600_000) / 1000)));
    u.searchParams.set('sig', createHmac('sha256', cfg.refSecret).update(u.toString()).digest('hex'));
    return u.toString();
  }
  function caseView(c, reviewer) {
    const v = {
      id: c.id, service: c.service, itemId: c.item_id, type: c.type, category: c.category, categoryLabel: REASONS[c.category] || null,
      priority: c.priority, status: c.status, dueBy: c.due_by, overdue: c.status !== 'closed' && c.due_by < now(),
      createdAt: c.created_at, closedAt: c.closed_at, resolution: c.resolution, decidedBy: c.decided_by,
      hides: !!c.hides, viewable: !!c.viewable, ref: refFor(c, reviewer), parentId: c.parent_id, restoreEligibleAt: c.restore_eligible_at,
      details: parse(c.details), contact: c.contact, acknowledgement: c.ack, itemHidden: c.item_id ? isHidden(c.service, c.item_id) : null,
    };
    if (c.type === 'hash_match') v.note = 'Hash match, quarantined. No image is available to view, ever. Report it and ban the seller.';
    return v;
  }
  const logView = (a) => ({ id: a.id, at: a.at, actor: a.actor, caseId: a.case_id, service: a.service, itemId: a.item_id, action: a.action, reason: a.reason, detail: parse(a.detail) });

  // ---------- routes
  const routes = [];
  const route = (method, pattern, fn, opts = {}) => routes.push({ method, pattern, fn, ...opts });

  route('GET', /^\/health$/, async () => [200, { ok: true }], { public: true });
  route('GET', /^\/v1\/reasons$/, async () => [200, {
    reasons: Object.entries(REASONS).map(([key, label]) => ({ key, label })),
    services: Object.entries(SERVICES).map(([key, s]) => ({ key, label: s.label })),
  }], { public: true });

  // ---- reports (§8.1): anyone, signed in or not, anonymous allowed
  route('POST', /^\/v1\/reports$/, async (req) => {
    limit(req, 'report-burst', 60, HOUR);
    const b = await readJson(req);
    const svc = service(b.service);
    if (req.service && req.service !== svc) fail(403, 'That token is for another service.');
    const item = itemId(b.itemId);
    if (!Object.hasOwn(REASONS, b.reason)) fail(400, `reason must be one of ${Object.keys(REASONS).join(', ')}.`);
    const details = str(b.details, 2000, 'details');
    const c = contact(b.contact);
    const ipH = ipHash(reporterIp(req));
    // The same person reporting the same item for the same reason again within a day gets the first case back.
    const dup = S.cases.duplicate.get(svc, item, ipH, b.reason, now() - LIM.dupHours * HOUR);
    if (dup) {
      const existing = S.cases.get.get(dup.id);
      return [200, { caseId: existing.id, duplicate: true, acknowledgement: existing.ack, hidden: isHidden(svc, item) }];
    }
    reportLimits(ipH, svc, item);
    const out = openCase({ type: 'report', svc, item, category: b.reason, details: details ? { text: details } : null, contactAddr: c, ipH, actor: req.service ? `service:${svc}` : 'public' });
    return [201, { caseId: out.id, acknowledgement: out.ack, hidden: isHidden(svc, item), dueBy: out.dueBy }];
  }, { public: true, serviceOptional: true });

  // ---- copyright notice (§12.4): only complete notices are accepted, and a complete notice hides the item
  route('POST', /^\/v1\/copyright\/notice$/, async (req) => {
    limit(req, 'notice-burst', 30, HOUR);
    const b = await readJson(req);
    const svc = service(b.service);
    const item = itemId(b.itemId);
    const missing = [];
    const name = str(b.name, 200, 'name'); if (!name) missing.push('name');
    const c = (() => { try { return contact(b.contact, { required: true }); } catch { missing.push('contact'); return null; } })();
    const work = str(b.work, 2000, 'work'); if (!work) missing.push('work');
    const why = str(b.infringement, 4000, 'infringement'); if (!why) missing.push('infringement');
    if (b.goodFaith !== true) missing.push('goodFaith');
    if (b.accurate !== true) missing.push('accurate');
    if (!['owner', 'agent'].includes(b.rightsHolder)) missing.push('rightsHolder');
    if (missing.length) fail(400, 'A copyright notice needs every item in §12.4. Missing: ' + missing.join(', ') + '.', undefined, { missing });
    const ipH = ipHash(reporterIp(req));
    reportLimits(ipH, svc, null);
    const out = openCase({ type: 'copyright_notice', svc, item, category: 'copyright', contactAddr: c, ipH,
      details: { name, work, infringement: why, rightsHolder: b.rightsHolder, goodFaith: true, accurate: true } });
    log('system', 'seller_to_be_told', { caseId: out.id, svc, item, reason: 'Copyright notice: tell the seller (phase 2 sends this).' });
    return [201, { caseId: out.id, acknowledgement: out.ack, hidden: isHidden(svc, item), dueBy: out.dueBy }];
  }, { public: true });

  // ---- counter-notice (§12.4.3): from the seller, forwarded by the marketplace server that signed them in
  route('POST', /^\/v1\/copyright\/counter-notice$/, async (req) => {
    const b = await readJson(req);
    const notice = CASE.test(String(b.noticeCaseId)) && S.cases.get.get(b.noticeCaseId);
    if (!notice || notice.type !== 'copyright_notice' || notice.service !== req.service) fail(404, 'No such copyright notice.');
    const seller = String(b.sellerKey || '').toLowerCase();
    if (!KEY.test(seller)) fail(400, 'sellerKey (the seller identity key) is required.');
    const item = S.items.get.get(notice.service, notice.item_id);
    if (item?.seller && !same(item.seller, seller)) fail(403, 'Only the seller of this item can send a counter-notice.');
    const missing = [];
    const name = str(b.name, 200, 'name'); if (!name) missing.push('name');
    const c = (() => { try { return contact(b.contact, { required: true }); } catch { missing.push('contact'); return null; } })();
    const why = str(b.why, 4000, 'why'); if (!why) missing.push('why');
    if (b.agreeContact !== true) missing.push('agreeContact');
    if (missing.length) fail(400, 'A counter-notice needs: ' + missing.join(', ') + '.', undefined, { missing });
    const eligible = addWorkingDays(now(), 10);
    const out = openCase({ type: 'counter_notice', svc: notice.service, item: notice.item_id, category: 'copyright', contactAddr: c, parentId: notice.id,
      details: { name, why, sellerKey: seller, agreeContact: true }, restoreEligibleAt: eligible, actor: `service:${req.service}` });
    // Pass it on to the rights holder (phase 2 emails it; the text is stored now).
    if (notice.contact) S.outbox.add.run(out.id, notice.contact, `A counter-notice was sent for your copyright notice ${notice.id}. Sender: ${name} (${c}). Their reasons: ${why}\nIf you have started legal action, tell us within 10 working days, by ${new Date(eligible).toISOString().slice(0, 10)}. Otherwise we may restore the item.`, now());
    log('system', 'counter_notice_passed_on', { caseId: out.id, svc: notice.service, item: notice.item_id, detail: { notice: notice.id, restoreEligibleAt: eligible, emailed: false } });
    return [201, { caseId: out.id, acknowledgement: out.ack, restoreEligibleAt: eligible }];
  }, { service: true });

  // ---- "I'm in this photo" (§12.6)
  route('POST', /^\/v1\/privacy-requests$/, async (req) => {
    limit(req, 'privacy-burst', 30, HOUR);
    const b = await readJson(req);
    const svc = service(b.service);
    const item = itemId(b.itemId);
    if (b.inPhoto !== true) fail(400, 'Confirm that you are the person in this photo (inPhoto: true), or that you act for them.');
    const c = contact(b.contact, { required: true });
    const details = str(b.details, 2000, 'details');
    const flags = { intimate: b.intimate === true, secretlyTaken: b.secretlyTaken === true, mayBeChild: b.mayBeChild === true };
    const ipH = ipHash(reporterIp(req));
    reportLimits(ipH, svc, item);
    const out = openCase({ type: 'privacy_request', svc, item, category: 'privacy', contactAddr: c, ipH, flags, details: { text: details, ...flags } });
    return [201, { caseId: out.id, acknowledgement: out.ack, hidden: isHidden(svc, item), dueBy: out.dueBy }];
  }, { public: true });

  // ---- complaints and appeals (§10)
  route('POST', /^\/v1\/complaints$/, async (req) => {
    limit(req, 'complaint-burst', 30, HOUR);
    const b = await readJson(req);
    const svc = service(b.service);
    if (!['complaint', 'appeal'].includes(b.kind)) fail(400, 'kind must be complaint or appeal.');
    const text = str(b.details, 4000, 'details', { required: true });
    const c = contact(b.contact, { required: true });
    let parent = null, item = itemId(b.itemId, { required: false });
    if (b.kind === 'appeal') {
      parent = CASE.test(String(b.caseId)) ? S.cases.get.get(b.caseId) : null;
      if (!parent || parent.service !== svc) fail(400, 'An appeal needs the reference (caseId) of the decision you are appealing.');
      item = parent.item_id;
    }
    const ipH = ipHash(reporterIp(req));
    reportLimits(ipH, svc, null);
    const out = openCase({ type: b.kind, svc, item, category: 'complaint', contactAddr: c, ipH, parentId: parent?.id ?? null, details: { text } });
    return [201, { caseId: out.id, acknowledgement: out.ack, dueBy: out.dueBy }];
  }, { public: true });

  // ---- the hidden check: marketplaces call this before serving an item (one, or a batch of up to 500)
  route('GET', /^\/v1\/hidden\/([a-z]+)\/([^/]+)$/, async (req, [svcRaw, idRaw]) => {
    limit(req, 'hidden', 6000, 60_000);
    const svc = service(svcRaw), item = itemId(decodeURIComponent(idRaw));
    return [200, { service: svc, itemId: item, hidden: isHidden(svc, item) }];
  }, { public: true });
  route('POST', /^\/v1\/hidden$/, async (req) => {
    limit(req, 'hidden', 6000, 60_000);
    const b = await readJson(req, 128 * 1024);
    const svc = service(b.service);
    if (!Array.isArray(b.ids) || b.ids.length > 500) fail(400, 'ids must be a list of at most 500 item ids.');
    const hidden = {};
    for (const id of b.ids) hidden[itemId(id)] = isHidden(svc, id);
    return [200, { service: svc, hidden }];
  }, { public: true });

  // ---- hash binding (§7.2): the buyer's client checks the opened photo against the screened hash before showing it
  route('POST', /^\/v1\/verify$/, async (req) => {
    limit(req, 'verify', 600, 60_000);
    const b = await readJson(req);
    const svc = service(b.service), item = itemId(b.itemId);
    const sha = String(b.sha256 || '').toLowerCase();
    if (!HASH.test(sha)) fail(400, 'sha256 (hex) of the opened file is required.');
    const it = S.items.get.get(svc, item);
    if (!it || it.status !== 'screened' || !it.screened_sha256) return [200, { ok: false, reason: 'not_screened' }];
    if (isHidden(svc, item)) return [200, { ok: false, reason: 'hidden' }];
    if (same(it.screened_sha256, sha)) return [200, { ok: true }];
    // Mismatch: don't show it, and report it automatically (one open case per item; per-IP limits apply).
    const ipH = ipHash(reporterIp(req));
    if (!S.cases.openMismatch.get(svc, item) && S.cases.byIpSince.get(ipH, now() - HOUR).n < LIM.ipPerHour) {
      openCase({ type: 'hash_mismatch', svc, item, category: 'other_illegal', ipH, sha, details: { text: 'Buyer client: opened file does not match the screened hash.', opened: sha, screened: it.screened_sha256 } });
    }
    return [200, { ok: false, reason: 'mismatch' }];
  }, { public: true });

  // ---- marketplace servers
  route('PUT', /^\/v1\/items\/([a-z]+)\/([^/]+)$/, async (req, [svcRaw, idRaw]) => {
    const svc = service(svcRaw), item = itemId(decodeURIComponent(idRaw));
    if (req.service !== svc) fail(403, 'That token is for another service.');
    const b = await readJson(req);
    const seller = b.seller == null ? null : String(b.seller).toLowerCase();
    if (seller && !KEY.test(seller)) fail(400, 'seller must be an identity key.');
    let ref = null;
    if (b.ref != null) {
      try { ref = new URL(String(b.ref)); } catch { fail(400, 'ref must be a URL.'); }
      if (ref.protocol !== 'https:' && (PROD || ref.protocol !== 'http:')) fail(400, 'ref must be an https URL.');
      ref = ref.toString();
    }
    S.items.register.run(svc, item, seller, ref, now());
    return [200, { service: svc, itemId: item }];
  }, { service: true });

  route('GET', /^\/v1\/items\/([a-z]+)\/([^/]+)$/, async (req, [svcRaw, idRaw]) => {
    const svc = service(svcRaw), item = itemId(decodeURIComponent(idRaw));
    if (req.service !== svc) fail(403, 'That token is for another service.');
    const it = S.items.get.get(svc, item);
    const hidden = isHidden(svc, item);
    const screened = it?.status === 'screened';
    return [200, { service: svc, itemId: item, status: it?.status || 'unknown', screened, hidden, listable: screened && !hidden, screenedSha256: it?.screened_sha256 || null }];
  }, { service: true });

  // Screening before display (§7.2). Body: the image bytes (image/png or image/jpeg). 200 only when screened.
  route('POST', /^\/v1\/screen\/([a-z]+)\/([^/]+)$/, async (req, [svcRaw, idRaw]) => {
    const svc = service(svcRaw), item = itemId(decodeURIComponent(idRaw));
    if (req.service !== svc) fail(403, 'That token is for another service.');
    const buf = await readBody(req, cfg.screenMaxBytes || 40 * 2 ** 20);
    if (!isPng(buf) && !isJpeg(buf)) fail(415, 'Send the image as PNG or JPEG.');
    const sha = sha256(buf);
    let dh;
    try { dh = dHash(buf); } catch (e) { if (e instanceof ImageError) fail(415, e.message); throw e; }
    const t = now();
    S.items.touch.run(svc, item, t, t);
    const it = S.items.get.get(svc, item);
    const actor = `service:${svc}`;
    const no = (status, why, extra = {}) => [409, { screened: false, status, why, message: "This photo can't be listed.", ...extra }];
    if (it.removed_at || (it.seller && S.bans.get.get(it.seller))) { log(actor, 'screening', { svc, item, detail: { outcome: 'refused_removed_or_banned', sha256: sha } }); return no('blocked', 'removed_or_banned'); }

    // Our own denylist first: a photo removed for illegality can't be listed again by anyone (§9.2).
    const hit = denylisted(sha, dh);
    if (hit) {
      S.items.screenResult.run('blocked', null, null, null, JSON.stringify({ denylist: hit.match }), t, svc, item);
      const out = openCase({ type: 'hash_match', svc, item, category: hit.entry.category || 'child_abuse', sha, dh, quarantined: true,
        details: { source: 'denylist', match: hit.match, distance: hit.distance, denylistId: hit.entry.id } });
      log(actor, 'screening', { caseId: out.id, svc, item, detail: { outcome: 'blocked', by: `denylist_${hit.match}`, sha256: sha, dhash: dh } });
      return no('blocked', 'denylisted');
    }

    const r = await screen(buf, providers);
    const detail = { outcome: r.outcome, hashMatch: r.hash?.status, classifier: r.classify?.status, sha256: sha, dhash: dh };
    if (r.outcome === 'blocked') {
      S.items.screenResult.run('blocked', null, null, null, JSON.stringify(detail), t, svc, item);
      const out = openCase({ type: 'hash_match', svc, item, category: 'child_abuse', sha, dh, quarantined: true, details: { source: r.hash.provider, match: 'known_hash' } });
      denylistAdd({ sha, dh, category: 'child_abuse', source: 'hash_match', caseId: out.id, svc, item, by: 'system' });
      log(actor, 'screening', { caseId: out.id, svc, item, detail });
      return no('blocked', 'hash_match');
    }
    if (r.outcome === 'suspected_csam' || r.outcome === 'flagged') {
      S.items.screenResult.run('in_review', null, null, null, JSON.stringify(detail), t, svc, item);
      const out = openCase({ type: 'screening_flag', svc, item, category: r.outcome === 'suspected_csam' ? 'child_abuse' : 'nudity_sexual', sha, dh,
        details: { labels: r.classify.labels || {}, provider: r.classify.provider } });
      log(actor, 'screening', { caseId: out.id, svc, item, detail });
      return no('in_review', r.outcome);
    }
    if (r.outcome !== 'screened') {
      S.items.screenResult.run('unscreened', null, null, null, JSON.stringify(detail), t, svc, item);
      log(actor, 'screening', { svc, item, detail: { ...detail, why: r.why } });
      return no('unscreened', r.why, { message: 'Listing is not open yet: screening is not set up.' });
    }
    S.items.screenResult.run('screened', sha, dh, t, JSON.stringify(detail), t, svc, item);
    log(actor, 'screening', { svc, item, detail });
    return [200, { screened: true, status: 'screened', sha256: sha, dhash: dh }];
  }, { service: true });

  // Denylist check on upload or listing. Body: the image (PNG/JPEG), or JSON { sha256, dhash }.
  route('POST', /^\/v1\/denylist\/check$/, async (req) => {
    const type = String(req.headers['content-type'] || '');
    let sha = null, dh = null;
    if (type.startsWith('application/json')) {
      const b = await readJson(req);
      sha = b.sha256 == null ? null : String(b.sha256).toLowerCase();
      dh = b.dhash == null ? null : String(b.dhash).toLowerCase();
      if ((sha && !HASH.test(sha)) || (dh && !DHASH.test(dh)) || (!sha && !dh)) fail(400, 'Send sha256 (64 hex) and/or dhash (16 hex), or the image itself.');
    } else {
      const buf = await readBody(req, cfg.screenMaxBytes || 40 * 2 ** 20);
      if (!buf.length) fail(400, 'Send the image, or JSON { sha256, dhash }.');
      sha = sha256(buf);
      if (isPng(buf) || isJpeg(buf)) { try { dh = dHash(buf); } catch (e) { if (!(e instanceof ImageError)) throw e; } }
    }
    const hit = denylisted(sha, dh);
    if (hit) log(`service:${req.service}`, 'denylist_hit', { svc: req.service, detail: { match: hit.match, distance: hit.distance, denylistId: hit.entry.id } });
    return [200, { denylisted: !!hit, match: hit?.match ?? null, distance: hit?.distance ?? null, sha256: sha, dhash: dh }];
  }, { service: true });

  // ---- reviewer sign-in (the same challenge/verify flow as bdrivex-api, with @bwalletx/connect)
  const reviewOrigin = (req) => {
    const origin = req.headers.origin;
    if (!origin || !cfg.origins.includes(origin)) fail(403, 'Sign in from the review page.');
    return origin;
  };
  route('POST', /^\/v1\/auth\/challenge$/, async (req) => {
    limit(req, 'auth', 30, 600_000);
    const origin = reviewOrigin(req);
    const { identityKey } = await readJson(req);
    try { return [200, await createChallenge({ origin, identityKey, store: nonceStore })]; } catch (e) { fail(400, e.message); }
  }, { reviewCors: true });
  route('POST', /^\/v1\/auth\/verify$/, async (req) => {
    limit(req, 'auth', 30, 600_000);
    const origin = reviewOrigin(req);
    const b = await readJson(req);
    const key = await verifySignIn({ origin, store: nonceStore, identityKey: b.identityKey, nonce: b.nonce, signature: b.signature });
    if (!key) fail(401, 'That signature was not accepted. Start again.');
    if (!REVIEWERS.has(key)) { log(key, 'reviewer_sign_in_refused'); fail(403, 'This wallet is not a reviewer.'); }
    const maxAge = SESSION_HOURS * 3600;
    const token = await signSession({ sub: key, aud: origin, sid: randomBytes(16).toString('base64url'), gen: 0, scope: 'reviewer' }, { secret: cfg.sessionSecret, maxAge });
    log(key, 'reviewer_signed_in');
    return [200, { token, identityKey: key, expiresAt: now() + maxAge * 1000 }];
  }, { reviewCors: true });
  route('POST', /^\/v1\/auth\/signout$/, async (req) => {
    S.sessions.revoke.run(req.session.sid, req.session.exp * 1000);
    return [204, null];
  }, { reviewer: true });

  // ---- the review queue
  route('GET', /^\/v1\/review\/me$/, async (req) => [200, { identityKey: req.reviewer }], { reviewer: true });

  route('GET', /^\/v1\/review\/cases$/, async (req, _m, url) => {
    const status = url.searchParams.get('status') || 'open';
    if (!['open', 'quarantined', 'closed'].includes(status)) fail(400, 'status must be open, quarantined or closed.');
    const n = Math.min(500, Math.max(1, Number(url.searchParams.get('limit')) || 200));
    const rows = S.cases.queue.all(status, n);
    // Closed cases newest first; the live queue in §8.2 order (priority, then due-by).
    if (status === 'closed') rows.sort((a, b) => b.closed_at - a.closed_at);
    return [200, { status, cases: rows.map((c) => caseView(c, req.reviewer)) }];
  }, { reviewer: true });

  route('GET', /^\/v1\/review\/cases\/(cs_[0-9a-f]{16})$/, async (req, [id]) => {
    const c = S.cases.get.get(id);
    if (!c) fail(404, 'No such case.');
    log(req.reviewer, 'case_viewed', { caseId: id, svc: c.service, item: c.item_id });
    const item = c.item_id ? S.items.get.get(c.service, c.item_id) : null;
    const seller = item?.seller || null;
    return [200, {
      case: caseView(c, req.reviewer),
      item: item && { status: item.status, seller, removedAt: item.removed_at, removedReason: item.removed_reason, screenedAt: item.screened_at, hidden: isHidden(c.service, c.item_id) },
      seller: seller && { identityKey: seller, banned: !!S.bans.get.get(seller), upheldCopyrightNotices: S.cases.upheldCopyright.get(seller).n },
      related: c.item_id ? S.cases.forItem.all(c.service, c.item_id).filter((o) => o.id !== c.id).map((o) => ({ id: o.id, type: o.type, category: o.category, status: o.status, resolution: o.resolution, createdAt: o.created_at })) : [],
      actions: S.actions.forCase.all(id).map(logView),
      authority: AUTHORITY[c.type === 'hash_match' ? 'child_abuse' : c.category] || null,
    }];
  }, { reviewer: true });

  // The reviewer page calls this when someone presses "show" on a blurred image, so the log records each viewing.
  route('POST', /^\/v1\/review\/cases\/(cs_[0-9a-f]{16})\/image-shown$/, async (req, [id]) => {
    const c = S.cases.get.get(id);
    if (!c) fail(404, 'No such case.');
    if (!c.viewable) fail(409, 'This case has no image to show.');
    const { level } = await readJson(req, 1024);
    log(req.reviewer, 'image_unblurred', { caseId: id, svc: c.service, item: c.item_id, detail: { level: level === 'clear' ? 'clear' : 'partial' } });
    return [204, null];
  }, { reviewer: true });

  route('GET', /^\/v1\/review\/log$/, async (req, _m, url) => {
    const n = Math.min(1000, Math.max(1, Number(url.searchParams.get('limit')) || 200));
    return [200, { actions: S.actions.recent.all(n).map(logView) }];
  }, { reviewer: true });

  // One-click actions (§7.4). Every one needs a reason and is logged.
  const ACTIONS_FOR = {
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
  route('POST', /^\/v1\/review\/cases\/(cs_[0-9a-f]{16})\/actions$/, async (req, [id]) => {
    const b = await readJson(req);
    const who = req.reviewer;
    const action = String(b.action || '');
    const reason = str(b.reason, 2000, 'reason', { required: true });
    if (reason.length < 3) fail(400, 'Give a reason (a few words at least).');
    const result = S.tx(() => {
      const c = S.cases.get.get(id);
      if (!c) fail(404, 'No such case.');
      if (!ACTIONS_FOR[c.type]?.includes(action)) fail(400, `${action || 'That action'} is not available for a ${c.type.replace('_', ' ')} case. Choose: ${ACTIONS_FOR[c.type].join(', ')}.`);
      if (c.status === 'closed' && !['restore', 'ban_seller'].includes(action)) fail(409, 'This case is already decided. Restore it, or open an appeal.');
      const t = now(), svc = c.service, itemKey = c.item_id;
      const item = itemKey ? S.items.get.get(svc, itemKey) : null;
      const entry = (act, extra = {}) => log(who, act, { caseId: id, svc, item: itemKey, reason, detail: Object.keys(extra).length ? extra : null });
      const close = (resolution) => S.cases.close.run(t, resolution, who, id);
      const remove = (why) => { if (itemKey) S.items.remove.run(t, why, t, svc, itemKey); };
      const restoreItem = (caseRow) => {
        if (!caseRow.item_id) return;
        const it = S.items.get.get(caseRow.service, caseRow.item_id);
        if (it?.status === 'blocked') fail(409, 'A hash-matched item can never be restored.');
        S.items.unremove.run(t, caseRow.service, caseRow.item_id);
        for (const d of S.denylist.forItem.all(caseRow.service, caseRow.item_id)) {
          S.denylist.remove.run(t, who, d.id);
          log(who, 'denylist_remove', { caseId: id, svc: caseRow.service, item: caseRow.item_id, reason, detail: { denylistId: d.id } });
        }
        reloadDenylist();
      };
      // §10: an appeal is reviewed by someone other than the original decision-maker where possible; if not, say why.
      if (c.type === 'appeal' && ['approve', 'reject'].includes(action)) {
        const parent = c.parent_id && S.cases.get.get(c.parent_id);
        if (parent?.decided_by && parent.decided_by === who) {
          const why = str(b.sameReviewerWhy, 1000, 'sameReviewerWhy');
          if (!why) fail(409, 'You made the original decision. Ask another reviewer, or give sameReviewerWhy (why nobody else can review it).');
          log(who, 'same_reviewer_recorded', { caseId: id, svc, item: itemKey, reason: why });
        }
      }

      switch (action) {
        case 'approve': {
          if (c.type === 'counter_notice') {
            if (c.restore_eligible_at && t < c.restore_eligible_at && b.rightsHolderAgreed !== true)
              fail(409, `The rights holder has until ${new Date(c.restore_eligible_at).toISOString()} to say they have started legal action.`);
            const notice = S.cases.get.get(c.parent_id);
            if (notice) { restoreItem(notice); if (notice.status !== 'closed') S.cases.close.run(t, 'restored', who, notice.id); else S.cases.setResolution.run('restored', who, notice.id); }
            close('accepted');
            entry('approve', { restored: notice?.id ?? null });
            break;
          }
          if (c.type === 'appeal') {
            const parent = S.cases.get.get(c.parent_id);
            if (parent && parent.status !== 'quarantined') {
              restoreItem(parent);
              if (parent.status === 'closed') S.cases.setResolution.run('restored_on_appeal', who, parent.id); else S.cases.close.run(t, 'restored_on_appeal', who, parent.id);
            }
            close('upheld');
            entry('approve', { appealUpheld: true, restored: parent?.id ?? null });
            break;
          }
          if (c.type === 'screening_flag' && item?.status === 'in_review') {
            // A screening flag only exists when both providers were configured and the hash match was clear; the
            // classifier flagged and a human cleared it. That is the only other way an item becomes screened.
            S.items.screenResult.run('screened', c.sha256, c.dhash, t, JSON.stringify({ outcome: 'screened', by: 'human_review', caseId: id }), t, svc, itemKey);
          }
          close(c.type === 'complaint' ? 'upheld' : 'approved');
          entry('approve');
          break;
        }
        case 'reject': {
          if (['complaint', 'appeal', 'counter_notice'].includes(c.type)) { close('rejected'); entry('reject'); break; }
          remove('policy');
          if (c.type === 'screening_flag' && item) S.items.setStatus.run('unscreened', t, svc, itemKey);
          close('rejected');
          const extra = {};
          if (c.type === 'copyright_notice' && item?.seller) {
            const n = S.cases.upheldCopyright.get(item.seller).n; // includes this one now it's closed
            extra.upheldCopyrightNotices = n;
            if (n >= 3) extra.repeatInfringer = 'third upheld notice: end the account (§12.4.4)';
            else if (n >= 2) extra.repeatInfringer = 'second upheld notice: end selling (§12.4.4)';
          }
          entry('reject', extra);
          break;
        }
        case 'reject_and_report': {
          remove('illegal');
          const cat = c.type === 'hash_match' ? 'child_abuse' : c.category;
          const sha = c.sha256 || item?.screened_sha256 || null, dh = c.dhash || item?.dhash || null;
          const added = denylistAdd({ sha, dh, category: cat, source: c.type === 'hash_match' ? 'hash_match' : 'reviewer', caseId: id, svc, item: itemKey, by: who });
          if (added) log(who, 'denylist_add', { caseId: id, svc, item: itemKey, reason, detail: { sha256: sha, dhash: dh } });
          else if (!sha && !dh) log(who, 'denylist_no_hash', { caseId: id, svc, item: itemKey, reason: 'No hash known for this item (e.g. encrypted bDriveX file). Removed but not denylisted.' });
          close('rejected_reported');
          entry('reject_and_report', { authority: AUTHORITY[cat] || 'none for this category', authorityRef: str(b.authorityRef, 200, 'authorityRef') || 'pending: record the reference when you have it' });
          break;
        }
        case 'ban_seller': {
          const seller = item?.seller;
          if (!seller) fail(409, 'No seller is known for this item. The marketplace registers it with PUT /v1/items.');
          S.bans.add.run(seller, t, who, reason, id);
          remove('banned');
          const hiddenItems = S.items.bySeller.all(seller).length;
          if (c.status !== 'closed') close('banned');
          entry('ban_seller', { seller, itemsHidden: hiddenItems });
          break;
        }
        case 'restore': {
          restoreItem(c);
          if (c.status === 'closed') S.cases.setResolution.run('restored', who, id); else close('restored');
          entry('restore');
          break;
        }
        case 'extend': {
          if (c.status !== 'open') fail(409, 'Only an open complaint or appeal can be extended.');
          const due = c.created_at + 14 * 24 * HOUR;
          S.cases.extend.run(due, id);
          if (c.contact) S.outbox.add.run(id, c.contact, `We need more information to decide ${id}. It may take up to 14 days, until ${new Date(due).toISOString().slice(0, 10)}. ${reason}`, t);
          entry('extend', { dueBy: due });
          break;
        }
      }
      return S.cases.get.get(id);
    });
    return [200, { case: caseView(result, who) }];
  }, { reviewer: true });

  // ---- the reviewer page (static) and, outside production, generated placeholder images
  const STATIC = {
    '/review': ['index.html', 'text/html; charset=utf-8'],
    '/review/': ['index.html', 'text/html; charset=utf-8'],
    '/review/app.js': ['app.js', 'text/javascript; charset=utf-8'],
    '/review/style.css': ['style.css', 'text/css; charset=utf-8'],
  };
  const connectBundle = (() => { try { return require.resolve('@bwalletx/connect').replace(/index\.cjs$/, 'bwalletx-connect.global.js'); } catch { return null; } })();
  const PAGE_HEADERS = {
    'content-security-policy': `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'${PROD ? ' https:' : ''}; connect-src 'self' https: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`,
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'cache-control': 'no-store',
  };
  function serveStatic(path, res) {
    if (path === '/review/connect.js' && connectBundle) {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', ...PAGE_HEADERS });
      res.end(readFileSync(connectBundle));
      return true;
    }
    const s = STATIC[path];
    if (!s) return false;
    res.writeHead(200, { 'content-type': s[1], ...PAGE_HEADERS });
    res.end(readFileSync(join(PUBLIC_DIR, 'review', s[0])));
    return true;
  }
  function placeholder(path, res) {
    const m = /^\/dev\/placeholder\/([A-Za-z0-9_-]{1,64})\.png$/.exec(path);
    if (PROD || !m) return false;
    const h = sha256(Buffer.from(m[1]));
    const rgb = [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
    res.writeHead(200, { 'content-type': 'image/png', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    res.end(solidPng(320, 240, rgb));
    return true;
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const path = url.pathname;
    const r0 = routes.find((r) => r.pattern.test(path));
    // CORS: public routes for any site (report buttons live on every marketplace), reviewer routes for the review
    // page's origin only, service routes for no browser at all.
    if (r0?.public) res.setHeader('access-control-allow-origin', '*');
    else if ((r0?.reviewer || r0?.reviewCors) && req.headers.origin && cfg.origins.includes(req.headers.origin)) {
      res.setHeader('access-control-allow-origin', req.headers.origin);
      res.setHeader('vary', 'Origin');
    }
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'access-control-allow-methods': 'GET, POST, PUT, OPTIONS', 'access-control-allow-headers': 'Authorization, Content-Type', 'access-control-max-age': '600' });
      return res.end();
    }
    try {
      if (req.method === 'GET' && (serveStatic(path, res) || placeholder(path, res))) return;
      for (const r of routes) {
        const m = r.pattern.exec(path);
        if (!m || r.method !== req.method) continue;
        if (r.service) { req.service = serviceFrom(req); if (!req.service) fail(401, 'This endpoint is for marketplace servers (Authorization: Service <token>).'); }
        else if (r.serviceOptional) req.service = serviceFrom(req);
        if (r.reviewer) { req.session = await reviewerFrom(req); req.reviewer = req.session.sub; }
        const [status, body, headers] = await r.fn(req, m.slice(1), url);
        return send(res, status, body, headers);
      }
      fail(404, 'Not found.');
    } catch (e) {
      if (res.headersSent) return res.destroy();
      if (!(e instanceof HttpError)) (cfg.log || console).error('[bsafety]', req.method, path, e);
      const status = e instanceof HttpError ? e.status : 500;
      send(res, status, e instanceof HttpError ? { error: e.message, ...(e.extra || {}) } : { error: 'Something went wrong on our side.' }, e.headers);
      if (status !== 500) req.resume();
    }
  });

  const timer = setInterval(() => { S.sessions.prune.run(now()); S.nonces.prune.run(now()); windows.clear(); }, HOUR);
  timer.unref();
  server.on('close', () => { clearInterval(timer); try { S.db.close(); } catch {} });
  return { server, store: S };
}
