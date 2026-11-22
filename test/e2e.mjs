// End to end against a real server on a temp data dir (in-process, so screening providers can be swapped for fakes;
// the server entry point never accepts providers from env). Synthetic images only.
//   node test/e2e.mjs
import { createServer } from 'node:http';
import { createHmac, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PrivateKey, ProtoWallet } from '@bsv/sdk';
import { createApp } from '../src/app.js';
import { addWorkingDays } from '../src/policy.js';
import { decodeImage, sha256 } from '../src/image.js';
import { patternJpeg, patternPng, solidPng } from './fixtures.mjs';

let failures = 0;
const ok = (cond, what) => { console.log(`${cond ? '  ok ' : '  FAIL'} ${what}`); if (!cond) failures++; };
const H = 3600_000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- webhook receiver (alerts)
const hooks = [];
const hookSrv = createServer(async (req, res) => { let b = ''; for await (const c of req) b += c; hooks.push({ headers: req.headers, body: JSON.parse(b) }); res.end('ok'); });
await new Promise((r) => hookSrv.listen(0, '127.0.0.1', r));
const WEBHOOK = `http://127.0.0.1:${hookSrv.address().port}/hook`;

// ---- wallets: two reviewers, one stranger
const mk = async () => { const w = new ProtoWallet(PrivateKey.fromRandom()); return { w, key: (await w.getPublicKey({ identityKey: true })).publicKey }; };
const rev1 = await mk(), rev2 = await mk(), stranger = await mk();
const seller = (await mk()).key, seller2 = (await mk()).key;

// ---- providers: start "not configured" like the phase-1 stubs, switch per test
const fake = { hash: 'not_configured', cls: 'not_configured', labels: {} };
const providers = {
  hashMatch: { name: 'fake-hash', configured: () => fake.hash !== 'not_configured', check: async () => ({ status: fake.hash }) },
  classifier: { name: 'fake-classifier', configured: () => fake.cls !== 'not_configured', check: async () => ({ status: fake.cls, labels: fake.labels }) },
};

const data = mkdtempSync(join(tmpdir(), 'bsafety-test-'));
const SALT = randomBytes(32).toString('hex'), SECRET = randomBytes(32).toString('hex');
const TOK = { bphotosx: 'p'.repeat(40), bdrivex: 'd'.repeat(40), bmarketx: 'm'.repeat(40) };
let PORT;
const base = (extra = {}) => ({
  prod: false, dbFile: join(data, 'bsafety.db'), sessionSecret: SECRET, ipSalt: SALT, reviewerKeys: [rev1.key, rev2.key],
  serviceTokens: new Map(Object.entries(TOK).map(([s, t]) => [t, s])), trustProxy: true, webhookUrl: WEBHOOK, webhookSecret: '',
  limits: { ipPerHour: 6, itemPerHour: 4 }, log: { warn() {}, error: console.error }, ...extra,
});
// The review page is served by the service itself, so its origin is the service's own address, known only after
// listen(). The app reads cfg.origins on each request, so the array is filled in once the port is known.
const appOrigins = [];
const { server, store } = createApp({ ...base(), providers, origins: appOrigins });
await new Promise((r) => server.listen(0, '127.0.0.1', r));
PORT = server.address().port;
const BASE = `http://127.0.0.1:${PORT}`, ORIGIN = BASE;
appOrigins.push(ORIGIN);
const stop = () => { server.close(); hookSrv.close(); rmSync(data, { recursive: true, force: true }); };

// ---- request helpers
let ipN = 0;
const freshIp = () => `198.51.100.${++ipN}`;
async function call(method, path, { body, ip = '203.0.113.7', token, svc, headers = {}, raw } = {}) {
  const h = { 'x-forwarded-for': ip, ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  if (svc) h.authorization = `Service ${TOK[svc]}`;
  let payload;
  if (raw) { payload = raw; h['content-type'] ||= 'image/png'; }
  else if (body !== undefined) { payload = JSON.stringify(body); h['content-type'] = 'application/json'; }
  const r = await fetch(BASE + path, { method, headers: h, body: payload });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: r.status, json, headers: r.headers, text };
}
const report = (service, itemId, reason, opts = {}) => call('POST', '/v1/reports', { body: { service, itemId, reason, ...opts.body }, ip: opts.ip ?? freshIp(), svc: opts.svc, headers: opts.headers });
const hidden = async (service, id) => (await call('GET', `/v1/hidden/${service}/${encodeURIComponent(id)}`)).json.hidden;

console.log('basics');
{
  ok((await call('GET', '/health')).json.ok === true, 'health');
  const r = await call('GET', '/v1/reasons');
  ok(r.json.reasons.length === 11 && r.json.reasons.some((x) => x.key === 'terrorism') && r.headers.get('access-control-allow-origin') === '*', 'reasons list (§8.1) is public');
}

console.log('reports');
{
  const r = await report('bphotosx', 'p-1', 'harassment', { ip: '203.0.113.50', body: { details: 'He keeps posting this to target me.', contact: 'me@example.com' } });
  ok(r.status === 201 && /^cs_[0-9a-f]{16}$/.test(r.json.caseId) && /Reference: cs_/.test(r.json.acknowledgement), `anonymous report filed: ${r.json.caseId}`);
  const row = store.cases.get.get(r.json.caseId);
  ok(row.ip_hash === createHmac('sha256', SALT).update('203.0.113.50').digest('hex'), 'the IP is stored only as a salted hash');
  const everything = JSON.stringify(store.db.prepare('SELECT * FROM cases').all()) + JSON.stringify(store.db.prepare('SELECT * FROM actions').all());
  ok(!everything.includes('203.0.113.50'), 'the raw IP appears nowhere in cases or the log');
  ok(row.ack && store.outbox.forCase.all(r.json.caseId).length === 1, 'acknowledgement stored, and queued for the contact address (sent in phase 2)');
  const dup = await report('bphotosx', 'p-1', 'harassment', { ip: '203.0.113.50' });
  ok(dup.status === 200 && dup.json.duplicate && dup.json.caseId === r.json.caseId, 'same person, same item, same reason: the first case comes back');
  ok((await report('bphotosx', 'p-2', 'not-a-reason')).status === 400, 'unknown reason refused');
  ok((await report('nope', 'p-2', 'harassment')).status === 400, 'unknown service refused');
  ok((await report('bphotosx', '../../etc', 'harassment')).status === 400, 'bad item id refused');
  const anon = await report('bmarketx', 'm-1', 'fraud_scam');
  ok(anon.status === 201 && store.cases.get.get(anon.json.caseId).contact === null, 'no contact needed');

  // per-IP limit (6/hour in this test)
  const ip = '203.0.113.99';
  const codes = [];
  for (let i = 0; i < 7; i++) codes.push((await report('bphotosx', `lim-${i}`, 'other_illegal', { ip })).status);
  ok(codes.slice(0, 6).every((c) => c === 201) && codes[6] === 429, `per-IP limit: ${codes.join(' ')}`);
  // per-item limit (4/hour)
  const codes2 = [];
  for (let i = 0; i < 5; i++) codes2.push((await report('bphotosx', 'busy-item', 'harassment')).status);
  ok(codes2.slice(0, 4).every((c) => c === 201) && codes2[4] === 429, `per-item limit: ${codes2.join(' ')}`);
  // a marketplace server forwarding a report passes the reporter's IP; without a service token the header is ignored
  const fwd = await report('bdrivex', 'link-fwd', 'other_illegal', { svc: 'bdrivex', ip: '10.0.0.1', headers: { 'x-reporter-ip': '192.0.2.44' } });
  ok(store.cases.get.get(fwd.json.caseId).ip_hash === createHmac('sha256', SALT).update('192.0.2.44').digest('hex'), 'service-forwarded report: hashes X-Reporter-IP');
  const spoof = await report('bdrivex', 'link-fwd2', 'other_illegal', { ip: '10.0.0.2', headers: { 'x-reporter-ip': '192.0.2.45' } });
  ok(store.cases.get.get(spoof.json.caseId).ip_hash === createHmac('sha256', SALT).update('10.0.0.2').digest('hex'), 'public report: X-Reporter-IP is ignored');
  ok((await report('bdrivex', 'x', 'other_illegal', { svc: 'bphotosx' })).status === 403, 'a service token cannot file for another service');
}

console.log('auto-hide (§8.2)');
{
  const serious = ['child_abuse', 'intimate_image', 'secretly_taken', 'terrorism'];
  const reasons = (await call('GET', '/v1/reasons')).json.reasons.map((r) => r.key);
  for (const svc of ['bphotosx', 'bmarketx']) {
    const got = [];
    for (const reason of reasons) { const id = `ah-${svc}-${reason}`; await report(svc, id, reason); if (await hidden(svc, id)) got.push(reason); }
    ok(JSON.stringify(got.sort()) === JSON.stringify(serious.slice().sort()), `${svc}: hidden at once exactly ${got.join(', ')}`);
  }
  let all = true;
  for (const reason of reasons) { const id = `ah-bdrivex-${reason}`; await report('bdrivex', id, reason); all &&= await hidden('bdrivex', id); }
  ok(all, 'bdrivex: every report switches the item off (bDriveX pack §7.4)');
  await report('bphotosx', 'flagged-1', 'nudity_sexual', { ip: '203.0.113.120' });
  ok(!(await hidden('bphotosx', 'flagged-1')), 'nudity report: stays up');
  await report('bphotosx', 'flagged-1', 'other_illegal', { ip: '203.0.113.121' });
  ok(await hidden('bphotosx', 'flagged-1'), 'a second report from someone else on an already-flagged item: hidden');
  await report('bphotosx', 'flagged-2', 'nudity_sexual', { ip: '203.0.113.122' });
  await report('bphotosx', 'flagged-2', 'other_illegal', { ip: '203.0.113.122' });
  ok(!(await hidden('bphotosx', 'flagged-2')), 'the same person reporting twice does not count as "already flagged"');
  const batch = await call('POST', '/v1/hidden', { body: { service: 'bphotosx', ids: ['ah-bphotosx-child_abuse', 'ah-bphotosx-harassment', 'never-seen'] } });
  ok(batch.json.hidden['ah-bphotosx-child_abuse'] === true && batch.json.hidden['ah-bphotosx-harassment'] === false && batch.json.hidden['never-seen'] === false, 'batch hidden check');
  ok((await call('POST', '/v1/hidden', { body: { service: 'bphotosx', ids: Array.from({ length: 501 }, (_, i) => `x${i}`) } })).status === 400, 'batch is capped at 500');
}

console.log('alerts');
{
  hooks.length = 0;
  await report('bphotosx', 'alert-1', 'terrorism', { body: { details: 'FREE TEXT MUST NOT LEAK', contact: 'leak@example.com' } });
  await report('bphotosx', 'alert-2', 'fraud_scam');
  for (let i = 0; i < 50 && hooks.length < 1; i++) await sleep(20);
  await sleep(100);
  ok(hooks.length === 1 && hooks[0].body.category === 'terrorism', 'a serious report calls the webhook; a non-serious one does not');
  const h = hooks[0]?.body || {};
  ok(JSON.stringify(Object.keys(h).sort()) === JSON.stringify(['at', 'caseId', 'category', 'dueBy', 'service']), `payload is minimal: ${Object.keys(h).join(', ')}`);
  const s = JSON.stringify(hooks);
  ok(!s.includes('FREE TEXT') && !s.includes('leak@') && !s.includes('alert-1'), 'no free text, contact or item id in the alert');
}

console.log('reviewer auth');
const post = (p, b, o = ORIGIN) => fetch(BASE + p, { method: 'POST', headers: { 'content-type': 'application/json', origin: o }, body: JSON.stringify(b) });
async function signIn({ w, key }, signer = w) {
  const ch = await (await post('/v1/auth/challenge', { identityKey: key })).json();
  const { signature } = await signer.createSignature({ protocolID: ch.protocolID, keyID: ch.keyID, counterparty: 'anyone', data: Array.from(new TextEncoder().encode(ch.message)) });
  return post('/v1/auth/verify', { identityKey: key, nonce: ch.nonce, signature: Array.from(signature) });
}
let T1, T2;
{
  ok((await post('/v1/auth/challenge', { identityKey: rev1.key }, 'https://evil.example')).status === 403, 'challenge refused from another origin');
  const r1 = await signIn(rev1);
  const s1 = await r1.json();
  ok(r1.status === 200 && s1.token && s1.identityKey === rev1.key, 'a listed reviewer signs in with their wallet');
  T1 = s1.token;
  T2 = (await (await signIn(rev2)).json()).token;
  const rs = await signIn(stranger);
  ok(rs.status === 403, 'a valid signature from a wallet not in REVIEWER_KEYS is refused');
  const forged = await signIn(rev1, stranger.w);
  ok(forged.status === 401, "a signature from someone else's key is refused");
  // connect 0.5.5+: a challenge with no key (key and signature in one wallet sheet) binds the key claimed at verify.
  const keyless = async ({ w, key }, signer = w) => {
    const c = await (await post('/v1/auth/challenge', {})).json();
    const { signature } = await signer.createSignature({ protocolID: c.protocolID, keyID: c.keyID, counterparty: 'anyone', data: Array.from(new TextEncoder().encode(c.message)) });
    return post('/v1/auth/verify', { identityKey: key, nonce: c.nonce, signature: Array.from(signature) });
  };
  ok((await keyless(rev1)).status === 200, 'a reviewer signs in from a challenge made without a key (one wallet sheet)');
  ok((await keyless(rev1, stranger.w)).status === 401, "a keyless challenge refuses someone else's signature");
  ok((await keyless(stranger)).status === 403, 'a keyless challenge still refuses a wallet not in REVIEWER_KEYS');
  ok((await call('GET', '/v1/review/cases')).status === 401, 'no token: 401');
  ok((await call('GET', '/v1/review/cases', { token: 'garbage.token' })).status === 401, 'junk token: 401');
  ok((await call('GET', '/v1/review/cases', { svc: 'bphotosx' })).status === 401, 'a service token cannot use the review queue');
  ok((await call('GET', '/v1/items/bphotosx/p-1', { token: T1 })).status === 401, 'a reviewer token cannot use service endpoints');
  ok((await call('GET', '/v1/items/bphotosx/p-1', { headers: { authorization: 'Service nope' } })).status === 401, 'a wrong service token: 401');
  ok((await call('GET', '/v1/items/bdrivex/x', { svc: 'bphotosx' })).status === 403, "one marketplace's token can't read another's items");
  ok((await call('GET', '/v1/review/cases', { token: T1, headers: { origin: 'https://evil.example' } })).status === 401, 'a reviewer token used from another origin: 401');
  // a reviewer taken out of REVIEWER_KEYS loses live sessions (second app on the same data, as after a restart)
  const other = createApp({ ...base({ reviewerKeys: [rev2.key] }), origins: [ORIGIN] });
  await new Promise((r) => other.server.listen(0, '127.0.0.1', r));
  const r = await fetch(`http://127.0.0.1:${other.server.address().port}/v1/review/cases`, { headers: { authorization: `Bearer ${T1}` } });
  ok(r.status === 403, 'a reviewer removed from REVIEWER_KEYS is refused even with a live session');
  other.server.close();
}

console.log('queue: order and deadlines');
{
  const notice = await call('POST', '/v1/copyright/notice', { body: { service: 'bphotosx', itemId: 'q-copy', name: 'A Photographer', contact: 'ph@example.com', work: 'My photo "Dawn"', infringement: 'Listed by someone else', goodFaith: true, accurate: true, rightsHolder: 'owner' }, ip: freshIp() });
  const priv = await call('POST', '/v1/privacy-requests', { body: { service: 'bphotosx', itemId: 'q-priv', inPhoto: true, contact: 'me2@example.com' }, ip: freshIp() });
  const comp = await call('POST', '/v1/complaints', { body: { service: 'bphotosx', kind: 'complaint', details: 'You ignored my report.', contact: 'c@example.com' }, ip: freshIp() });
  const { json } = await call('GET', '/v1/review/cases?status=open', { token: T1 });
  const cs = json.cases;
  let sorted = true;
  for (let i = 1; i < cs.length; i++) if (cs[i].priority < cs[i - 1].priority || (cs[i].priority === cs[i - 1].priority && cs[i].dueBy < cs[i - 1].dueBy)) sorted = false;
  ok(cs.length > 20 && sorted, `${cs.length} open cases in priority then due-by order`);
  ok(cs[0].priority === 1 && cs[0].category === 'child_abuse', 'child abuse first');
  const by = (id) => cs.find((c) => c.id === id) || store.cases.get.get(id);
  const ca = cs.find((c) => c.category === 'child_abuse');
  ok(ca.dueBy - ca.createdAt === 4 * H, 'child abuse due in 4 hours');
  const ii = cs.find((c) => c.category === 'intimate_image');
  ok(ii.priority === 2 && ii.dueBy - ii.createdAt === 24 * H, 'intimate image: priority 2, 24 hours');
  const st = cs.find((c) => c.category === 'secretly_taken'), te = cs.find((c) => c.category === 'terrorism');
  ok(st.priority === 3 && te.priority === 3 && te.dueBy - te.createdAt === 24 * H, 'secretly taken and terrorism: priority 3, 24 hours');
  const n = by(notice.json.caseId), p = by(priv.json.caseId), c = by(comp.json.caseId);
  ok(notice.status === 201 && n.priority === 5 && n.dueBy === addWorkingDays(n.createdAt, 2), 'copyright notice: priority 5, 2 working days');
  ok(p.priority === 6 && p.dueBy === addWorkingDays(p.createdAt, 5), '"a photo of me": priority 6, 5 working days');
  ok(c.priority === 7 && c.dueBy - c.createdAt === 7 * 24 * H, 'complaint: priority 7, 7 days');
  ok(cs.every((x) => typeof x.overdue === 'boolean' && !('ip_hash' in x) && !('ipHash' in x)), 'each case has an overdue flag and no IP hash');
}

console.log('notices, privacy, complaints');
{
  const bad = await call('POST', '/v1/copyright/notice', { body: { service: 'bphotosx', itemId: 'cp-1', name: 'X', contact: 'x@example.com' }, ip: freshIp() });
  ok(bad.status === 400 && bad.json.missing.includes('work') && bad.json.missing.includes('goodFaith') && !(await hidden('bphotosx', 'cp-1')), 'an incomplete notice is refused, listing what is missing, and hides nothing');
  await call('PUT', '/v1/items/bphotosx/cp-1', { svc: 'bphotosx', body: { seller } });
  const good = await call('POST', '/v1/copyright/notice', { body: { service: 'bphotosx', itemId: 'cp-1', name: 'A Photographer', contact: 'ph@example.com', work: 'Photo "Dusk"', infringement: 'Copied', goodFaith: true, accurate: true, rightsHolder: 'agent' }, ip: freshIp() });
  ok(good.status === 201 && (await hidden('bphotosx', 'cp-1')) && /2 working days/.test(good.json.acknowledgement), 'a complete notice hides the item and is acknowledged');
  const cnBody = { noticeCaseId: good.json.caseId, sellerKey: seller, name: 'The Seller', contact: 'seller@example.com', why: 'I took this photo myself.', agreeContact: true };
  ok((await call('POST', '/v1/copyright/counter-notice', { body: cnBody })).status === 401, 'counter-notice needs the marketplace server');
  ok((await call('POST', '/v1/copyright/counter-notice', { svc: 'bphotosx', body: { ...cnBody, sellerKey: seller2 } })).status === 403, 'only the seller can counter-notify');
  const cn = await call('POST', '/v1/copyright/counter-notice', { svc: 'bphotosx', body: cnBody });
  ok(cn.status === 201 && Math.abs(cn.json.restoreEligibleAt - addWorkingDays(Date.now(), 10)) < 5000, 'counter-notice accepted; restore possible after 10 working days');
  ok(store.outbox.forCase.all(cn.json.caseId).some((m) => m.to_contact === 'ph@example.com' && /counter-notice/.test(m.body)), 'counter-notice queued to pass on to the rights holder');
  globalThis.__cn = { notice: good.json.caseId, counter: cn.json.caseId };

  const plain = await call('POST', '/v1/privacy-requests', { body: { service: 'bphotosx', itemId: 'pr-1', inPhoto: true, contact: 'p@example.com' }, ip: freshIp() });
  ok(plain.status === 201 && !(await hidden('bphotosx', 'pr-1')), '"I\'m in this photo": stays up pending review');
  const intim = await call('POST', '/v1/privacy-requests', { body: { service: 'bphotosx', itemId: 'pr-2', inPhoto: true, intimate: true, contact: 'p@example.com' }, ip: freshIp() });
  ok(await hidden('bphotosx', 'pr-2') && store.cases.get.get(intim.json.caseId).priority === 2, 'intimate: hidden at once, priority 2');
  const child = await call('POST', '/v1/privacy-requests', { body: { service: 'bphotosx', itemId: 'pr-3', inPhoto: true, mayBeChild: true, contact: 'p@example.com' }, ip: freshIp() });
  ok(await hidden('bphotosx', 'pr-3') && child.status === 201, 'may be a child: hidden at once');
  ok((await call('POST', '/v1/privacy-requests', { body: { service: 'bphotosx', itemId: 'pr-4', contact: 'p@example.com' }, ip: freshIp() })).status === 400, 'needs the "I am in this photo" confirmation');
  ok((await call('POST', '/v1/complaints', { body: { service: 'bphotosx', kind: 'appeal', details: 'Wrong decision', contact: 'a@example.com' }, ip: freshIp() })).status === 400, 'an appeal needs the case reference');
}

console.log('screening (fails closed) and verify()');
const imgA = patternPng(256, 192), imgB = patternPng(256, 192, { fx: 5, fy: 3, phase: 0.3 });
{
  await call('PUT', '/v1/items/bphotosx/ph-1', { svc: 'bphotosx', body: { seller, ref: 'https://bphotosx.com/review-preview/ph-1' } });
  const r = await call('POST', '/v1/screen/bphotosx/ph-1', { svc: 'bphotosx', raw: imgA });
  ok(r.status === 409 && r.json.screened === false && r.json.status === 'unscreened', 'providers not configured: 409, not screened');
  const st = await call('GET', '/v1/items/bphotosx/ph-1', { svc: 'bphotosx' });
  ok(st.json.listable === false && st.json.screened === false, 'and not listable');
  ok((await call('POST', '/v1/verify', { body: { service: 'bphotosx', itemId: 'ph-1', sha256: sha256(imgA) } })).json.ok === false, 'verify refuses an unscreened item');
  fake.hash = 'clear';
  ok((await call('POST', '/v1/screen/bphotosx/ph-1', { svc: 'bphotosx', raw: imgA })).status === 409, 'hash match configured but no classifier: still not screened');
  fake.hash = 'not_configured'; fake.cls = 'clear';
  ok((await call('POST', '/v1/screen/bphotosx/ph-1', { svc: 'bphotosx', raw: imgA })).status === 409, 'classifier but no hash match: still not screened');
  fake.hash = 'error';
  ok((await call('POST', '/v1/screen/bphotosx/ph-1', { svc: 'bphotosx', raw: imgA })).status === 409, 'hash match erroring: still not screened');
  fake.hash = 'clear'; fake.cls = 'clear';
  const ok1 = await call('POST', '/v1/screen/bphotosx/ph-1', { svc: 'bphotosx', raw: imgA });
  ok(ok1.status === 200 && ok1.json.screened && ok1.json.sha256 === sha256(imgA), 'both configured and clear: screened, sha256 recorded');
  ok((await call('GET', '/v1/items/bphotosx/ph-1', { svc: 'bphotosx' })).json.listable === true, 'now listable');
  ok((await call('POST', '/v1/screen/bphotosx/ph-1', { raw: imgA })).status === 401, 'screening needs a service token');
  ok((await call('POST', '/v1/screen/bphotosx/ph-1', { svc: 'bphotosx', raw: Buffer.from('GIF89a....') })).status === 415, 'non-PNG/JPEG refused');
  const jpg = await call('POST', '/v1/screen/bphotosx/ph-jpg', { svc: 'bphotosx', raw: patternJpeg(200, 150), headers: { 'content-type': 'image/jpeg' } });
  ok(jpg.status === 200, 'JPEG screened too');

  const v1 = await call('POST', '/v1/verify', { body: { service: 'bphotosx', itemId: 'ph-1', sha256: sha256(imgA) } });
  ok(v1.json.ok === true, 'verify: the opened photo matches the screened hash');
  const v2 = await call('POST', '/v1/verify', { body: { service: 'bphotosx', itemId: 'ph-1', sha256: sha256(imgB) } });
  await call('POST', '/v1/verify', { body: { service: 'bphotosx', itemId: 'ph-1', sha256: sha256(imgB) } });
  const mism = store.cases.forItem.all('bphotosx', 'ph-1').filter((c) => c.type === 'hash_mismatch');
  ok(v2.json.ok === false && v2.json.reason === 'mismatch' && mism.length === 1, 'a swapped file fails verify and is reported automatically (once)');
  ok(!(await hidden('bphotosx', 'ph-1')), 'a mismatch report alone does not hide the listing');

  // classifier flags
  fake.cls = 'flag'; fake.labels = { possibleMinor: true, nudity: true };
  hooks.length = 0;
  await call('PUT', '/v1/items/bphotosx/ph-2', { svc: 'bphotosx', body: { seller } });
  const f = await call('POST', '/v1/screen/bphotosx/ph-2', { svc: 'bphotosx', raw: imgB });
  const fc = store.cases.forItem.all('bphotosx', 'ph-2').find((c) => c.type === 'screening_flag');
  ok(f.status === 409 && f.json.status === 'in_review' && fc.priority === 1 && fc.category === 'child_abuse' && fc.viewable === 1, 'possible minor + nudity: held, priority-1 human review');
  for (let i = 0; i < 50 && !hooks.length; i++) await sleep(20);
  ok(hooks.some((h) => h.body.caseId === fc.id), 'and an alert');
  globalThis.__flag = fc.id;

  // known-hash match
  fake.cls = 'clear'; fake.hash = 'match';
  hooks.length = 0;
  const imgC = patternPng(256, 192, { fx: 2, fy: 4, phase: 0.6 });
  await call('PUT', '/v1/items/bphotosx/ph-3', { svc: 'bphotosx', body: { seller: seller2, ref: 'https://bphotosx.com/review-preview/ph-3' } });
  const m = await call('POST', '/v1/screen/bphotosx/ph-3', { svc: 'bphotosx', raw: imgC });
  const mc = store.cases.forItem.all('bphotosx', 'ph-3').find((c) => c.type === 'hash_match');
  ok(m.status === 409 && m.json.status === 'blocked' && m.json.message === "This photo can't be listed.", 'known-hash match: blocked; the seller sees only "can\'t be listed"');
  ok(mc.status === 'quarantined' && mc.viewable === 0 && (await hidden('bphotosx', 'ph-3')), 'stored as "hash match, quarantined", not viewable, hidden');
  const chk = await call('POST', '/v1/denylist/check', { svc: 'bphotosx', raw: imgC });
  ok(chk.json.denylisted && chk.json.match === 'exact', 'the matched image is now on the denylist');
  for (let i = 0; i < 50 && !hooks.length; i++) await sleep(20);
  ok(hooks.some((h) => h.body.category === 'hash_match'), 'hash match alert sent');
  globalThis.__match = mc.id;
  fake.hash = 'clear';
}

console.log('review cases: references, blur and quarantine');
{
  const open = (await call('GET', '/v1/review/cases?status=open', { token: T1 })).json.cases;
  const withRef = open.find((c) => c.itemId === 'ph-2');
  ok(withRef.viewable && withRef.ref === `/dev/placeholder/${withRef.id}.png`, 'in development every reference is a generated placeholder');
  const ph = await fetch(BASE + withRef.ref);
  const img = decodeImage(Buffer.from(await ph.arrayBuffer()));
  let flat = true;
  for (let i = 4; i < img.data.length; i += 4) if (img.data[i] !== img.data[0] || img.data[i + 1] !== img.data[1] || img.data[i + 2] !== img.data[2]) { flat = false; break; }
  ok(ph.headers.get('content-type') === 'image/png' && flat, 'and the placeholder is one solid colour');
  ok(!open.some((c) => c.type === 'hash_match'), 'hash matches are not in the open queue');
  const q = (await call('GET', '/v1/review/cases?status=quarantined', { token: T1 })).json.cases;
  const hm = q.find((c) => c.id === globalThis.__match);
  ok(hm && hm.ref === null && hm.viewable === false && /quarantined/.test(hm.note), 'quarantined list: no reference, ever');
  ok((await call('POST', `/v1/review/cases/${hm.id}/image-shown`, { token: T1, body: { level: 'clear' } })).status === 409, 'a hash match has no image to show');
  ok((await call('POST', `/v1/review/cases/${hm.id}/actions`, { token: T1, body: { action: 'approve', reason: 'looks fine' } })).status === 400, 'a hash match cannot be approved');
  ok((await call('POST', `/v1/review/cases/${hm.id}/actions`, { token: T1, body: { action: 'restore', reason: 'try' } })).status === 400, 'or restored');
  const page = await fetch(BASE + '/review');
  ok(page.status === 200 && /bSafety review/.test(await page.text()) && /script-src 'self'/.test(page.headers.get('content-security-policy')), 'reviewer page served with a strict CSP');
  ok((await fetch(BASE + '/review/connect.js')).status === 200 && (await fetch(BASE + '/review/app.js')).status === 200, 'page scripts served');

  // production: real references, signed and short-lived; no placeholders
  const prod = createApp({ ...base({ prod: true, refSecret: 'r'.repeat(40) }), providers, origins: [ORIGIN] });
  await new Promise((r) => prod.server.listen(0, '127.0.0.1', r));
  const P = `http://127.0.0.1:${prod.server.address().port}`;
  const refCase = open.find((c) => c.itemId === 'ph-1'); // registered with ref https://bphotosx.com/review-preview/ph-1
  const pr = await (await fetch(`${P}/v1/review/cases/${refCase.id}`, { headers: { authorization: `Bearer ${T2}`, origin: ORIGIN } })).json();
  const u = pr.case?.ref ? new URL(pr.case.ref) : null;
  let sigOk = false;
  if (u) { const sig = u.searchParams.get('sig'); u.searchParams.delete('sig'); sigOk = sig === createHmac('sha256', 'r'.repeat(40)).update(u.toString()).digest('hex'); }
  ok(u && u.origin === 'https://bphotosx.com' && u.pathname === '/review-preview/ph-1' && sigOk && Number(u.searchParams.get('exp')) * 1000 > Date.now(), 'production: the marketplace reference, HMAC-signed with a 10-minute expiry');
  ok((await fetch(`${P}${withRef.ref}`)).status === 404, 'production: no placeholder route');
  prod.server.close();
}

console.log('reviewer actions and the log');
const act = (id, body, token = T1) => call('POST', `/v1/review/cases/${id}/actions`, { token, body });
const caseFor = (svc, item, type = 'report') => store.cases.forItem.all(svc, item).find((c) => c.type === type);
{
  ok((await act(caseFor('bphotosx', 'ah-bphotosx-terrorism').id, { action: 'approve' })).status === 400, 'every action needs a reason');
  ok((await act(caseFor('bphotosx', 'ah-bphotosx-terrorism').id, { action: 'extend', reason: 'x'.repeat(5) })).status === 400, 'an action that does not fit the case type is refused');

  // approve: report not upheld -> visible again
  const a = caseFor('bphotosx', 'ah-bphotosx-terrorism');
  const ra = await act(a.id, { action: 'approve', reason: 'Reviewed: a war museum photo, not terrorist content.' });
  ok(ra.status === 200 && ra.json.case.status === 'closed' && ra.json.case.resolution === 'approved' && !(await hidden('bphotosx', 'ah-bphotosx-terrorism')), 'approve: closed, item visible again');
  ok((await act(a.id, { action: 'reject', reason: 'changed my mind' })).status === 409, 'a decided case cannot be decided again');

  // reject (policy): removed, not denylisted
  const b = caseFor('bphotosx', 'ah-bphotosx-nudity_sexual');
  await act(b.id, { action: 'reject', reason: 'Breaks the no-nudity policy (§5).' });
  ok(await hidden('bphotosx', 'ah-bphotosx-nudity_sexual') && store.items.get.get('bphotosx', 'ah-bphotosx-nudity_sexual').removed_reason === 'policy', 'reject (policy): removed');

  // reject and report: a screened item, so its hashes go on the denylist
  await report('bphotosx', 'ph-1', 'child_abuse', { ip: '203.0.113.200' });
  const c = store.cases.forItem.all('bphotosx', 'ph-1').find((x) => x.category === 'child_abuse');
  const rc = await act(c.id, { action: 'reject_and_report', reason: 'Reasonable grounds to infer CSAM.', authorityRef: 'NCA-TEST-0001' });
  ok(rc.status === 200 && rc.json.case.resolution === 'rejected_reported' && (await hidden('bphotosx', 'ph-1')), 'reject and report: removed');
  const exact = await call('POST', '/v1/denylist/check', { svc: 'bphotosx', raw: imgA });
  ok(exact.json.denylisted && exact.json.match === 'exact', 'denylist: exact sha256 match');
  const near = await call('POST', '/v1/denylist/check', { svc: 'bmarketx', raw: patternPng(200, 150, { bright: 10 }) });
  ok(near.json.denylisted && near.json.match === 'perceptual' && near.json.distance <= 10, `denylist: resized + brightened copy matches perceptually (distance ${near.json.distance})`);
  const nearJpg = await call('POST', '/v1/denylist/check', { svc: 'bmarketx', raw: patternJpeg(256, 192, {}, 60), headers: { 'content-type': 'image/jpeg' } });
  ok(nearJpg.json.match === 'perceptual', 'denylist: a JPEG re-encode matches perceptually');
  const diff = await call('POST', '/v1/denylist/check', { svc: 'bphotosx', raw: patternPng(256, 192, { fx: 4, fy: 1, phase: 0.15 }) });
  ok(diff.json.denylisted === false, 'denylist: a different image does not match');
  const byJson = await call('POST', '/v1/denylist/check', { svc: 'bdrivex', body: { sha256: sha256(imgA) } });
  ok(byJson.json.denylisted && byJson.json.match === 'exact', 'denylist: check by hash alone (JSON)');
  ok((await call('POST', '/v1/denylist/check', { raw: imgA })).status === 401, 'the denylist check is not public (no oracle for bad actors)');
  const relist = await call('POST', '/v1/screen/bmarketx/mk-relist', { svc: 'bmarketx', raw: patternPng(240, 180, { bright: -8 }) });
  const rq = store.cases.forItem.all('bmarketx', 'mk-relist').find((x) => x.type === 'hash_match');
  ok(relist.status === 409 && relist.json.status === 'blocked' && rq?.status === 'quarantined' && rq.viewable === 0, 'anyone relisting a near-duplicate anywhere is blocked and quarantined');
  const logC = store.actions.forCase.all(c.id);
  ok(logC.some((l) => l.action === 'denylist_add') && logC.some((l) => l.action === 'reject_and_report' && JSON.parse(l.detail).authorityRef === 'NCA-TEST-0001' && /NCA/.test(JSON.parse(l.detail).authority)), 'logged with the authority and its reference');

  // the flat-colour edge case: exact only
  await call('PUT', '/v1/items/bphotosx/flat-1', { svc: 'bphotosx', body: { seller } });
  await call('POST', '/v1/screen/bphotosx/flat-1', { svc: 'bphotosx', raw: solidPng(64, 64, [10, 20, 30]) });
  await report('bphotosx', 'flat-1', 'terrorism', { ip: '203.0.113.201' });
  await act(caseFor('bphotosx', 'flat-1').id, { action: 'reject_and_report', reason: 'Test: flat image.' });
  ok((await call('POST', '/v1/denylist/check', { svc: 'bphotosx', raw: solidPng(64, 64, [10, 20, 30]) })).json.match === 'exact', 'a denylisted flat image matches exactly');
  ok((await call('POST', '/v1/denylist/check', { svc: 'bphotosx', raw: solidPng(64, 64, [200, 20, 30]) })).json.denylisted === false, 'but does not swallow every other flat image');

  // restore (e.g. after a successful appeal): visible again, denylist entry lifted, logged
  const rr = await act(c.id, { action: 'restore', reason: 'Appeal evidence: misidentified, synthetic test.' }, T2);
  ok(rr.status === 200 && rr.json.case.resolution === 'restored' && !(await hidden('bphotosx', 'ph-1')), 'restore: visible again');
  ok((await call('POST', '/v1/denylist/check', { svc: 'bphotosx', raw: imgA })).json.denylisted === false, 'restore lifts the denylist entry it added');

  // the screening flag: a human approves -> screened
  const fr = await act(globalThis.__flag, { action: 'approve', reason: 'Adult, clothed; classifier false positive.' });
  const it = await call('GET', '/v1/items/bphotosx/ph-2', { svc: 'bphotosx' });
  ok(fr.status === 200 && it.json.screened && it.json.listable && it.json.screenedSha256 === sha256(imgB), 'approving a screening flag marks the item screened with the screened hash');

  // ban seller: every item of theirs hidden
  await call('PUT', '/v1/items/bphotosx/s2-a', { svc: 'bphotosx', body: { seller: seller2 } });
  await call('PUT', '/v1/items/bmarketx/s2-b', { svc: 'bmarketx', body: { seller: seller2 } });
  const hb = await act(globalThis.__match, { action: 'reject_and_report', reason: 'Known hash match. Reported.', authorityRef: 'NCA-TEST-0002' });
  const bb = await act(globalThis.__match, { action: 'ban_seller', reason: 'Known CSAM hash match: ban (§9.3.4).' });
  ok(hb.status === 200 && bb.status === 200 && store.bans.get.get(seller2), 'hash match: reported, then seller banned');
  ok((await hidden('bphotosx', 's2-a')) && (await hidden('bmarketx', 's2-b')), "all the banned seller's items are hidden, on every marketplace");
  const banned = await call('POST', '/v1/screen/bphotosx/s2-a', { svc: 'bphotosx', raw: patternPng(64, 64, { fx: 7 }) });
  ok(banned.status === 409 && banned.json.status === 'blocked', 'a banned seller cannot list');

  // counter-notice: not before 10 working days unless the rights holder agrees; then it restores
  const early = await act(globalThis.__cn.counter, { action: 'approve', reason: 'Seller has the rights.' });
  ok(early.status === 409, 'a counter-notice cannot restore before the 10 working days');
  const agreed = await act(globalThis.__cn.counter, { action: 'approve', reason: 'Rights holder withdrew the notice by email.', rightsHolderAgreed: true });
  ok(agreed.status === 200 && !(await hidden('bphotosx', 'cp-1')) && store.cases.get.get(globalThis.__cn.notice).resolution === 'restored', 'with the rights holder agreeing: restored');

  // complaints: extend to 14 days; appeals reviewed by someone else, or the same reviewer says why
  const comp = store.db.prepare("SELECT * FROM cases WHERE type = 'complaint' LIMIT 1").get();
  const ex = await act(comp.id, { action: 'extend', reason: 'Need the listing URL from the complainant.' });
  ok(ex.status === 200 && ex.json.case.dueBy === comp.created_at + 14 * 24 * H, 'complaint extended to 14 days, and the complainant is told (outbox)');
  const decided = caseFor('bphotosx', 'ah-bphotosx-nudity_sexual'); // rejected by reviewer 1
  const ap = await call('POST', '/v1/complaints', { body: { service: 'bphotosx', kind: 'appeal', caseId: decided.id, details: 'It was swimwear, not nudity.', contact: 'seller@example.com' }, ip: freshIp() });
  ok(ap.status === 201 && /someone other than/i.test(ap.json.acknowledgement), 'appeal filed and acknowledged');
  const same = await act(ap.json.caseId, { action: 'approve', reason: 'On reflection, swimwear.' }, T1);
  ok(same.status === 409, 'the original decision-maker cannot decide the appeal without saying why');
  const up = await act(ap.json.caseId, { action: 'approve', reason: 'Swimwear is allowed.' }, T2);
  ok(up.status === 200 && up.json.case.resolution === 'upheld' && !(await hidden('bphotosx', 'ah-bphotosx-nudity_sexual')), 'another reviewer upholds the appeal and the item is restored');

  // the log: who, when, what, why; append-only
  const log = (await call('GET', '/v1/review/log?limit=1000', { token: T1 })).json.actions;
  const mine = log.filter((l) => l.actor === rev1.key || l.actor === rev2.key);
  const kinds = new Set(mine.map((l) => l.action));
  ok(['approve', 'reject', 'reject_and_report', 'restore', 'ban_seller', 'extend', 'case_viewed'].every((k) => kinds.has(k)), `log has every reviewer action: ${[...kinds].join(', ')}`);
  ok(mine.filter((l) => ['approve', 'reject', 'reject_and_report', 'restore', 'ban_seller', 'extend'].includes(l.action)).every((l) => l.at > 0 && l.reason && l.caseId), 'each with who, when, which case and why');
  ok(log.some((l) => l.action === 'auto_hide' && l.actor === 'system') && log.some((l) => l.action === 'acknowledged') && log.some((l) => l.action === 'alert'), 'system actions (auto-hide, acknowledgement, alert) are logged too');
  await call('POST', `/v1/review/cases/${globalThis.__flag}/image-shown`, { token: T1, body: { level: 'partial' } });
  ok(store.actions.forCase.all(globalThis.__flag).some((l) => l.action === 'image_unblurred'), 'unblurring an image is logged');
  let upd = false, del = false;
  try { store.db.exec('UPDATE actions SET reason = \'edited\' WHERE id = 1'); } catch { upd = true; }
  try { store.db.exec('DELETE FROM actions WHERE id = 1'); } catch { del = true; }
  ok(upd && del, 'the action log refuses updates and deletes');
}

console.log('the real phase-1 stubs, over HTTP');
{
  const stubbed = createApp({ ...base(), origins: [ORIGIN] }); // no providers passed: the env-driven stubs
  await new Promise((r) => stubbed.server.listen(0, '127.0.0.1', r));
  const r = await fetch(`http://127.0.0.1:${stubbed.server.address().port}/v1/screen/bphotosx/stub-1`, { method: 'POST', headers: { authorization: `Service ${TOK.bphotosx}`, 'content-type': 'image/png' }, body: patternPng(128, 96, { fx: 6 }) });
  const j = await r.json();
  ok(r.status === 409 && j.screened === false && j.why === 'hash_match_not_configured', `nothing can be screened until PhotoDNA and a classifier are plugged in (${j.why})`);
  stubbed.server.close();
}

stop();
console.log(failures ? `\n${failures} FAILED` : '\nall e2e tests passed');
process.exit(failures ? 1 : 0);
