// Entry point: read env, start the bSafety API. All behaviour is in app.js; see README.md for every variable.
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { createApp } from './app.js';

const env = process.env;
const PROD = env.NODE_ENV === 'production';
const PORT = Number(env.PORT || 8790);
const HOST = env.HOST || '127.0.0.1';
const DATA = env.DATA_DIR || join(process.cwd(), 'data');
const list = (s) => (s || '').split(',').map((x) => x.trim()).filter(Boolean);

// The review page's own origin(s): reviewer sign-in is accepted only from these.
const origins = list(env.REVIEW_ORIGINS || (PROD ? '' : `http://127.0.0.1:${PORT},http://localhost:${PORT}`));
if (PROD && !origins.length) throw new Error('REVIEW_ORIGINS is required in production.');

function secret(name, why) {
  let v = env[name] || '';
  if (v.length < 32) {
    if (PROD) throw new Error(`${name} (32+ chars) is required in production.`);
    v = randomBytes(32).toString('hex');
    console.warn(`[bsafety] no ${name}: using a random one, so ${why} until this process restarts.`);
  }
  return v;
}
const sessionSecret = secret('SESSION_SECRET', 'reviewer sign-ins last only');
const ipSalt = secret('IP_HASH_SALT', 'per-IP report limits reset');

// REVIEWER_KEYS: identity keys (66 hex) of the named human reviewers. Nobody else can use the queue.
const reviewerKeys = list(env.REVIEWER_KEYS).map((k) => k.toLowerCase());
for (const k of reviewerKeys) if (!/^0[23][0-9a-f]{64}$/.test(k)) throw new Error(`REVIEWER_KEYS: ${k.slice(0, 12)}… is not an identity key.`);
if (!reviewerKeys.length) console.warn('[bsafety] REVIEWER_KEYS is empty: nobody can use the review queue.');

// SERVICE_TOKENS: "bphotosx:<token>,bdrivex:<token>,bmarketx:<token>" for the marketplaces' own servers.
const serviceTokens = new Map();
for (const pair of list(env.SERVICE_TOKENS)) {
  const i = pair.indexOf(':');
  const svc = pair.slice(0, i), tok = pair.slice(i + 1);
  if (!['bphotosx', 'bdrivex', 'bmarketx'].includes(svc)) throw new Error(`SERVICE_TOKENS: unknown service ${svc}.`);
  if (tok.length < 32) throw new Error(`SERVICE_TOKENS: the ${svc} token must be 32+ characters.`);
  serviceTokens.set(tok, svc);
}

// REVIEW_REF_TEMPLATES: "bphotosx=https://bphotosx.com/review-preview/{id},..." used when an item has no ref of its own.
const refTemplates = Object.fromEntries(list(env.REVIEW_REF_TEMPLATES).map((p) => [p.slice(0, p.indexOf('=')), p.slice(p.indexOf('=') + 1)]));

mkdirSync(DATA, { recursive: true });
const { server } = createApp({
  prod: PROD,
  dbFile: join(DATA, 'bsafety.db'),
  origins,
  sessionSecret,
  ipSalt,
  reviewerKeys,
  serviceTokens,
  trustProxy: env.TRUST_PROXY === '1',
  webhookUrl: env.WEBHOOK_URL || '',
  webhookSecret: env.WEBHOOK_SECRET || '',
  refSecret: env.REF_SIGNING_SECRET || '',
  refTemplates,
  limits: {
    ipPerHour: Number(env.REPORT_LIMIT_IP_PER_HOUR || 10),
    itemPerHour: Number(env.REPORT_LIMIT_ITEM_PER_HOUR || 20),
  },
  dhashMaxDistance: Number(env.DHASH_MAX_DISTANCE || 10),
  screenMaxBytes: Number(env.SCREEN_MAX_BYTES || 40 * 2 ** 20),
});
server.listen(PORT, HOST, () => console.log(`[bsafety] api on http://${HOST}:${PORT} · data ${DATA} · reviewers ${reviewerKeys.length} · services ${[...serviceTokens.values()].join(' ') || 'none'} · review page ${origins[0] || '-'}/review`));
