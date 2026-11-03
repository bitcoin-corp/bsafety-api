// Screening before display (§7). Two pluggable providers, both required:
//
//   hashMatch(image) -> { status: 'clear' | 'match' | 'not_configured' | 'error', provider, detail? }
//     Known-image matching. Phase 2: PhotoDNA (Microsoft), key in PHOTODNA_KEY (server env only).
//   classify(image)  -> { status: 'clear' | 'flag' | 'not_configured' | 'error', provider, labels?: { nudity, sexual,
//                         possibleMinor, violence, childMainSubject } }
//     New material, nudity and apparent age. Phase 2: the vendor RB contracts (with a DPA), key in CLASSIFIER_KEY.
//
// FAIL CLOSED: an item is "screened" only when both providers are configured and both return 'clear'. Anything else
// (not configured, error, timeout, flag, match) leaves it unscreened, and an unscreened item is never listable.
//
// Plugging a real provider in: write an object with the same shape (name, configured(), check(buf)) and return it
// from hashMatchProvider() / classifierProvider() below when its env key is present. Keys only ever come from env.
// The provider sees the plaintext image over TLS; nothing here stores it. Until then the stubs below are used even
// if a key is set, so setting PHOTODNA_KEY alone can never open listings.

const notConfigured = (name) => ({
  name,
  configured: () => false,
  async check() { return { status: 'not_configured', provider: name }; },
});

export function hashMatchProvider(env = process.env) {
  // Phase 2: if (env.PHOTODNA_KEY) return photoDnaProvider({ key: env.PHOTODNA_KEY, endpoint: env.PHOTODNA_ENDPOINT });
  //   photoDnaProvider.check(buf) posts the image to the PhotoDNA Match API and maps IsMatch -> 'match', else 'clear';
  //   any HTTP or parse failure -> 'error'. Never log the image or the response body.
  void env;
  return notConfigured('photodna');
}

export function classifierProvider(env = process.env) {
  // Phase 2: if (env.CLASSIFIER_KEY) return vendorProvider({ key: env.CLASSIFIER_KEY, endpoint: env.CLASSIFIER_ENDPOINT });
  //   map the vendor's scores to labels { nudity, sexual, possibleMinor, violence, childMainSubject } with thresholds
  //   from env, and return 'flag' when any label is set, else 'clear'.
  void env;
  return notConfigured('classifier');
}

const TIMEOUT_MS = 20_000;
async function run(provider, buf) {
  if (!provider.configured()) return { status: 'not_configured', provider: provider.name };
  try {
    const r = await Promise.race([provider.check(buf), new Promise((_, no) => setTimeout(() => no(new Error('timeout')), TIMEOUT_MS).unref())]);
    if (!r || typeof r.status !== 'string') return { status: 'error', provider: provider.name };
    return { ...r, provider: provider.name };
  } catch { return { status: 'error', provider: provider.name }; }
}

/**
 * Run both providers. Returns { outcome, hash, classify } where outcome is one of:
 *   'screened'      both configured and clear
 *   'blocked'       known-hash match (never shown to anyone, quarantined, §9.3)
 *   'suspected_csam' classifier: possible minor with nudity or sexual content (§7.2.3), priority review
 *   'flagged'       other classifier flags, human review
 *   'unscreened'    a provider is not configured or failed (fail closed)
 * The hash match runs first; on a match the classifier is not called (nothing more needs to see the image).
 */
export async function screen(buf, { hashMatch = hashMatchProvider(), classifier = classifierProvider() } = {}) {
  const hash = await run(hashMatch, buf);
  if (hash.status === 'match') return { outcome: 'blocked', hash, classify: null };
  const cls = await run(classifier, buf);
  if (hash.status !== 'clear') return { outcome: 'unscreened', hash, classify: cls, why: `hash_match_${hash.status}` };
  if (cls.status === 'flag') {
    const l = cls.labels || {};
    return { outcome: l.possibleMinor && (l.nudity || l.sexual) ? 'suspected_csam' : 'flagged', hash, classify: cls };
  }
  if (cls.status !== 'clear') return { outcome: 'unscreened', hash, classify: cls, why: `classifier_${cls.status}` };
  return { outcome: 'screened', hash, classify: cls };
}
