# bSafety API

The shared trust-and-safety service for **bPhotosX**, **bDriveX** and **bMarketX**. Phase 1 builds everything that needs no outside vendor, following the bPhotosX online safety pack (`bitcoin-corp/legal/BPHOTOSX-ONLINE-SAFETY-PACK-2026-11-03.md`, stage (ii) and §§7–10, 12.4, 12.6) and the bDriveX pack's reporting and takedown sections.

What it does:

- **Reports** from anyone, signed in or not, anonymous allowed (§8.1). Rate-limited per IP and per item. The IP is stored only as a salted HMAC.
- **Auto-hide** exactly as §8.2: child sexual abuse or a child at risk, intimate image without consent, secretly taken photo and terrorism are hidden at once. bDriveX switches off on every report (its pack §7.4).
- **Hidden check**: marketplaces ask "is this item hidden?" before serving it (single or batch of 500).
- **Review queue** for named human reviewers (bWalletX sign-in, keys in `REVIEWER_KEYS`), in §8.2 order with a due-by time per case, and one-click actions: approve, reject (policy), reject and report, restore, ban seller (plus "need more information" for complaints and appeals).
- **Append-only action log**: who, when, what, why. SQLite triggers refuse updates and deletes.
- **Hash denylist**: exact sha256 plus a 64-bit dHash computed here from the image. An item rejected for illegality is added automatically, so nobody can list it, or a near-duplicate, again.
- **Copyright notices and counter-notices** (§12.4), **"I'm in this photo"** requests (§12.6), **complaints and appeals** (§10), each with an automatic acknowledgement (stored now, emailed in phase 2).
- **Alerts** for serious cases: a log line, plus a POST to `WEBHOOK_URL` with `{ caseId, category, dueBy, service, at }` only.
- **Screening gate** with pluggable providers, `hashMatch(image)` and `classify(image)`. Phase 1 stubs answer "not configured", so nothing can be marked screened. It fails closed.
- **Hash binding** (§7.2): the screened sha256 is stored, and `verify(itemId, sha256)` tells the buyer's client whether the opened photo is the one that was screened.
- **Reviewer page** at `/review`: lists cases, takes the actions, opens image references behind a blur.

What it never does: store, return, log or describe an image. Screening reads the bytes, hashes them, hands them to the configured providers and drops them. Reviewers get **references** (a URL to a server-made preview held by the marketplace), which the page opens only on request, blurred, with "Less blur" and "Show" (each logged). Known-hash matches are stored as "hash match, quarantined", with no reference at all. In development every reference is replaced by a generated solid-colour placeholder PNG, so no real image can ever appear on a dev machine. Tests use synthetic solid-colour and pattern images only.

## Run

```bash
pnpm install
pnpm dev            # http://127.0.0.1:8790, review page at /review
pnpm test           # unit + end-to-end (in-process server on a temp data dir)
```

Node 22.13+ (it uses `node:sqlite`, like bdrivex-api). Dependencies: `@bwalletx/connect` and `@bsv/sdk` (reviewer sign-in, same versions as bdrivex-api) and `jpeg-js` (pure-JS JPEG decoding for the dHash; PNG decoding is built in on `node:zlib`).

## Callers

| Caller | How it authenticates | CORS |
|---|---|---|
| **Public**: report buttons, report pages, the hidden check, the buyer's verify | none | `*` |
| **Service**: a marketplace's own server | `Authorization: Service <token>` (one token per marketplace in `SERVICE_TOKENS`; a token only works for its own service) | none (server-to-server) |
| **Reviewer**: a named person | `Authorization: Bearer <session>` from the bWalletX challenge/verify flow, same as bdrivex-api; the identity key must be in `REVIEWER_KEYS`, checked on every request | the review page's origin only |

## Endpoints

### Public

| Method and path | Body | Answer |
|---|---|---|
| `GET /health` | | `{ ok }` |
| `GET /v1/reasons` | | the §8.1 reasons `{ key, label }` and the services |
| `POST /v1/reports` | `{ service, itemId, reason, details?, contact? }` | `201 { caseId, acknowledgement, hidden, dueBy }`; the same IP, item and reason within 24 h returns the first case (`200, duplicate: true`) |
| `POST /v1/copyright/notice` | `{ service, itemId, name, contact, work, infringement, goodFaith: true, accurate: true, rightsHolder: 'owner'\|'agent' }` | `201`; an incomplete notice is `400 { missing: [...] }` and hides nothing |
| `POST /v1/privacy-requests` | `{ service, itemId, inPhoto: true, contact, details?, intimate?, secretlyTaken?, mayBeChild? }` | `201`; hidden at once if any flag is set |
| `POST /v1/complaints` | `{ service, kind: 'complaint'\|'appeal', details, contact, itemId?, caseId? }` (an appeal needs `caseId`) | `201` |
| `GET /v1/hidden/:service/:itemId` | | `{ hidden }` |
| `POST /v1/hidden` | `{ service, ids: [...] }` (max 500) | `{ hidden: { id: bool } }` |
| `POST /v1/verify` | `{ service, itemId, sha256 }` | `{ ok: true }`, or `{ ok: false, reason: 'not_screened'\|'hidden'\|'mismatch' }`. A mismatch opens a case automatically (one per item) |

Reasons (`reason`): `child_abuse`, `intimate_image`, `nudity_sexual`, `secretly_taken`, `harassment`, `violence_hate`, `terrorism`, `fraud_scam`, `copyright`, `privacy`, `other_illegal`. The pack's single line "violence, cruelty, terrorism or hate" is offered as two choices, because §8.2 hides terrorism at once but not the rest. bDriveX's "malware" sits under `fraud_scam`.

Report limits: `REPORT_LIMIT_IP_PER_HOUR` (default 10, counted on the salted IP hash in the database, so they survive restarts) and `REPORT_LIMIT_ITEM_PER_HOUR` (default 20), plus an in-memory burst limit. Over a limit: `429` with `retry-after`.

### Service (marketplace servers)

| Method and path | Body | Answer |
|---|---|---|
| `PUT /v1/items/:service/:itemId` | `{ seller?, ref? }`: the seller's identity key, and the URL where a reviewer can open the server-made preview | `200` |
| `GET /v1/items/:service/:itemId` | | `{ status, screened, hidden, listable, screenedSha256 }` |
| `POST /v1/screen/:service/:itemId` | the image bytes (`image/png` or `image/jpeg`) | `200 { screened: true, sha256, dhash }` **only** when screened; otherwise `409 { screened: false, status: 'unscreened'\|'in_review'\|'blocked', why, message }`. A client that only checks `res.ok` fails closed |
| `POST /v1/denylist/check` | the image bytes, or JSON `{ sha256?, dhash? }` | `{ denylisted, match: 'exact'\|'perceptual'\|null, distance }` |
| `POST /v1/copyright/counter-notice` | `{ noticeCaseId, sellerKey, name, contact, why, agreeContact: true }` (forwarded for a signed-in seller; must match the item's seller) | `201 { restoreEligibleAt }` (10 working days) |
| `POST /v1/reports` | as above, with the service token and `X-Reporter-IP: <the reporter's IP>` | as above; the forwarded IP is hashed. Without a service token the header is ignored |

The denylist check is deliberately not public: a public "is this hash known?" endpoint would let someone test material against it.

### Reviewer

| Method and path | Body | Answer |
|---|---|---|
| `POST /v1/auth/challenge` | `{ identityKey }` | a challenge to sign in bWalletX (from a `REVIEW_ORIGINS` origin only) |
| `POST /v1/auth/verify` | `{ identityKey, nonce, signature }` | `{ token, identityKey, expiresAt }` (12 h), or `403` if the key isn't in `REVIEWER_KEYS` |
| `POST /v1/auth/signout` | | `204` |
| `GET /v1/review/cases?status=open\|quarantined\|closed` | | cases in §8.2 order: priority, then due-by. Each has `dueBy`, `overdue`, `viewable`, `ref` (null when not viewable) |
| `GET /v1/review/cases/:id` | | the case, the item, the seller (banned? upheld copyright notices), other cases on the item, the case's log, which authority to report to. Opening it is logged |
| `POST /v1/review/cases/:id/actions` | `{ action, reason, authorityRef?, sameReviewerWhy?, rightsHolderAgreed? }` | the updated case |
| `POST /v1/review/cases/:id/image-shown` | `{ level: 'partial'\|'clear' }` | `204`; the page calls this when a reviewer unblurs, so every viewing is in the log |
| `GET /v1/review/log?limit=` | | the most recent actions |

### Priorities and deadlines (§8.2)

| P | What | Hidden at once | Decide within |
|---|---|---|---|
| 1 | Child sexual abuse or a child at risk; known-hash matches; classifier "possible minor + nudity" | yes | 4 hours |
| 2 | Intimate image without consent | yes | 24 hours |
| 3 | Secretly taken photo; terrorism | yes | 24 hours |
| 4 | Other illegal content, nudity, harassment, violence/hate, fraud; hash mismatches; other classifier flags | only if someone else has already flagged the item (bDriveX: always) | 24 hours |
| 5 | Copyright (a complete notice hides; a plain report doesn't) | complete notice only | 2 working days |
| 6 | "A photo of me" | if intimate, secretly taken or may be a child | 5 working days |
| 7 | Complaints and appeals | no | 7 days (14 after "need more information") |

One deliberate escalation beyond the table: an "I'm in this photo" request flagged intimate is triaged as P2 (24 h), and intimate plus "may be a child" as P1 (4 h), rather than waiting 5 working days. Working days skip weekends, not yet UK bank holidays. "4 hours" is wall-clock until staffed hours are set (phase 2).

### Actions

| Action | Cases | Effect |
|---|---|---|
| `approve` | reports, notices, privacy requests, screening flags, mismatches | report not upheld: case closed, item visible again unless another open case still hides it. On a screening flag, the item becomes screened (the only other way, since a flag exists only when both providers were configured and the hash match was clear) |
| `approve` | complaint / appeal / counter-notice | complaint upheld / appeal upheld (restores the item) / counter-notice accepted (restores; refused before the 10 working days unless `rightsHolderAgreed`) |
| `reject` | as above | policy breach: item removed, not denylisted. On a copyright notice, counts toward repeat infringement (2 upheld: end selling; 3: end the account, §12.4.4), shown in the log |
| `reject_and_report` | as above, and hash matches | illegal: item removed, its sha256 and dHash added to the denylist, the authority to report to recorded (NCA/IWF, Counter Terrorism Policing), with `authorityRef` once the reviewer has one |
| `ban_seller` | any case with a known seller (also after it's decided) | seller's identity key banned; every item of theirs, on every marketplace, is hidden and can't be listed |
| `restore` | any decided case except hash matches | item visible again; any denylist entry this item got from a reviewer is lifted (logged) |
| `extend` | open complaint or appeal | due-by moves to 14 days; the complainant is told (outbox) |

Every action needs a reason. Appeals are decided by someone other than the original reviewer; if that's impossible, the same reviewer must give `sameReviewerWhy`, which is logged (§10). Hash-match cases accept only `reject_and_report` and `ban_seller`.

## How the marketplaces integrate

1. **Register items.** When an item is created or listed, the marketplace server calls `PUT /v1/items/:service/:itemId` with the seller's identity key and a `ref`: a URL on the marketplace that serves the **server-made, reduced preview** to reviewers only. With `REF_SIGNING_SECRET` set, references are handed to reviewers as short-lived signed URLs (`case`, `rv`, `exp`, `sig` = HMAC-SHA256 of the URL without `sig`); the marketplace checks the signature and `exp` before serving the preview.
2. **Hidden check before serving.** Before serving an item, preview, listing, profile image or file (including bDriveX link pages and blobs), call `GET /v1/hidden/:service/:itemId`, or `POST /v1/hidden` for a page of items. If `hidden`, don't serve it. Fail closed: if bSafety is unreachable, don't serve public listings (private libraries are unaffected).
3. **Screening before listing (bPhotosX, bMarketX images).** When a seller chooses "List", the seller's browser sends the plaintext over TLS to the marketplace server, which posts it to `POST /v1/screen/:service/:itemId`. Only a `200 { screened: true }` lets the listing go public. Check `GET /v1/items/...` → `listable` before showing any listing. Today nothing can be screened: that is the gate working.
4. **Denylist check on upload.** Where the marketplace can see the plaintext (bPhotosX listings, bMarketX images), call `POST /v1/denylist/check` with the image, or with `{ sha256 }` alone where only a hash is available. bDriveX free files are ciphertext the server can't read (bDriveX pack §5.2), so the check only applies to paid or "anyone with the link" images once the client-side design in that pack is decided.
5. **The report button.** Every public photo, listing, seller page, receipt and share page gets "Report", which posts to `POST /v1/reports` (directly from the browser, CORS `*`), or via the marketplace server with `X-Reporter-IP`. bDriveX's existing `POST /v1/s/:id/report` should forward to bSafety with `service: 'bdrivex'` and the link id. The report page (`bphotosx.com/report`, `bdrivex.com/report`) also offers the copyright notice, "I'm in this photo" and complaint/appeal forms, posting to the endpoints above.
6. **Verify on purchase.** After the buyer's client opens the purchased full-resolution photo, it hashes it (sha256) and calls `POST /v1/verify`. Show the photo only on `{ ok: true }`. On a mismatch bSafety opens a case automatically.

## Plugging in PhotoDNA and a classifier (phase 2)

`src/screening.js` holds both providers. Each is an object `{ name, configured(), check(buf) }`:

- **Hash match (PhotoDNA)**: when `PHOTODNA_KEY` is set, return a provider whose `check` posts the image to the PhotoDNA Match API and maps a match to `{ status: 'match' }`, otherwise `{ status: 'clear' }`; any failure is `'error'`.
- **Classifier**: when `CLASSIFIER_KEY` is set, return a provider that maps the vendor's scores to `labels: { nudity, sexual, possibleMinor, violence, childMainSubject }` and returns `'flag'` if any is set, otherwise `'clear'`.

Keys only ever come from env, on the server. Until the real providers are written, the stubs are used even if a key is set, so a key alone can't open listings. Whatever the providers say, an item is screened only when both are configured and both are clear; errors, timeouts (20 s), unknown answers and flags all leave it unscreened. Never log the image or the vendor's response body.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `NODE_ENV` | | `production` makes the secrets and `REVIEW_ORIGINS` mandatory, turns off placeholders, and returns real (signed) references |
| `PORT`, `HOST` | `8790`, `127.0.0.1` | |
| `DATA_DIR` | `./data` | the SQLite file `bsafety.db` |
| `SESSION_SECRET` | random in dev | 32+ chars; signs reviewer sessions |
| `IP_HASH_SALT` | random in dev | 32+ chars; the HMAC key for reporter IPs |
| `REVIEW_ORIGINS` | the dev address | origins the review page is served from; sign-in is accepted only from these |
| `REVIEWER_KEYS` | | comma-separated identity keys of the named reviewers |
| `SERVICE_TOKENS` | | `bphotosx:<token>,bdrivex:<token>,bmarketx:<token>`, each 32+ chars |
| `TRUST_PROXY` | `0` | `1` to take the client IP from `X-Forwarded-For` behind your own proxy |
| `WEBHOOK_URL`, `WEBHOOK_SECRET` | | alert webhook, and an optional HMAC signature (`x-bsafety-signature`) |
| `REF_SIGNING_SECRET` | | signs reviewer references in production |
| `REVIEW_REF_TEMPLATES` | | `bphotosx=https://bphotosx.com/review-preview/{id},...` when an item has no `ref` |
| `REPORT_LIMIT_IP_PER_HOUR`, `REPORT_LIMIT_ITEM_PER_HOUR` | `10`, `20` | |
| `DHASH_MAX_DISTANCE` | `10` | perceptual match threshold (bits of 64) |
| `SCREEN_MAX_BYTES` | 40 MB | largest image accepted for screening or checking |
| `PHOTODNA_KEY`, `PHOTODNA_ENDPOINT`, `CLASSIFIER_KEY`, `CLASSIFIER_ENDPOINT` | | phase 2; not read yet |

## Design notes

- **Storage** is SQLite via `node:sqlite`, as bdrivex-api does. No Postgres migration, nothing touches the Hetzner database.
- **dHash**: greyscale, area-average to 9×8, one bit per horizontal neighbour pair. Re-encodes (PNG↔JPEG), resizes, brightness changes and small edits stay within a few bits. A hash with almost every bit the same (a flat colour, a plain gradient) is "degenerate" and never used for perceptual matching, because it would match every other flat image; sha256 still applies. The perceptual scan is a linear Hamming search in memory, fine for a phase-1 list; a BK-tree or multi-index hashing can replace it if the list grows.
- **Hidden** is computed, not stored: an item is hidden if it was removed, is blocked by a hash match, belongs to a banned seller, or has an open case that hides it. Approving one report can't unhide an item another open case is still holding.
- **The action log** includes system actions (case opened, auto-hide, acknowledgement, alert, screening outcomes) as well as reviewers' decisions, case views and unblurs.
- **Untrusted text**: the reviewer page renders everything with `textContent`, under a strict CSP (`script-src 'self'`, no inline script or style). References come only from the marketplace's server (service token), never from a reporter, so a stranger can't put an image in front of a reviewer.

## Phase 2 / needs the owner

- **PhotoDNA key.** The application was declined twice (16 and 21 Oct) because it came from a gmail address. Reapply as the company from support@bwalletx.com. Then write the PhotoDNA provider in `src/screening.js`.
- **Classifier vendor and DPA.** Choose and contract the nudity/apparent-age classifier, with a data processing agreement and international-transfer cover. Then write its provider.
- **Report mailbox and email sending.** Create `reports@bphotosx.com` (placeholder) and `reports@bdrivex.com`, decide who reads them, and add an email provider to send the `outbox` (acknowledgements, outcomes, counter-notices passed to rights holders, telling sellers about notices).
- **Named human reviewers and hours.** Who reviews, in what staffed hours, and the backup (§2, §7.4). Put their keys in `REVIEWER_KEYS`. Then model staffed hours so a P1 report outside them is due "first thing next staffed day", and add UK bank holidays to working days. Reviewer wellbeing limits (time spent) are not enforced yet.
- **NCA, IWF and Counter Terrorism Policing reporting steps** (§9.3–9.5), and counsel's view on the NCA industry route, OSA s.66, PhotoDNA's reporting terms and evidence preservation. Phase 1 records the authority and the reference the reviewer enters; it doesn't submit anything.
- **Quarantine store for matched images** (§9.3.2): an encrypted, access-logged store, once counsel confirms the lawful basis and retention (default 12 months). Phase 1 keeps hashes and metadata only, never the image.
- **StopNCII** hash matching for intimate image abuse: apply to integrate (Ofcom has consulted on it). IWF membership for UK hash and URL lists: cost to confirm.
- **Telling sellers and buyers** what was done, why and how to appeal (§9.2), except where it could prejudice an investigation. Needs email sending and counsel's wording.
- **Deployment**: where this runs (e.g. Hetzner beside bdrivex-api), its domain for `REVIEW_ORIGINS`, the proxy (`TRUST_PROXY=1`), and the marketplaces wired up as described above.
