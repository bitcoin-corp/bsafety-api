// Unit tests: the PNG codec and dHash, the §8.2 rules, screening failing closed, the alert payload.
//   node test/unit.mjs
import { decodePng, dHash, decodeImage, degenerate, encodePng, hamming, sha256 } from '../src/image.js';
import { PRIORITY, REASONS, acknowledgement, addWorkingDays, dueBy, triage } from '../src/policy.js';
import { classifierProvider, hashMatchProvider, screen } from '../src/screening.js';
import { createNotifier } from '../src/notify.js';
import { patternEditedPng, patternJpeg, patternPng, patternRgba, solidPng } from './fixtures.mjs';

let failures = 0;
const ok = (cond, what) => { console.log(`${cond ? '  ok ' : '  FAIL'} ${what}`); if (!cond) failures++; };
const H = 3600_000;

console.log('png codec');
{
  const px = patternRgba(37, 23);
  const back = decodePng(encodePng(37, 23, px));
  ok(back.width === 37 && back.height === 23 && Buffer.from(back.data).equals(Buffer.from(px)), 'RGBA PNG round-trips pixel for pixel');
  const solid = decodeImage(solidPng(10, 10, [12, 200, 99]));
  ok(solid.data[0] === 12 && solid.data[1] === 200 && solid.data[2] === 99 && solid.data[3] === 255, 'solid placeholder decodes to its colour');
  let threw = false;
  try { decodeImage(Buffer.from('GIF89a not supported')); } catch { threw = true; }
  ok(threw, 'unsupported formats are refused, not guessed');
}

console.log('dHash');
{
  const base = dHash(patternPng(256, 192));
  ok(/^[0-9a-f]{16}$/.test(base) && !degenerate(base), `pattern hashes to ${base}`);
  ok(hamming(base, dHash(patternPng(200, 150))) <= 10, 'a resized copy is a near-duplicate');
  ok(hamming(base, dHash(patternPng(256, 192, { bright: 12 }))) <= 10, 'a brightened copy is a near-duplicate');
  ok(hamming(base, dHash(patternEditedPng(256, 192))) <= 10, 'a lightly edited copy is a near-duplicate');
  ok(hamming(base, dHash(patternJpeg(256, 192, {}, 70))) <= 10, 'a JPEG re-encode of the PNG is a near-duplicate');
  ok(hamming(base, dHash(patternPng(256, 192, { fx: 5, fy: 3, phase: 0.3 }))) > 10, 'a different pattern is not');
  ok(hamming(base, dHash(patternPng(256, 192, { fx: 2, fy: 4, phase: 0.6 }))) > 10, 'nor is another');
  ok(degenerate(dHash(solidPng(64, 64, [200, 30, 30]))), 'a flat colour gives a degenerate hash (never used for perceptual matching)');
  ok(sha256(Buffer.from('abc')) === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'sha256 is sha256');
}

console.log('§8.2 rules');
{
  const t = Date.UTC(2026, 10, 3, 10, 0); // Tue 3 Nov 2026 10:00 UTC
  const hiddenAtOnce = Object.keys(REASONS).filter((r) => triage({ kind: 'report', category: r, service: 'bphotosx', t }).hides);
  ok(JSON.stringify(hiddenAtOnce.sort()) === JSON.stringify(['child_abuse', 'intimate_image', 'secretly_taken', 'terrorism']), `bPhotosX hides at once exactly: ${hiddenAtOnce.join(', ')}`);
  ok(Object.keys(REASONS).every((r) => triage({ kind: 'report', category: r, service: 'bdrivex', t }).hides), 'bDriveX switches off on every report (its pack §7.4)');
  ok(triage({ kind: 'report', category: 'nudity_sexual', service: 'bphotosx', alreadyFlagged: true, t }).hides, 'nudity hides when the item is already flagged');
  ok(!triage({ kind: 'report', category: 'copyright', service: 'bphotosx', alreadyFlagged: true, t }).hides, 'a plain copyright report never hides (a complete notice does)');
  ok(triage({ kind: 'report', category: 'child_abuse', service: 'bphotosx', t }).dueBy === t + 4 * H, 'child abuse: decide within 4 hours');
  ok(triage({ kind: 'report', category: 'intimate_image', service: 'bphotosx', t }).dueBy === t + 24 * H, 'intimate image: 24 hours');
  ok(triage({ kind: 'copyright_notice', category: 'copyright', service: 'bphotosx', t }).dueBy === Date.UTC(2026, 10, 5, 10, 0), 'copyright notice: 2 working days (Tue -> Thu)');
  ok(triage({ kind: 'privacy_request', category: 'privacy', service: 'bphotosx', t }).dueBy === Date.UTC(2026, 10, 10, 10, 0), 'privacy request: 5 working days (Tue -> next Tue)');
  ok(triage({ kind: 'complaint', category: 'complaint', service: 'bphotosx', t }).dueBy === t + 7 * 24 * H, 'complaint: 7 days');
  ok(addWorkingDays(Date.UTC(2026, 10, 6, 9), 1) === Date.UTC(2026, 10, 9, 9), 'Friday + 1 working day = Monday');
  ok(addWorkingDays(Date.UTC(2026, 10, 7, 9), 2) === Date.UTC(2026, 10, 10, 9), 'Saturday + 2 working days = Tuesday');
  const pi = triage({ kind: 'privacy_request', service: 'bphotosx', flags: { intimate: true, mayBeChild: true }, t });
  ok(pi.hides && pi.priority === 1 && pi.dueBy === t + 4 * H, 'an intimate privacy request about a possible child is hidden and treated as priority 1');
  ok(triage({ kind: 'hash_match', service: 'bphotosx', t }).priority === 1, 'hash matches are priority 1');
  ok(dueBy(t, PRIORITY.terrorism.due) === t + 24 * H, 'terrorism: 24 hours');
  const ack = acknowledgement({ kind: 'report', category: 'intimate_image', caseId: 'cs_x', service: 'bphotosx' });
  ok(/StopNCII/.test(ack) && /Revenge Porn Helpline/.test(ack) && /hidden/.test(ack), 'intimate-image acknowledgement points to the helpline and StopNCII');
}

console.log('screening fails closed');
{
  const img = patternPng(64, 48);
  const stub = await screen(img);
  ok(stub.outcome === 'unscreened' && stub.hash.status === 'not_configured' && stub.classify.status === 'not_configured', 'phase 1 stubs: not configured -> unscreened');
  ok(!hashMatchProvider({ PHOTODNA_KEY: 'x'.repeat(40) }).configured() && !classifierProvider({ CLASSIFIER_KEY: 'x'.repeat(40) }).configured(), 'setting a key alone does not configure a stub');
  const fake = (name, status, labels) => ({ name, configured: () => status !== 'not_configured', check: async () => ({ status, labels }) });
  const boom = { name: 'boom', configured: () => true, check: async () => { throw new Error('vendor down'); } };
  const run = (h, c) => screen(img, { hashMatch: h, classifier: c });
  ok((await run(fake('h', 'clear'), fake('c', 'clear'))).outcome === 'screened', 'both configured and clear -> screened');
  ok((await run(fake('h', 'clear'), fake('c', 'not_configured'))).outcome === 'unscreened', 'classifier missing -> unscreened');
  ok((await run(fake('h', 'not_configured'), fake('c', 'clear'))).outcome === 'unscreened', 'hash match missing -> unscreened');
  ok((await run(boom, fake('c', 'clear'))).outcome === 'unscreened', 'hash match throws -> unscreened');
  ok((await run(fake('h', 'clear'), boom)).outcome === 'unscreened', 'classifier throws -> unscreened');
  ok((await run(fake('h', 'clear'), fake('c', 'error'))).outcome === 'unscreened', 'classifier error -> unscreened');
  ok((await run(fake('h', 'weird'), fake('c', 'clear'))).outcome === 'unscreened', 'an unknown answer -> unscreened');
  let classifierCalled = false;
  const spy = { name: 'spy', configured: () => true, check: async () => { classifierCalled = true; return { status: 'clear' }; } };
  ok((await run(fake('h', 'match'), spy)).outcome === 'blocked' && !classifierCalled, 'known-hash match -> blocked, and the image goes no further');
  ok((await run(fake('h', 'clear'), fake('c', 'flag', { possibleMinor: true, nudity: true }))).outcome === 'suspected_csam', 'possible minor + nudity -> suspected CSAM');
  ok((await run(fake('h', 'clear'), fake('c', 'flag', { violence: true }))).outcome === 'flagged', 'other flags -> human review');
}

console.log('alert payload');
{
  const sent = [];
  const log = { warn() {}, error() {} };
  const notify = createNotifier({ webhookUrl: 'https://hooks.example/x', webhookSecret: 's'.repeat(32), log, fetchImpl: async (u, o) => { sent.push(o); return { ok: true }; } });
  await notify({ caseId: 'cs_1', category: 'child_abuse', dueBy: Date.now(), service: 'bphotosx', details: 'secret text', image: 'data' });
  const body = JSON.parse(sent[0].body);
  ok(JSON.stringify(Object.keys(body).sort()) === JSON.stringify(['at', 'caseId', 'category', 'dueBy', 'service']), `payload carries only ${Object.keys(body).join(', ')}`);
  ok(/^[0-9a-f]{64}$/.test(sent[0].headers['x-bsafety-signature']), 'signed with WEBHOOK_SECRET when set');
  const none = await createNotifier({ log })({ caseId: 'cs_2', category: 'terrorism', dueBy: Date.now(), service: 'bdrivex' });
  ok(none.sent === false, 'no WEBHOOK_URL: log only');
}

console.log(failures ? `\n${failures} FAILED` : '\nall unit tests passed');
process.exit(failures ? 1 : 0);
