// Alerts to a human when a serious report arrives (§8.2 rows 1-3, hash matches, suspected CSAM from the classifier).
// Phase 1: a log line, plus a POST to WEBHOOK_URL when set. Phase 2: email / push to the named reviewers.
//
// The payload is deliberately minimal: { caseId, category, dueBy, service, at }. Never the image, never a
// reference to it, never the reporter's free text or contact, never the item id (the reviewer opens the case).
import { createHmac } from 'node:crypto';

export function createNotifier({ webhookUrl = '', webhookSecret = '', log = console, fetchImpl = globalThis.fetch } = {}) {
  return async function notify({ caseId, category, dueBy, service }) {
    const payload = { caseId, category, dueBy: new Date(dueBy).toISOString(), service, at: new Date().toISOString() };
    log.warn(`[bsafety] ALERT ${category} case ${caseId} (${service}) due by ${payload.dueBy}`);
    if (!webhookUrl) return { sent: false };
    const body = JSON.stringify(payload);
    const headers = { 'content-type': 'application/json' };
    if (webhookSecret) headers['x-bsafety-signature'] = createHmac('sha256', webhookSecret).update(body).digest('hex');
    try {
      const r = await fetchImpl(webhookUrl, { method: 'POST', headers, body, signal: AbortSignal.timeout(5000) });
      if (!r.ok) log.error(`[bsafety] alert webhook answered ${r.status} for case ${caseId}`);
      return { sent: r.ok };
    } catch (e) {
      log.error(`[bsafety] alert webhook failed for case ${caseId}: ${e.message}`);
      return { sent: false };
    }
  };
}
