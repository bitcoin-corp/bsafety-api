// The rules from the bPhotosX online safety pack (3 Nov 2026), in one place so the server, the tests and the reviewer
// page agree. Section numbers refer to bitcoin-corp/legal/BPHOTOSX-ONLINE-SAFETY-PACK-2026-11-03.md; the bDriveX pack
// (BDRIVEX-ONLINE-SAFETY-PACK-2026-11-03.md §7.4) differs only in what is switched off at once (see SERVICES).

export const SERVICES = {
  bphotosx: { label: 'bPhotosX', autoHideAll: false },
  bmarketx: { label: 'bMarketX', autoHideAll: false },
  // bDriveX pack §7.4: every report switches the link off at once (live behaviour in bdrivex-api today), including
  // other illegal content (fraud, malware, threats, extreme porn). Deadlines and priorities are the same.
  bdrivex: { label: 'bDriveX', autoHideAll: true },
};

// §8.1 reasons. The pack's "violence, cruelty, terrorism or hate" is offered as two choices, because §8.2 hides
// terrorism at once but not the rest of that line. bDriveX's "malware" sits under fraud_scam.
export const REASONS = {
  child_abuse: 'Child sexual abuse, or a child at risk',
  intimate_image: 'Intimate image shared without consent (including fakes)',
  nudity_sexual: 'Nudity or sexual content',
  secretly_taken: 'Secretly taken photo',
  harassment: 'Harassment or threats',
  violence_hate: 'Violence, cruelty or hate',
  terrorism: 'Terrorism',
  fraud_scam: 'Fraud, scam or malware',
  copyright: "Someone else's copyright",
  privacy: 'A photo of me (privacy)',
  other_illegal: 'Something else illegal',
};

// §8.2, in the table's order. Lower number = higher priority. `hide` = hidden at once, automatically.
const H = 3600_000;
export const PRIORITY = {
  child_abuse: { p: 1, hide: true, due: { hours: 4 } },
  intimate_image: { p: 2, hide: true, due: { hours: 24 } },
  secretly_taken: { p: 3, hide: true, due: { hours: 24 } },
  terrorism: { p: 3, hide: true, due: { hours: 24 } },
  nudity_sexual: { p: 4, hide: false, due: { hours: 24 } },
  harassment: { p: 4, hide: false, due: { hours: 24 } },
  violence_hate: { p: 4, hide: false, due: { hours: 24 } },
  fraud_scam: { p: 4, hide: false, due: { hours: 24 } },
  other_illegal: { p: 4, hide: false, due: { hours: 24 } },
  copyright: { p: 5, hide: false, due: { workingDays: 2 } }, // a plain report; a complete notice (below) hides
  privacy: { p: 6, hide: false, due: { workingDays: 5 } },
  complaint: { p: 7, hide: false, due: { days: 7 } },
};

// The serious categories: an alert goes to a human at once (§8.2 rows 1-3, plus hash matches).
export const SERIOUS = new Set(['child_abuse', 'intimate_image', 'secretly_taken', 'terrorism']);

// Which authority a "reject and report" goes to (§9.3-9.5). The reviewer records the reference they get back.
export const AUTHORITY = {
  child_abuse: 'NCA (and IWF where there is a reachable URL)',
  terrorism: 'Counter Terrorism Policing (gov.uk "Report terrorism online")',
  intimate_image: 'Police if asked (metadata preserved); point the reporter to the Revenge Porn Helpline and StopNCII.org',
};

export const CASE_TYPES = ['report', 'copyright_notice', 'counter_notice', 'privacy_request', 'complaint', 'appeal', 'hash_match', 'screening_flag', 'hash_mismatch'];

/** n working days (Mon-Fri, UTC) after t, same time of day. UK bank holidays are not counted yet (phase 2). */
export function addWorkingDays(t, n) {
  const d = new Date(t);
  let added = 0;
  while (added < n) {
    d.setUTCDate(d.getUTCDate() + 1);
    const wd = d.getUTCDay();
    if (wd !== 0 && wd !== 6) added++;
  }
  return d.getTime();
}

/** The due-by time for a deadline spec. Staffed hours aren't modelled yet: "4 hours" is wall-clock (phase 2). */
export function dueBy(t, due) {
  if (due.hours) return t + due.hours * H;
  if (due.days) return t + due.days * 24 * H;
  if (due.workingDays) return addWorkingDays(t, due.workingDays);
  throw new Error('bad deadline');
}

/**
 * What a new case gets: priority, due-by and whether it hides the item at once.
 * kind: 'report' | 'copyright_notice' | 'counter_notice' | 'privacy_request' | 'complaint' | 'appeal' |
 *       'hash_match' | 'screening_flag' | 'hash_mismatch'
 */
export function triage({ kind, category, service, flags = {}, alreadyFlagged = false, t }) {
  const svc = SERVICES[service];
  let rule;
  let hide = false;
  switch (kind) {
    case 'report':
      rule = PRIORITY[category];
      // §8.2 row 4: other illegal content and nudity stay up unless the item is already flagged.
      hide = rule.hide || (rule.p === 4 && alreadyFlagged) || !!svc?.autoHideAll;
      break;
    case 'copyright_notice':
      rule = PRIORITY.copyright;
      hide = true; // only complete notices are accepted, and a complete notice hides (§12.4.2)
      break;
    case 'counter_notice':
      rule = PRIORITY.copyright;
      break;
    case 'privacy_request':
      // §12.6: hide at once if intimate, secretly taken, or the person may be a child. Deliberate escalation beyond
      // the §8.2 table: those requests are triaged like the matching report category, so an intimate image of a
      // possible child is decided within 4 hours, not 5 working days.
      if (flags.intimate && flags.mayBeChild) rule = PRIORITY.child_abuse;
      else if (flags.intimate) rule = PRIORITY.intimate_image;
      else if (flags.secretlyTaken) rule = PRIORITY.secretly_taken;
      else rule = PRIORITY.privacy;
      hide = !!(flags.intimate || flags.secretlyTaken || flags.mayBeChild);
      break;
    case 'complaint':
    case 'appeal':
      rule = PRIORITY.complaint;
      break;
    case 'hash_match':
      rule = PRIORITY.child_abuse;
      hide = true;
      break;
    case 'screening_flag':
      // §7.2.3: a possible minor with any nudity or sexual content is suspected CSAM: priority review.
      rule = category === 'child_abuse' ? PRIORITY.child_abuse : PRIORITY.nudity_sexual;
      hide = true; // flagged listings never go public while in the queue (§7.4)
      break;
    case 'hash_mismatch':
      rule = PRIORITY.other_illegal;
      break;
    default:
      throw new Error(`unknown case kind ${kind}`);
  }
  return { priority: rule.p, dueBy: dueBy(t, rule.due), hides: hide };
}

const HELP_INTIMATE = ' If this is an intimate image of you, the Revenge Porn Helpline (revengepornhelpline.org.uk) can help, and StopNCII.org can stop it being shared on other sites.';

/** The automatic acknowledgement stored with each case (and, in phase 2, emailed to the contact address). */
export function acknowledgement({ kind, category, caseId, service, flags = {} }) {
  const name = SERVICES[service]?.label || 'our service';
  const ref = `Reference: ${caseId}.`;
  switch (kind) {
    case 'report': {
      const p = PRIORITY[category];
      const hidden = p.hide || SERVICES[service]?.autoHideAll;
      return [
        `Thank you. We have your report about an item on ${name}. ${ref}`,
        hidden ? 'We have hidden the item while a person reviews it.' : 'A person will review it.',
        category === 'copyright' ? 'If you own the rights, send a full copyright notice so we can take the item down.' : '',
        category === 'intimate_image' ? HELP_INTIMATE.trim() : '',
        'If you left a contact address, we will tell you what we decided.',
      ].filter(Boolean).join(' ');
    }
    case 'copyright_notice':
      return `We have your copyright notice for an item on ${name}. ${ref} The item is taken down while we check it, and we have told the seller. We aim to decide within 2 working days. The seller may send a counter-notice, which we will pass to you.`;
    case 'counter_notice':
      return `We have your counter-notice. ${ref} We will pass it to the person who sent the notice. If they don't tell us within 10 working days that they have started legal action, we may put the item back.`;
    case 'privacy_request':
      return [
        `We have your request about a photo of you on ${name}. ${ref}`,
        flags.intimate || flags.secretlyTaken || flags.mayBeChild ? 'We have hidden it while a person reviews it.' : 'A person will review it within 5 working days.',
        flags.intimate ? HELP_INTIMATE.trim() : '',
        'We will tell you and the seller what we decided.',
      ].filter(Boolean).join(' ');
    case 'complaint':
      return `We have your complaint. ${ref} We aim to reply with a decision and our reasons within 7 days. If we need more information it can take up to 14 days, and we will tell you.`;
    case 'appeal':
      return `We have your appeal. ${ref} Someone other than the person who made the first decision will review it where we can. We aim to reply with a decision and our reasons within 7 days (up to 14 if we need more information, and we will tell you).`;
    default:
      return `We have your message. ${ref}`;
  }
}
