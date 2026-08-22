/**
 * Rendering a validated chain.
 *
 * The chain is drawn as an ordered list of links, each carrying its own
 * status, its own checklist, and — behind a disclosure — the actual bytes it
 * compared. A link that has not been reached is drawn as pending rather than
 * as passing, because a validator that stops does not silently approve what
 * comes after.
 */

import { presentName } from '../dns/name.ts';
import { algorithmName } from '../dns/types.ts';
import type { ChainLink, ChainResult } from '../dnssec/chain.ts';
import { FAILURES, STATUS, type FailureCode, type SecurityStatus } from '../dnssec/failures.ts';
import { badge, checkList, checkRow, disclosure, el, list } from './dom.ts';
import { compareBytesPanel, signedDataPanel, STATUS_TONE, utcStamp } from './format.ts';

const STATUS_CLASS: Record<SecurityStatus, string> = {
  SECURE: 'link-secure',
  INSECURE: 'link-insecure',
  BOGUS: 'link-bogus',
  INDETERMINATE: 'link-indeterminate',
};

function keySummary(link: ChainLink): HTMLElement {
  if (link.keys.length === 0) {
    return el('p', { class: 'prose', text: 'This zone publishes no keys — it is not signed.' });
  }
  return list(
    'ul',
    'chips',
    `Keys published by ${presentName(link.zone)}`,
    link.keys.map((key) =>
      el('li', { class: 'chip', role: 'listitem' }, [
        `${key.isSep ? 'KSK' : 'ZSK'} tag ${key.tag} · ${algorithmName(key.algorithm)}` +
          (link.vouchedKey && link.vouchedKey.tag === key.tag ? ' · vouched for by the parent' : ''),
      ])
    ),
    'This zone publishes no keys.'
  );
}

function digestDisclosure(link: ChainLink): HTMLElement | null {
  const match = link.dsMatches.find((m) => m.preimage && m.computedDigest);
  if (!match || !match.preimage || !match.computedDigest) return null;
  return disclosure(
    'Show the digest that was compared',
    el('p', {
      class: 'prose',
      text:
        `The parent published a fingerprint of the child's key. The child served a key. Hashing ${presentName(link.zone)} together with that key's RDATA — ${match.preimage.length} octets in total — has to reproduce the parent's value exactly.`,
    }),
    compareBytesPanel(
      'Computed from the child’s key',
      match.computedDigest,
      'Published by the parent',
      match.ds.digest
    )
  );
}

function signedDataDisclosure(link: ChainLink): HTMLElement | null {
  const attempt = link.dnskeyVerification?.attempts.find((a) => a.signedData);
  if (!attempt?.signedData) return null;
  return disclosure(
    'Show the octets this signature covers',
    el('p', {
      class: 'prose',
      text:
        'A DNSSEC signature does not cover a packet. It covers a byte string assembled to a fixed recipe (RFC 4034 section 3.1.8.1): the signature record’s own metadata first, then every covered record in canonical order — down-cased owner name, the ORIGINAL time-to-live rather than the one that arrived, and the record data sorted as unsigned octets.',
    }),
    signedDataPanel(attempt.signedData.rrsigPrefix, attempt.signedData.records)
  );
}

export function renderLink(link: ChainLink, index: number, reached: boolean): HTMLElement {
  if (!reached) {
    return el('li', { class: 'link link-pending', role: 'listitem' }, [
      el('div', { class: 'link-head' }, [
        el('span', { class: 'link-title', text: link.title }),
        badge('muted', 'not reached', 'the chain stopped above this link'),
      ]),
    ]);
  }
  const rows = link.checks.map((check) => checkRow(check.passed, check.label, check.detail));
  return el('li', { class: `link ${STATUS_CLASS[link.status]}`, role: 'listitem' }, [
    el('div', { class: 'link-head' }, [
      el('span', { class: 'link-title', text: link.title }),
      badge(STATUS_TONE[link.status], STATUS[link.status].title),
    ]),
    keySummary(link),
    checkList(rows, `Checks for link ${index + 1}, ${link.title}`),
    digestDisclosure(link),
    signedDataDisclosure(link),
  ]);
}

export function failureNote(code: FailureCode): HTMLElement {
  const info = FAILURES[code];
  return el('div', { class: 'failure-note' }, [
    el('p', {}, [
      el('span', { class: 'failure-code', text: code }),
      ' — ',
      info.title,
    ]),
    el('p', { class: 'failure-plain', text: info.plain }),
    el('p', { class: 'failure-ref', text: info.reference }),
  ]);
}

export function statusNote(status: SecurityStatus): HTMLElement {
  const tone = STATUS_TONE[status];
  const info = STATUS[status];
  return el('div', { class: `status-note status-note-${tone}` }, [
    el('p', {}, [badge(tone, info.title)]),
    el('p', { class: 'failure-plain', text: info.plain }),
    el('p', { class: 'failure-ref', text: info.reference }),
  ]);
}

export function renderChain(result: ChainResult, now: number): HTMLElement {
  const items: HTMLElement[] = [];
  result.links.forEach((link, index) => {
    if (index > 0) items.push(el('li', { class: 'link-arrow', 'aria-hidden': 'true', text: '↓' }));
    items.push(renderLink(link, index, true));
  });

  const answer = result.answer;
  if (answer) {
    items.push(el('li', { class: 'link-arrow', 'aria-hidden': 'true', text: '↓' }));
    const verified = answer.verification.verified;
    const attempt = answer.verification.attempts[0];
    items.push(
      el('li', { class: `link ${verified ? 'link-secure' : 'link-bogus'}`, role: 'listitem' }, [
        el('div', { class: 'link-head' }, [
          el('span', { class: 'link-title', text: `answer: ${presentName(answer.rrset.name)}` }),
          badge(verified ? 'ok' : 'bad', verified ? 'Verified' : 'Rejected'),
        ]),
        checkList(
          (attempt?.checks ?? []).map((c) => checkRow(c.passed, c.label, c.detail)),
          'Checks for the answer RRset'
        ),
        attempt?.signedData
          ? disclosure(
              'Show the octets this signature covers',
              signedDataPanel(attempt.signedData.rrsigPrefix, attempt.signedData.records)
            )
          : null,
      ])
    );
  }

  return el('div', {}, [
    el('p', { class: 'prose', text: `Validating at ${utcStamp(now)}.` }),
    list('ol', 'chain', 'Chain of trust, from the anchor down', items, 'No links to show.'),
    result.failure ? failureNote(result.failure) : statusNote(result.status),
  ]);
}
