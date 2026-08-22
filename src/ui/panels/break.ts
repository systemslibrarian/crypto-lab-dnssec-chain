/**
 * Exhibit 2 — break each link, and get a different name for each break.
 *
 * Every break below is produced by SIGNING SOMETHING WRONG, not by corrupting
 * bytes after the fact. That distinction is the exhibit: a corrupted byte can
 * only ever produce "the signature does not verify", while a zone that signs a
 * stale fingerprint, or signs outside its window, or signs with a key nobody
 * vouched for, produces three completely different diagnoses — and those are
 * the ones that actually take zones off the internet.
 *
 * The one exception is the unsupported-algorithm case, and it is not
 * synthesized at all: it runs RFC 6605's own ECDSA P-384 example, a real and
 * perfectly valid signature this lab does not implement. That is what makes
 * "I cannot judge this" distinguishable from "this is forged".
 */

import { parseName, presentName } from '../../dns/name.ts';
import { RR_TYPE, toRRsets } from '../../dns/types.ts';
import { parseRecords } from '../../dns/zonefile.ts';
import { validateChain } from '../../dnssec/chain.ts';
import { FAILURES, HEADLINE_FAILURE_CODES, type FailureCode } from '../../dnssec/failures.ts';
import { verifyRrset } from '../../dnssec/verify.ts';
import { RFC6605_P384 } from '../../vectors/rfc.ts';
import {
  buildHierarchy,
  DEMO_EXPIRATION,
  DEMO_INCEPTION,
  DEMO_NOW,
  TLD,
  type HierarchyOptions,
} from '../../zone/demo.ts';
import { resolveInDemo } from '../../zone/resolve.ts';
import { signRrsetAs } from '../../zone/sign.ts';
import { renderChain, failureNote } from '../chainview.ts';
import { badge, button, checkList, checkRow, controlGroup, el, list, liveRegion, para, replace } from '../dom.ts';

type BreakId =
  | 'none'
  | 'ds-digest'
  | 'ds-keytag'
  | 'expired'
  | 'early'
  | 'rogue-ksk'
  | 'tampered-answer'
  | 'neighbour-signed'
  | 'alg-unsupported';

interface BreakSpec {
  readonly id: BreakId;
  readonly label: string;
  readonly what: string;
  readonly expect: FailureCode | null;
}

const BREAKS: readonly BreakSpec[] = [
  {
    id: 'none',
    label: 'Nothing broken',
    what: 'The hierarchy exactly as signed. Every link should verify.',
    expect: null,
  },
  {
    id: 'ds-digest',
    label: 'Stale fingerprint at the parent',
    what:
      'example. publishes a DS whose digest no longer matches the child’s key, and signs it correctly. This is the failure a registrar causes by not updating the DS after a key roll — the single most common way a real domain goes dark.',
    expect: 'DS_MISMATCH',
  },
  {
    id: 'ds-keytag',
    label: 'DS points at a key that is not there',
    what:
      'The DS names a key tag the child does not publish. The tag is only a lookup hint, but with no candidate key there is nothing to check against.',
    expect: 'KEYTAG_MISMATCH',
  },
  {
    id: 'expired',
    label: 'Signatures expired',
    what:
      'The clock is past every expiration. The arithmetic is perfect and the answer is still unusable, because a DNSSEC signature is only valid inside a window it carries with it.',
    expect: 'RRSIG_EXPIRED',
  },
  {
    id: 'early',
    label: 'Clock behind the inception',
    what:
      'The clock is before every inception. Same maths, opposite direction — and this is what a resolver with a wrong clock sees when the zone is fine.',
    expect: 'RRSIG_NOT_YET_VALID',
  },
  {
    id: 'rogue-ksk',
    label: 'Zone signs its keys with a key nobody vouched for',
    what:
      'The parent still vouches for the original key-signing key; the child has started signing its DNSKEY set with a different one. The signature verifies under the key that made it — and that key is not the one the delegation points at.',
    expect: 'KEYTAG_MISMATCH',
  },
  {
    id: 'tampered-answer',
    label: 'Answer rewritten in flight',
    what:
      'Every link verifies and the final address has been changed by one byte. This is the only break here that is genuinely an attack rather than an operational mistake.',
    expect: 'SIGNATURE_INVALID',
  },
  {
    id: 'neighbour-signed',
    label: 'A neighbouring zone signs your records',
    what:
      'example. signs an answer that belongs to demo.example., with a real key and a real signature. Accepting it would let any zone speak for any other, which is the entire property the hierarchy exists to enforce.',
    expect: 'SIGNER_NAME_MISMATCH',
  },
  {
    id: 'alg-unsupported',
    label: 'An algorithm this validator does not implement',
    what:
      'RFC 6605’s own ECDSA P-384 example — a genuine, valid signature by algorithm 14, which this lab does not implement. The right answer is not “forged”; it is “I cannot judge this”.',
    expect: 'ALG_UNSUPPORTED',
  },
];

const OPTIONS: Partial<Record<BreakId, HierarchyOptions>> = {
  'ds-digest': { corruptDs: true },
  'ds-keytag': { wrongKeyTag: true },
  'rogue-ksk': { rogueKsk: true },
};

const CLOCK: Partial<Record<BreakId, number>> = {
  expired: DEMO_EXPIRATION + 3600,
  early: DEMO_INCEPTION - 3600,
};

async function runBreak(spec: BreakSpec): Promise<HTMLElement> {
  if (spec.id === 'alg-unsupported') return runAlgorithmCase();

  const hierarchy = await buildHierarchy(OPTIONS[spec.id] ?? {});
  const now = CLOCK[spec.id] ?? DEMO_NOW;
  const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, { now });
  let input = resolution.input;

  if (spec.id === 'tampered-answer' && input.answer) {
    const rdatas = input.answer.rrset.rdatas.map((rdata) => {
      const copy = Uint8Array.from(rdata);
      const last = copy[copy.length - 1];
      if (last !== undefined) copy[copy.length - 1] = (last + 1) & 0xff;
      return copy;
    });
    input = { ...input, answer: { ...input.answer, rrset: { ...input.answer.rrset, rdatas } } };
  }

  if (spec.id === 'neighbour-signed' && input.answer) {
    const rrsig = await signRrsetAs(input.answer.rrset, hierarchy.keys.tldZsk, {
      apex: TLD,
      inception: DEMO_INCEPTION,
      expiration: DEMO_EXPIRATION,
    });
    input = { ...input, answer: { ...input.answer, rrsigs: [rrsig] } };
  }

  const result = await validateChain(input);
  return el('div', { class: 'reveal', 'data-failure': result.failure ?? 'none', 'data-status': result.status }, [
    para(spec.what),
    renderChain(result, now),
  ]);
}

/**
 * The unsupported-algorithm case, run against real RFC text rather than
 * against anything this page made.
 */
async function runAlgorithmCase(): Promise<HTMLElement> {
  const records = parseRecords(RFC6605_P384);
  const rrset = toRRsets(records.filter((r) => r.type === RR_TYPE.A))[0];
  if (!rrset) throw new Error('the P-384 vector lost its A record');
  const verification = await verifyRrset(
    rrset,
    records.filter((r) => r.type === RR_TYPE.RRSIG).map((r) => r.rdata),
    records.filter((r) => r.type === RR_TYPE.DNSKEY).map((r) => r.rdata),
    { zone: parseName('example.net.'), now: Date.UTC(2010, 7, 15) / 1000 }
  );
  const attempt = verification.attempts[0];
  return el('div', { class: 'reveal', 'data-failure': verification.failure ?? 'none', 'data-status': verification.failure === 'ALG_UNSUPPORTED' ? 'INDETERMINATE' : 'BOGUS' }, [
    para(
      'This is RFC 6605 section 6.2, verbatim: an A record for www.example.net., the zone’s algorithm-14 key, and a signature that is genuinely valid. Every check that can be made passes, and then the validator stops at the one it cannot.'
    ),
    el('div', { class: 'records' }, [
      el('code', {
        text: records
          .map((r) => `${presentName(r.name)} ${r.ttl} IN ${r.type === RR_TYPE.A ? 'A' : r.type === RR_TYPE.DS ? 'DS' : r.type === RR_TYPE.DNSKEY ? 'DNSKEY' : 'RRSIG'} …`)
          .join('\n'),
      }),
    ]),
    checkList(
      (attempt?.checks ?? []).map((c) => checkRow(c.passed, c.label, c.detail)),
      'Checks against the RFC 6605 P-384 vector'
    ),
    verification.failure ? failureNote(verification.failure) : para('Verified.'),
    para(
      'Note what did NOT happen: the DS digest for this same key still computes correctly, because a digest is over bytes and does not care which algorithm made them. A validator that reported this zone as broken would be blaming the zone for its own gap.'
    ),
  ]);
}

export function renderBreakPanel(host: HTMLElement): void {
  const output = liveRegion('Result of the selected break', 'break-out');
  const buttons: HTMLButtonElement[] = [];
  let current: BreakSpec = BREAKS[0]!;

  const run = async (): Promise<void> => {
    output.dataset.status = 'pending';
    output.dataset.failure = 'pending';
    replace(output, el('p', { class: 'prose', text: 'Signing and validating…' }));
    const view = await runBreak(current);
    output.dataset.break = current.id;
    output.dataset.expected = current.expect ?? 'none';
    output.dataset.failure = view.dataset.failure ?? 'none';
    output.dataset.status = view.dataset.status ?? 'unknown';
    replace(output, view);
  };

  for (const spec of BREAKS) {
    const node = button(
      spec.label,
      () => {
        current = spec;
        for (const other of buttons) {
          other.setAttribute('aria-pressed', other === node ? 'true' : 'false');
        }
        void run();
      },
      { 'aria-pressed': spec.id === current.id ? 'true' : 'false' }
    );
    buttons.push(node);
  }

  host.append(
    el('h2', { text: 'Break each link, and read the diagnosis' }),
    el('p', {
      class: 'lede',
      text:
        'A hierarchy signed here, in this tab, with real keys — so a break can be made by re-signing something wrong rather than by corrupting bytes. Each break produces its own named failure, because "invalid" is not a diagnosis.',
    }),
    controlGroup('Choose a break', ...buttons),
    output,
    el('h3', { text: 'The failures this validator can name' }),
    list(
      'ul',
      'check-list',
      'Named failure codes',
      HEADLINE_FAILURE_CODES.map((code) =>
        el('li', { class: 'check', role: 'listitem' }, [
          el('span', { class: 'check-glyph', 'aria-hidden': 'true', text: '•' }),
          el('div', { class: 'check-body' }, [
            el('span', { class: 'check-label', text: code }),
            el('span', { class: 'check-detail', text: `${FAILURES[code].plain} (${FAILURES[code].reference})` }),
          ]),
        ])
      ),
      'No failure codes declared.'
    ),
    el('p', { class: 'prose' }, [
      badge('info', 'note'),
      ' Two of these are not failures at all. INSECURE is a chain that ended correctly — the next tab — and an unsupported algorithm is a statement about the validator, not about the zone.',
    ])
  );

  void run();
}
