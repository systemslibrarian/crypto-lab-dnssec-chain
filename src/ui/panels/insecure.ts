/**
 * Exhibit 3 — a delegation with no DS returns INSECURE, not BOGUS.
 *
 * This is the distinction that is most often got backwards, and getting it
 * backwards is not a nuance: it trains people to read a normal answer as an
 * attack, which is how real alarms end up ignored. So the panel puts the two
 * side by side and makes the difference something you can watch happen —
 * remove the DS and the parent's signed proof, and the same missing record
 * turns from a legitimate ending into a hole.
 */

import { parseName, presentName } from '../../dns/name.ts';
import { RR_TYPE } from '../../dns/types.ts';
import { validateChain } from '../../dnssec/chain.ts';
import { buildInsecureChain, capturedOptOutNsec3 } from '../../dnssec/realworld.ts';
import { STATUS } from '../../dnssec/failures.ts';
import { PINNED_CHAIN, section } from '../../vectors/pinned.ts';
import { buildHierarchy, DEMO_NOW } from '../../zone/demo.ts';
import { resolveInDemo } from '../../zone/resolve.ts';
import { renderChain } from '../chainview.ts';
import { badge, button, controlGroup, disclosure, el, liveRegion, para, replace, scroller } from '../dom.ts';
import { recordBlock } from '../format.ts';

type Case = 'real' | 'demo' | 'hole';

const CASES: { id: Case; label: string; note: string }[] = [
  {
    id: 'real',
    label: 'Real: .com on google.com',
    note:
      'Captured from a .com nameserver. google.com has never been signed, so .com answers the DS query with a signed statement that it holds no DS — via an NSEC3 record with the Opt-Out flag set. The chain reaches .com, verifies, and then correctly ends.',
  },
  {
    id: 'demo',
    label: 'In-page: an unsigned child',
    note:
      'The same shape with NSEC instead of NSEC3, signed here. The parent’s NSEC at the delegation shows NS present and DS absent — and SOA absent, which is what proves the parent is speaking rather than the child.',
  },
  {
    id: 'hole',
    label: 'For contrast: no DS and no proof',
    note:
      'The DS is missing and so is any proof that it should be. That is not INSECURE. Nothing signed says the delegation is unsigned, so an attacker who simply deleted the DS would be indistinguishable from a zone that never had one.',
  },
];

export function renderInsecurePanel(host: HTMLElement): void {
  const output = liveRegion('Delegation result', 'insecure-out');
  const buttons: HTMLButtonElement[] = [];
  let current: Case = 'real';

  const run = async (): Promise<void> => {
    output.dataset.status = 'pending';
    const spec = CASES.find((c) => c.id === current);
    if (!spec) throw new Error(`no case named ${current}`);
    let view: HTMLElement;
    if (current === 'real') {
      const result = await validateChain(buildInsecureChain());
      output.dataset.status = result.status;
      view = el('div', { class: 'reveal' }, [para(spec.note), renderChain(result, PINNED_CHAIN.capturedAt)]);
    } else if (current === 'demo') {
      const hierarchy = await buildHierarchy();
      const resolution = await resolveInDemo(
        hierarchy,
        parseName('www.unsigned.example.'),
        RR_TYPE.A,
        { now: DEMO_NOW, target: 'unsigned' }
      );
      output.dataset.status = resolution.result.status;
      view = el('div', { class: 'reveal' }, [para(spec.note), renderChain(resolution.result, DEMO_NOW)]);
    } else {
      const hierarchy = await buildHierarchy({ noDs: true });
      const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, {
        now: DEMO_NOW,
      });
      output.dataset.status = resolution.result.status;
      view = el('div', { class: 'reveal' }, [para(spec.note), renderChain(resolution.result, DEMO_NOW)]);
    }
    output.dataset.case = current;
    replace(output, view);
  };

  for (const spec of CASES) {
    const node = button(
      spec.label,
      () => {
        current = spec.id;
        for (const other of buttons) other.setAttribute('aria-pressed', other === node ? 'true' : 'false');
        void run();
      },
      { 'aria-pressed': spec.id === current ? 'true' : 'false' }
    );
    buttons.push(node);
  }

  const captured = section(PINNED_CHAIN, 'com-ds-for-google-none');
  const optOut = capturedOptOutNsec3();

  host.append(
    el('h2', { text: 'A chain that ends is not a chain that broke' }),
    el('p', {
      class: 'lede',
      text:
        'Most of the DNS is unsigned. A validating resolver has to be able to say so without raising an alarm — and it does that by demanding a signed proof from the parent that the child has no DS record.',
    }),

    el('div', { class: 'result-grid' }, [
      el('div', { class: 'result-card' }, [
        el('h4', { text: 'INSECURE' }),
        el('p', {}, [badge('info', 'insecure')]),
        para(STATUS.INSECURE.plain),
        para('A resolver returns this answer normally. Your browser gets it.'),
      ]),
      el('div', { class: 'result-card' }, [
        el('h4', { text: 'BOGUS' }),
        el('p', {}, [badge('bad', 'bogus')]),
        para(STATUS.BOGUS.plain),
        para('A resolver refuses to return it at all. Your browser gets SERVFAIL.'),
      ]),
    ]),

    controlGroup('Choose a delegation', ...buttons),
    output,

    disclosure(
      'Show what .com actually sent',
      para(
        `Two NSEC3 records and their signatures, plus the SOA. Neither NSEC3 is owned by google.com — under Opt-Out the signer is allowed to skip one entirely, so the proof runs through the closest encloser and a covering record with the Opt-Out bit set. The flag is ${optOut.length > 0 ? 'set' : 'clear'} on the covering record.`
      ),
      recordBlock(
        captured.authority.map(
          (r) => `${presentName(r.name)} ${r.ttl} IN ${r.type === RR_TYPE.NSEC3 ? 'NSEC3' : r.type === RR_TYPE.SOA ? 'SOA' : 'RRSIG'} …`
        ),
        'Captured authority section for the google.com DS query'
      ),
      scroller(
        'Raw captured records',
        el('pre', { class: 'records' }, [
          el('code', {
            text: PINNED_CHAIN.rawText
              .slice(PINNED_CHAIN.rawText.indexOf(';; ==== com-ds-for-google-none'))
              .trim(),
          }),
        ])
      )
    ),

    el('div', { class: 'callout callout-note' }, [
      el('p', {}, [
        el('strong', { text: 'Opt-Out is a real weakening, and it is deliberate. ' }),
        'With the flag set, an unsigned delegation may exist inside a covered gap with no record of its own. That is what makes .com’s NSEC3 chain proportional to the number of SIGNED domains rather than to all of them — and it means a covering record proves less than it appears to. The proof above says so explicitly rather than glossing it.',
      ]),
    ])
  );

  void run();
}
