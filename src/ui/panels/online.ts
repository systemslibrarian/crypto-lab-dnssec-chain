/**
 * Exhibit 6 — denial synthesized per query, captured from a real server.
 *
 * The other way out of the enumeration problem is to stop pre-computing the
 * denial. Instead of publishing a chain that represents the zone, the server
 * makes up a proof for each query that covers as little as possible — often
 * nothing but the name that was asked about. There is then no neighbour to
 * learn and nothing to walk to.
 *
 * The cost is the thing to be careful about. Synthesizing a proof means
 * signing it, which means a private key on an internet-facing server, which is
 * exactly the property offline signing existed to avoid. It also makes every
 * denial a signature operation, so an attacker can spend a query and make the
 * server spend a signature. This is a trade, not an upgrade.
 *
 * Citations, checked against their own abstracts: RFC 4470 (Standards Track)
 * specifies minimally covering NSEC records and on-line signing, and defines
 * the increment used below. RFC 7129 (Informational, Independent Submission)
 * is the readable overview and its Appendix B is where "NSEC3 white lies" is
 * named. "Black lies" — the NODATA variant the capture shows — has no RFC; it
 * is an Internet-Draft, draft-valsorda-dnsop-black-lies.
 */

import { presentName } from '../../dns/name.ts';
import { presentRdata } from '../../dns/rdata.ts';
import { RR_TYPE, typeName } from '../../dns/types.ts';
import { proveNxdomain } from '../../dnssec/nsec.ts';
import { buildBlackLieDenial } from '../../dnssec/realworld.ts';
import { PINNED_CHAIN } from '../../vectors/pinned.ts';
import { buildDemoZone } from '../../zone/demo.ts';
import { queryZone } from '../../zone/resolve.ts';
import { badge, button, checkList, checkRow, controlGroup, disclosure, el, list, liveRegion, para, replace, scroller } from '../dom.ts';
import { recordBlock } from '../format.ts';

export function renderOnlinePanel(host: HTMLElement): void {
  const denial = buildBlackLieDenial();
  const record = denial.nsec[0];
  const comparison = liveRegion('Comparison of the two denial styles', 'online-out');

  const showPrecomputed = async (): Promise<void> => {
    comparison.dataset.style = 'pending';
    const zone = await buildDemoZone();
    const response = queryZone(zone, [new TextEncoder().encode('does-not-exist'), ...zone.spec.apex], RR_TYPE.A);
    const lines = response.authority.flatMap((signed) =>
      signed.rrset.rdatas.map(
        (rdata) =>
          `${presentName(signed.rrset.name)} ${signed.rrset.ttl} IN ${typeName(signed.rrset.type)} ${presentRdata(signed.rrset.type, rdata)}`
      )
    );
    comparison.dataset.style = 'precomputed';
    comparison.dataset.leaks = String(
      new Set(
        response.authority
          .filter((r) => r.rrset.type === RR_TYPE.NSEC)
          .map((r) => presentName(r.rrset.name))
      ).size
    );
    replace(
      comparison,
      el('div', { class: 'reveal' }, [
        el('p', { class: 'prose' }, [
          badge('bad', 'leaks neighbours'),
          ' A pre-computed chain answers with records that name REAL owners on both sides of the gap. Every one of those names is now known.',
        ]),
        recordBlock(lines, 'Pre-computed NSEC denial from the in-page zone'),
      ])
    );
  };

  const showSynthesized = (): void => {
    if (!record) return;
    const lines = denial.records.map(
      (r) => `${presentName(r.name)} ${r.ttl} IN ${typeName(r.type)} ${presentRdata(r.type, r.rdata)}`
    );
    const proof = proveNxdomain(denial.nsec, denial.queried, denial.zone);
    comparison.dataset.style = 'synthesized';
    comparison.dataset.rcode = denial.rcodeIsNoError ? 'NOERROR' : 'NXDOMAIN';
    comparison.dataset.nxproof = proof.proven ? 'true' : 'false';
    replace(
      comparison,
      el('div', { class: 'reveal' }, [
        el('p', { class: 'prose' }, [
          badge('ok', 'leaks nothing'),
          ' The next owner is the queried name with a single NUL octet prepended as a new label — the smallest possible step forward in canonical order. Both endpoints of the "gap" are derived from the question, so the answer contains no name the asker did not already have.',
        ]),
        recordBlock(lines, 'Captured Cloudflare denial'),
        el('div', { class: 'callout callout-note' }, [
          el('p', {}, [
            el('strong', { text: 'Note the response code. ' }),
            `The status is ${denial.rcodeIsNoError ? 'NOERROR' : 'NXDOMAIN'}, not NXDOMAIN. The server is answering "this name exists and has no A record" rather than "this name does not exist" — which is what "black lies" names. It is also why the two-part NXDOMAIN proof does not apply here: `,
            badge(proof.proven ? 'bad' : 'info', proof.proven ? 'would prove NXDOMAIN' : 'not an NXDOMAIN proof'),
            ' — running the NXDOMAIN prover against it correctly declines, because there is no wildcard half and none is needed.',
          ]),
        ]),
        checkList(
          proof.steps.map((s) => checkRow(s.passed, s.label, s.detail)),
          'What the NXDOMAIN prover makes of a black lie',
        ),
      ])
    );
  };

  host.append(
    el('h2', { text: 'Making the denial up, one query at a time' }),
    el('p', {
      class: 'lede',
      text:
        'If the proof is synthesized per query it can cover almost nothing — just the name that was asked about. There is then no neighbour to hand back, and systematic enumeration stops being practical. The price is an online signing key.',
    }),

    controlGroup(
      'Compare the two styles',
      button('Pre-computed chain', () => void showPrecomputed()),
      button('Synthesized per query (real capture)', () => showSynthesized(), { class: 'btn btn-primary' })
    ),
    comparison,

    el('h3', { text: 'The increment, in one line' }),
    para(
      'RFC 4470 section 4 defines how to name the smallest name greater than a given one: prepend a label containing a single zero octet. Nothing can sort between them, so an NSEC from the query to that value covers exactly the query and nothing else.'
    ),
    record
      ? recordBlock(
          [
            `queried  ${presentName(denial.queried)}`,
            `owner    ${presentName(record.owner)}`,
            `next     ${presentName(record.rdata.nextName)}`,
            `types    ${record.rdata.types.map(typeName).join(' ')}`,
          ],
          'The synthesized interval'
        )
      : para('The capture did not include an NSEC record.'),

    el('div', { class: 'callout callout-warn' }, [
      el('p', {}, [
        el('strong', { text: 'What this costs. ' }),
        'The signature has to be made when the query arrives, so the zone’s private key lives on a machine that answers the internet — the opposite of the offline-signing property that made the enumeration problem exist in the first place. Every denial also becomes a public-key operation, so a stream of queries for random names is a stream of signatures the server must produce. Neither is disqualifying; both belong in the decision.',
      ]),
    ]),

    disclosure(
      'Citations, and one that is commonly wrong',
      list('ul', 'check-list', 'References for online denial', [
        el('li', { class: 'check check-ok', role: 'listitem' }, [
          el('span', { class: 'check-glyph', 'aria-hidden': 'true', text: '✓' }),
          el('div', { class: 'check-body' }, [
            el('span', { class: 'check-label', text: 'RFC 4470 — Standards Track' }),
            el('span', {
              class: 'check-detail',
              text:
                'Minimally Covering NSEC Records and DNSSEC On-line Signing. Defines the synthesis, the epsilon functions, and states the on-line-key cost in its own security considerations.',
            }),
          ]),
        ]),
        el('li', { class: 'check check-ok', role: 'listitem' }, [
          el('span', { class: 'check-glyph', 'aria-hidden': 'true', text: '✓' }),
          el('div', { class: 'check-body' }, [
            el('span', { class: 'check-label', text: 'RFC 7129 — Informational, Independent Submission' }),
            el('span', {
              class: 'check-detail',
              text:
                'Authenticated Denial of Existence in the DNS. The readable overview; Appendix A restates RFC 4470 and Appendix B is where "NSEC3 white lies" is defined.',
            }),
          ]),
        ]),
        el('li', { class: 'check check-ok', role: 'listitem' }, [
          el('span', { class: 'check-glyph', 'aria-hidden': 'true', text: '✓' }),
          el('div', { class: 'check-body' }, [
            el('span', { class: 'check-label', text: 'RFC 5155 — NSEC3' }),
            el('span', {
              class: 'check-detail',
              text: 'The normative NSEC3 specification; section 12.1.1 is its own account of dictionary attacks.',
            }),
          ]),
        ]),
        el('li', { class: 'check check-bad', role: 'listitem' }, [
          el('span', { class: 'check-glyph', 'aria-hidden': 'true', text: '✗' }),
          el('div', { class: 'check-body' }, [
            el('span', { class: 'check-label', text: 'RFC 8901 — not a reference for this' }),
            el('span', {
              class: 'check-detail',
              text:
                'Multi-Signer DNSSEC Models. It is about running a zone across several DNS providers, and mentions enumeration only in passing while pointing elsewhere for the definitions. Citing it for enumeration defences is a mistake this page names rather than repeats.',
            }),
          ]),
        ]),
        el('li', { class: 'check check-bad', role: 'listitem' }, [
          el('span', { class: 'check-glyph', 'aria-hidden': 'true', text: '✗' }),
          el('div', { class: 'check-body' }, [
            el('span', { class: 'check-label', text: '"Black lies" has no RFC' }),
            el('span', {
              class: 'check-detail',
              text:
                'The NODATA variant shown above is specified only in an Internet-Draft, draft-valsorda-dnsop-black-lies. RFC 4470 is the published anchor for minimally covering NSEC; RFC 7129 Appendix B is the published anchor for white lies.',
            }),
          ]),
        ]),
      ], 'No references listed.')
    ),

    disclosure(
      'Where this capture came from',
      para(
        `Fetched with dig from an authoritative Cloudflare nameserver and committed to this repository at ${PINNED_CHAIN.capturedAtIso}. Nothing is queried at run time.`
      ),
      scroller(
        'Raw captured denial',
        el('pre', { class: 'records' }, [
          el('code', {
            text: PINNED_CHAIN.rawText
              .slice(
                PINNED_CHAIN.rawText.indexOf(';; ==== cloudflare-nxdomain'),
                PINNED_CHAIN.rawText.indexOf(';; ==== com-ds-for-google-none')
              )
              .trim(),
          }),
        ])
      )
    )
  );

  showSynthesized();
}
