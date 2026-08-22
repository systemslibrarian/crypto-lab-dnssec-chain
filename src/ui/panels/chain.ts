/**
 * Exhibit 1 — the real chain, from the IANA root anchor down to an answer.
 *
 * Nothing on this panel was made here. The keys are the root's, Verisign's and
 * Cloudflare's; the signatures are theirs; the trust anchor is the one IANA
 * publishes and every validating resolver ships with. The only thing this page
 * contributes is the arithmetic, and the point of showing each link separately
 * is that the arithmetic is local: every step is one signature over one RRset
 * under one key, and the "chain" is nothing more than doing that three times
 * in a row.
 */

import { validateChain } from '../../dnssec/chain.ts';
import { buildSecureChain, ANCHORS } from '../../dnssec/realworld.ts';
import { PINNED_CHAIN } from '../../vectors/pinned.ts';
import { ROOT_TRUST_ANCHORS } from '../../vectors/rfc.ts';
import { renderChain } from '../chainview.ts';
import { badge, button, controlGroup, disclosure, el, liveRegion, para, replace, scroller } from '../dom.ts';
import { utcStamp } from '../format.ts';

interface ClockPreset {
  readonly id: string;
  readonly label: string;
  readonly offsetDays: number;
  readonly note: string;
}

const CLOCK_PRESETS: readonly ClockPreset[] = [
  {
    id: 'capture',
    label: 'The capture instant',
    offsetDays: 0,
    note: 'The moment the records were fetched. Every signature in the file was valid then.',
  },
  {
    id: 'plus-1',
    label: '+1 day',
    offsetDays: 1,
    note: 'A day later. Some signatures have short windows; the chain may already be failing.',
  },
  {
    id: 'plus-400',
    label: '+400 days',
    offsetDays: 400,
    note: 'Long past every expiration in the capture.',
  },
  {
    id: 'minus-400',
    label: '−400 days',
    offsetDays: -400,
    note: 'Before every inception in the capture — the shape of a validator with a wrong clock.',
  },
];

export function renderChainPanel(host: HTMLElement): void {
  const output = liveRegion('Chain validation result', 'chain-out');
  let current: ClockPreset = CLOCK_PRESETS[0]!;
  const buttons: HTMLButtonElement[] = [];

  const run = async (): Promise<void> => {
    // Marked pending BEFORE the await: without this a test (or a fast second
    // click) can read the previous run's status and believe it is this one's.
    output.dataset.status = 'pending';
    const now = PINNED_CHAIN.capturedAt + current.offsetDays * 86400;
    const result = await validateChain(buildSecureChain(PINNED_CHAIN, { now }));
    // Stamped on the live region so the claims suite can compare the status the
    // page PRINTS against the status it recomputes from the same capture.
    output.dataset.status = result.status;
    output.dataset.failure = result.failure ?? 'none';
    output.dataset.now = String(now);
    replace(output, el('div', { class: 'reveal' }, [
      el('p', { class: 'prose', text: current.note }),
      renderChain(result, now),
    ]));
  };

  for (const preset of CLOCK_PRESETS) {
    const node = button(
      preset.label,
      () => {
        current = preset;
        for (const other of buttons) {
          other.setAttribute('aria-pressed', other === node ? 'true' : 'false');
        }
        void run();
      },
      { 'aria-pressed': preset.id === current.id ? 'true' : 'false' }
    );
    buttons.push(node);
  }

  host.append(
    el('h2', { text: 'A real chain of trust, one link at a time' }),
    el('p', {
      class: 'lede',
      text:
        'Root zone to .com to cloudflare.com, captured with dig and committed to this repository. Each link is checked on its own: the parent’s fingerprint has to hash to the child’s key, and the child’s key set has to carry a valid signature by that same key.',
    }),

    el('h3', { text: 'Where trust starts' }),
    para(
      'One layer of this system is not learned from the network at all: the root key-signing keys. IANA publishes their fingerprints, resolvers compile them in, and every other key in the DNS is derived from there. More than one is configured at a time so a rollover has an overlap — the retiring anchor and its successor are both trusted until the old one is withdrawn. These are the current ones, transcribed from data.iana.org:'
    ),
    el('table', { class: 'data' }, [
      el('thead', {}, [
        el('tr', {}, [
          el('th', { scope: 'col', text: 'Anchor' }),
          el('th', { scope: 'col', text: 'Key tag' }),
          el('th', { scope: 'col', text: 'Algorithm' }),
          el('th', { scope: 'col', text: 'SHA-256 digest' }),
        ]),
      ]),
      el(
        'tbody',
        {},
        ROOT_TRUST_ANCHORS.map((anchor) =>
          el('tr', {}, [
            el('td', { text: `${anchor.label} (valid from ${anchor.validFrom})` }),
            el('td', { class: 'mono', text: String(anchor.keyTag) }),
            el('td', { class: 'mono', text: String(anchor.algorithm) }),
            el('td', { class: 'mono', text: anchor.digestHex }),
          ])
        )
      ),
    ]),
    el('p', { class: 'prose' }, [
      badge('info', 'note'),
      ` ${ANCHORS.length} anchors are configured. The chain below only needs one of them to match a key the root actually served.`,
    ]),

    controlGroup(
      'Move the validation clock',
      ...buttons
    ),
    el('p', { class: 'prose' }, [
      'DNSSEC validity is wall-clock: every signature carries an inception and an expiration, and a validator compares them against its own clock. The capture was taken at ',
      el('code', { text: utcStamp(PINNED_CHAIN.capturedAt) }),
      ', so that is the honest instant to judge it at — and moving away from it is the same thing as a resolver whose clock is wrong.',
    ]),
    output,

    disclosure(
      'Show the raw dig output this chain was built from',
      para(
        'Committed verbatim, comments and all. Everything on this panel is derived from this text by the same parser the lab uses on RFC example zones.'
      ),
      scroller(
        'Captured dig output',
        el('pre', { class: 'records' }, [el('code', { text: PINNED_CHAIN.rawText })])
      )
    )
  );

  void run();
}
