/**
 * Rendering records, bytes and verdicts.
 *
 * The rule everywhere here: SHOW the thing rather than describe it. A record
 * is printed the way `dig` prints it, so what is on screen is comparable with
 * what a learner would get from their own terminal. A digest comparison prints
 * both digests. A signed-data panel prints the actual octets, split into the
 * runs the RFC defines, because "the signature covers these bytes" means
 * nothing until the bytes are visible.
 */

import { toHex } from '../dns/codec.ts';
import type { SecurityStatus } from '../dnssec/failures.ts';
import { el, list, type Tone } from './dom.ts';

/**
 * A block of record text, wrapping rather than scrolling sideways.
 *
 * `role="group"` is not decoration. `<pre>` has no implicit ARIA role, and
 * `aria-label` on a role-less element is PROHIBITED — screen readers discard
 * it silently, and axe files the finding under `incomplete` rather than
 * `violations`, so a gate that reads only the violations array never sees it.
 * The role is what makes the label reach a reader.
 */
export function recordBlock(lines: readonly string[], label: string): HTMLElement {
  return el('pre', { class: 'records', role: 'group', 'aria-label': label }, [
    el('code', { text: lines.join('\n') }),
  ]);
}

/**
 * Two byte strings, printed side by side with a per-nibble verdict.
 *
 * Computing both sides and comparing them is the difference between showing a
 * digest match and asserting one. When they differ, the first differing nibble
 * is marked so the reader can see WHERE, not just THAT.
 */
export function compareBytesPanel(
  leftLabel: string,
  left: Uint8Array,
  rightLabel: string,
  right: Uint8Array
): HTMLElement {
  const a = toHex(left);
  const b = toHex(right);
  const equal = a === b;
  const firstDiff = equal ? -1 : [...a].findIndex((ch, i) => ch !== b[i]);
  const mark = (text: string): HTMLElement =>
    el('code', { class: 'cmp-hex' }, [
      firstDiff < 0
        ? text
        : el('span', {}, [
            text.slice(0, firstDiff),
            el('mark', { class: 'cmp-diff', text: text.slice(firstDiff) }),
          ]),
    ]);
  return el('div', { class: `cmp ${equal ? 'cmp-equal' : 'cmp-differ'}` }, [
    el('div', { class: 'cmp-row' }, [
      el('span', { class: 'cmp-label', text: leftLabel }),
      mark(a),
    ]),
    el('div', { class: 'cmp-row' }, [
      el('span', { class: 'cmp-label', text: rightLabel }),
      mark(b),
    ]),
    el('p', { class: 'cmp-verdict' }, [
      el('span', { class: 'cmp-glyph', 'aria-hidden': 'true', text: equal ? '✓' : '✗' }),
      equal
        ? 'Byte for byte identical — the parent is vouching for this exact key.'
        : `They differ from nibble ${firstDiff + 1} onward, so the parent is not vouching for this key.`,
    ]),
  ]);
}

/**
 * The bytes a signature actually covers, split into the runs RFC 4034 defines.
 *
 * Shown rather than summarised because "the signature covers the RRSIG's own
 * RDATA followed by each canonicalized record" is otherwise a sentence a
 * learner has to take on faith.
 */
export function signedDataPanel(
  rrsigPrefix: Uint8Array,
  records: readonly { bytes: Uint8Array }[]
): HTMLElement {
  const rows: HTMLElement[] = [
    el('li', { class: 'sd-run', role: 'listitem' }, [
      el('span', { class: 'sd-tag', text: 'RRSIG RDATA, signature field removed' }),
      el('code', { class: 'sd-bytes', text: toHex(rrsigPrefix) }),
      el('span', { class: 'sd-len', text: `${rrsigPrefix.length} octets` }),
    ]),
  ];
  records.forEach((record, index) => {
    rows.push(
      el('li', { class: 'sd-run', role: 'listitem' }, [
        el('span', {
          class: 'sd-tag',
          text: `RR(${index + 1}) — owner | type | class | ORIGINAL TTL | length | RDATA`,
        }),
        el('code', { class: 'sd-bytes', text: toHex(record.bytes) }),
        el('span', { class: 'sd-len', text: `${record.bytes.length} octets` }),
      ])
    );
  });
  return list('ul', 'sd', 'The octets this signature covers', rows, 'No signed octets to show.');
}

/** Status colours track SYSTEM INTEGRITY, not the raw return value. */
export const STATUS_TONE: Record<SecurityStatus, Tone> = {
  SECURE: 'ok',
  INSECURE: 'info',
  BOGUS: 'bad',
  INDETERMINATE: 'warn',
};

/** Seconds since the epoch, printed as the UTC stamp DNSSEC actually compares. */
export function utcStamp(seconds: number): string {
  return `${new Date(seconds * 1000).toISOString().replace('T', ' ').replace('.000Z', '')} UTC`;
}
