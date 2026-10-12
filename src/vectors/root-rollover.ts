/** Post-rollover root-only resolver capture; the historical full chain is unchanged. */
import { RR_TYPE } from '../dns/types.ts';
import type { ChainInput } from '../dnssec/chain.ts';
import { ANCHORS } from '../dnssec/realworld.ts';
import { parsePinnedChain, PINNED_ZONES, rrsetOf, rrsigsFor, section } from './pinned.ts';
import raw from './root-rollover-2026.txt?raw';

export const ROOT_ROLLOVER_CAPTURE = parsePinnedChain(raw);
export function buildRootRollover(): ChainInput {
  const records = section(ROOT_ROLLOVER_CAPTURE, 'root-dnskey').answer;
  return {
    anchors: ANCHORS,
    zones: [{
      zone: PINNED_ZONES.root, title: 'root zone after the 2026 rollover',
      dnskeys: rrsetOf(records, PINNED_ZONES.root, RR_TYPE.DNSKEY),
      dnskeyRrsigs: rrsigsFor(records, PINNED_ZONES.root, RR_TYPE.DNSKEY),
      ds: null, dsRrsigs: [],
    }],
    answer: null, now: ROOT_ROLLOVER_CAPTURE.capturedAt,
  };
}
