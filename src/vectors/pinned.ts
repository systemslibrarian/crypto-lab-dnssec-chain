/**
 * The pinned real-world chain: `dig` output, committed verbatim, parsed here.
 *
 * `src/vectors/pinned-chain.txt` is exactly what `scripts/capture-chain.sh`
 * printed, straight from the authoritative servers for the root, `.com`, and
 * `cloudflare.com`. The lab never queries DNS at run time — a demo whose
 * lesson depends on what a network returns today is a demo that teaches
 * something different tomorrow, and the RRSIGs in a live chain expire within
 * days regardless.
 *
 * So the capture instant is pinned too, and validation runs against it. That
 * is not a workaround: DNSSEC validity is wall-clock, the whole point of the
 * inception and expiration fields is that they are compared against a clock,
 * and giving the learner a clock to move is how this lab shows it.
 */

import { parseName, presentName, type Labels } from '../dns/name.ts';
import { RR_TYPE, toRRsets, type ResourceRecord, type RRset } from '../dns/types.ts';
import { parseRecords } from '../dns/zonefile.ts';
import pinnedChainText from './pinned-chain.txt?raw';

export interface CapturedSection {
  readonly key: string;
  /** The `dig` command line, kept so the capture is reproducible by hand. */
  readonly command: string;
  readonly answer: readonly ResourceRecord[];
  readonly authority: readonly ResourceRecord[];
}

export interface PinnedChain {
  /** Seconds since the epoch at which the capture was taken. */
  readonly capturedAt: number;
  readonly capturedAtIso: string;
  readonly sections: ReadonlyMap<string, CapturedSection>;
  readonly rawText: string;
}

const SECTION_RE = /^;;\s*====\s*(\S+)\s*====\s*$/;
const COMMAND_RE = /^;;\s*(dig .*)$/;

export function parsePinnedChain(text: string): PinnedChain {
  const unixMatch = /^;;\s*capture-unixtime\s+(\d+)\s*$/m.exec(text);
  const isoMatch = /^;;\s*PINNED DNSSEC CHAIN -- captured (\S+)\s*$/m.exec(text);
  if (!unixMatch || !isoMatch) {
    throw new Error('pinned-chain.txt is missing its capture header');
  }

  const sections = new Map<string, CapturedSection>();
  let key: string | null = null;
  let command = '';
  let bucket: 'answer' | 'authority' | null = null;
  let answerLines: string[] = [];
  let authorityLines: string[] = [];

  const flush = (): void => {
    if (key === null) return;
    sections.set(key, {
      key,
      command,
      answer: parseRecords(answerLines.join('\n')),
      authority: parseRecords(authorityLines.join('\n')),
    });
  };

  for (const line of text.split(/\r?\n/)) {
    const section = SECTION_RE.exec(line);
    if (section) {
      flush();
      key = section[1]!;
      command = '';
      bucket = null;
      answerLines = [];
      authorityLines = [];
      continue;
    }
    if (key === null) continue;
    const cmd = COMMAND_RE.exec(line);
    if (cmd) {
      command = cmd[1]!;
      continue;
    }
    if (/^;;\s*ANSWER SECTION:/.test(line)) {
      bucket = 'answer';
      continue;
    }
    if (/^;;\s*AUTHORITY SECTION:/.test(line)) {
      bucket = 'authority';
      continue;
    }
    // Any other `;`-prefixed line is dig's own commentary (header flags, the
    // EDNS pseudo-section) and carries no records.
    if (/^\s*;/.test(line) || line.trim() === '') continue;
    if (bucket === 'answer') answerLines.push(line);
    else if (bucket === 'authority') authorityLines.push(line);
  }
  flush();

  return {
    capturedAt: Number(unixMatch[1]),
    capturedAtIso: isoMatch[1]!,
    sections,
    rawText: text,
  };
}

export const PINNED_CHAIN: PinnedChain = parsePinnedChain(pinnedChainText);

/** Pull one section, failing loudly rather than silently returning nothing. */
export function section(chain: PinnedChain, key: string): CapturedSection {
  const found = chain.sections.get(key);
  if (!found) throw new Error(`pinned capture has no section ${JSON.stringify(key)}`);
  return found;
}

/** The RRset of one type at one owner, out of a captured section. */
export function rrsetOf(
  records: readonly ResourceRecord[],
  owner: Labels,
  type: number
): RRset | null {
  const wanted = presentName(owner).toLowerCase();
  const matching = records.filter(
    (r) => r.type === type && presentName(r.name).toLowerCase() === wanted
  );
  if (matching.length === 0) return null;
  return toRRsets(matching)[0] ?? null;
}

/** The RRSIG RDATAs covering one type at one owner. */
export function rrsigsFor(
  records: readonly ResourceRecord[],
  owner: Labels,
  typeCovered: number
): Uint8Array[] {
  const wanted = presentName(owner).toLowerCase();
  return records
    .filter((r) => r.type === RR_TYPE.RRSIG && presentName(r.name).toLowerCase() === wanted)
    .filter((r) => (r.rdata[0]! << 8 | r.rdata[1]!) === typeCovered)
    .map((r) => r.rdata);
}

/** The three zones the pinned capture covers, in chain order. */
export const PINNED_ZONES = {
  root: parseName('.'),
  com: parseName('com.'),
  cloudflare: parseName('cloudflare.com.'),
  /** Signed parent, unsigned child: the INSECURE case, captured live. */
  google: parseName('google.com.'),
  /** The name whose denial Cloudflare synthesizes per query. */
  nxdomain: parseName('no-such-name-9x7q.cloudflare.com.'),
} as const;
