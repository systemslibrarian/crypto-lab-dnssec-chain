/**
 * The registries and the record model everything else is written against.
 *
 * A resource record here is deliberately stored as `{ name, type, class, ttl,
 * rdata }` with `rdata` already in WIRE form. Presentation text is a rendering
 * of that, never the source of truth — the moment a validator starts working
 * from re-printed text it is authenticating a string rather than the bytes the
 * signer signed.
 */

import type { Labels } from './name.ts';
import { presentName } from './name.ts';

/** RR types this lab reads or writes. */
export const RR_TYPE = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3: 50,
  NSEC3PARAM: 51,
} as const;

const TYPE_BY_NUMBER = new Map<number, string>(
  Object.entries(RR_TYPE).map(([name, num]) => [num, name])
);

/** `48` to `DNSKEY`; an unknown number to the RFC 3597 `TYPE128` spelling. */
export function typeName(type: number): string {
  return TYPE_BY_NUMBER.get(type) ?? `TYPE${type}`;
}

/**
 * `DNSKEY` to 48, and `TYPE128` to 128.
 *
 * RFC 3597 generic spellings are accepted because real zones use them: the
 * captured Cloudflare denial in `src/vectors/pinned-chain.txt` lists `TYPE128`
 * in its NSEC type bitmap, and a parser that rejected it would refuse a proof
 * that is perfectly valid.
 */
export function typeNumber(name: string): number {
  const upper = name.toUpperCase();
  const known = (RR_TYPE as Record<string, number>)[upper];
  if (known !== undefined) return known;
  const generic = /^TYPE(\d{1,5})$/.exec(upper);
  if (generic) {
    const value = Number(generic[1]);
    if (value <= 65535) return value;
  }
  throw new Error(`unknown RR type ${JSON.stringify(name)}`);
}

/** DNSSEC algorithm numbers (IANA registry). */
export const ALGORITHM = {
  RSASHA1: 5,
  RSASHA1_NSEC3_SHA1: 7,
  RSASHA256: 8,
  RSASHA512: 10,
  ECDSAP256SHA256: 13,
  ECDSAP384SHA384: 14,
  ED25519: 15,
  ED448: 16,
} as const;

const ALGORITHM_BY_NUMBER = new Map<number, string>(
  Object.entries(ALGORITHM).map(([name, num]) => [num, name])
);

export function algorithmName(algorithm: number): string {
  return ALGORITHM_BY_NUMBER.get(algorithm) ?? `ALG${algorithm}`;
}

/**
 * The algorithms this lab actually verifies, and nothing else.
 *
 * 8 is here because the DNS root signs with it: without RSASHA256 the pinned
 * real-world chain could not be validated from its own trust anchor, and the
 * lab would be teaching against a chain it had quietly replaced. 13 and 15 are
 * the two the demo zone signs with.
 *
 * Everything absent from this set — 5, 7, 10, 14, 16 — is a REAL algorithm
 * this lab has not implemented, which is a different statement from "invalid",
 * and the validator reports it as its own outcome (`ALG_UNSUPPORTED`) instead
 * of folding it into a signature failure.
 */
export const SUPPORTED_ALGORITHMS: ReadonlySet<number> = new Set([
  ALGORITHM.RSASHA256,
  ALGORITHM.ECDSAP256SHA256,
  ALGORITHM.ED25519,
]);

/** DS digest types (IANA registry). 1 and 2 are what the real chain uses. */
export const DIGEST_TYPE = { SHA1: 1, SHA256: 2, SHA384: 4 } as const;

export function digestTypeName(digestType: number): string {
  if (digestType === DIGEST_TYPE.SHA1) return 'SHA-1';
  if (digestType === DIGEST_TYPE.SHA256) return 'SHA-256';
  if (digestType === DIGEST_TYPE.SHA384) return 'SHA-384';
  return `DIGEST${digestType}`;
}

export const SUPPORTED_DIGEST_TYPES: ReadonlySet<number> = new Set([
  DIGEST_TYPE.SHA1,
  DIGEST_TYPE.SHA256,
  DIGEST_TYPE.SHA384,
]);

/** DNSKEY flag bits (RFC 4034 section 2.1.1). */
export const DNSKEY_FLAG_ZONE = 0x0100;
export const DNSKEY_FLAG_SEP = 0x0001;

/** IN is the only class this lab handles; CH and HS never appear in DNSSEC. */
export const CLASS_IN = 1;

/**
 * One resource record. `rdata` is the wire-format RDATA — the exact octets
 * that go into a signature — and never a re-rendering of it.
 */
export interface ResourceRecord {
  readonly name: Labels;
  readonly type: number;
  readonly class: number;
  readonly ttl: number;
  readonly rdata: Uint8Array;
}

/**
 * An RRset: every record sharing owner name, class, and type. DNSSEC signs
 * RRsets, never individual records, which is why nothing downstream accepts a
 * lone `ResourceRecord` to verify.
 */
export interface RRset {
  readonly name: Labels;
  readonly type: number;
  readonly class: number;
  /** The TTL as served. The ORIGINAL TTL from the RRSIG is what gets signed. */
  readonly ttl: number;
  readonly rdatas: readonly Uint8Array[];
}

export function rrsetKey(name: Labels, type: number, klass: number): string {
  return `${presentName(name).toLowerCase()}|${klass}|${type}`;
}

/** Group loose records into RRsets, keyed by owner/class/type. */
export function toRRsets(records: readonly ResourceRecord[]): RRset[] {
  const groups = new Map<string, { head: ResourceRecord; rdatas: Uint8Array[] }>();
  for (const rr of records) {
    const key = rrsetKey(rr.name, rr.type, rr.class);
    const existing = groups.get(key);
    if (existing) existing.rdatas.push(rr.rdata);
    else groups.set(key, { head: rr, rdatas: [rr.rdata] });
  }
  return Array.from(groups.values(), ({ head, rdatas }) => ({
    name: head.name,
    type: head.type,
    class: head.class,
    ttl: head.ttl,
    rdatas,
  }));
}
