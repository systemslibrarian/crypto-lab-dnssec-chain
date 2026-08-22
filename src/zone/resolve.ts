/**
 * An authoritative server for the in-page zone, and a validating resolver in
 * front of it.
 *
 * The "server" is local — there is no network here — but everything it hands
 * back is real: real RRsets, real RRSIGs made by `sign.ts`, real NSEC or NSEC3
 * denial proofs built from the zone's actual contents. The resolver then
 * verifies them with the same code that verifies the pinned root-to-Cloudflare
 * chain. Nothing takes a shortcut because the two halves are in the same tab.
 *
 * This is what makes the zone walk a real walk. The walker does not read the
 * zone; it asks questions and reads the signed answers, exactly as an outsider
 * with no access to the zone file would.
 */

import { nameEquals, type Labels } from '../dns/name.ts';
import { decodeNsec } from '../dns/rdata.ts';
import { RR_TYPE } from '../dns/types.ts';
import { validateChain, type ChainInput, type ChainResult, type ZoneEvidence } from '../dnssec/chain.ts';
import { nsecCovers, proveNoData, proveNxdomain, toNsecRecord, type DenialProof, type NsecRecord } from '../dnssec/nsec.ts';
import {
  nsec3Hash,
  proveNsec3NoData,
  proveNsec3Nxdomain,
  toNsec3Record,
  type Nsec3Denial,
  type Nsec3Record,
} from '../dnssec/nsec3.ts';
import { fromBase32Hex } from '../dns/codec.ts';
import { ROOT, TLD, UNSIGNED_CHILD, ZONE, type DemoHierarchy } from './demo.ts';
import { lookup, type SignedRrset, type SignedZone } from './sign.ts';

export type Rcode = 'NOERROR' | 'NXDOMAIN';

export interface ZoneResponse {
  readonly rcode: Rcode;
  readonly qname: Labels;
  readonly qtype: number;
  /** The answer RRset, when there is one. */
  readonly answer: SignedRrset | null;
  /** The denial records the server offers, each with its own signature. */
  readonly authority: readonly SignedRrset[];
  /** Which kind of denial, so the UI can label it. */
  readonly denialKind: 'none' | 'nodata' | 'nxdomain';
}

const signedFor = (zone: SignedZone, owner: Labels, type: number): SignedRrset | null =>
  lookup(zone, owner, type);

/**
 * Answer one query against a signed zone.
 *
 * The three cases are the three a real server has, and each hands back
 * different evidence:
 *
 *  - the name and type exist: the RRset and its signature;
 *  - the name exists, the type does not (NODATA): the record that ASSERTS the
 *    name, whose type bit map is a complete inventory of what the name has;
 *  - the name does not exist (NXDOMAIN): the record covering the gap the name
 *    would fall in, plus one covering the wildcard that could have answered.
 *
 * The second and third are where the zone leaks. Nothing about that is a bug
 * being demonstrated — it is the proof doing exactly what it was designed to.
 */
export function queryZone(zone: SignedZone, qname: Labels, qtype: number): ZoneResponse {
  const exists = zone.owners.some((o) => nameEquals(o, qname));
  const answer = signedFor(zone, qname, qtype);

  if (answer) {
    return { rcode: 'NOERROR', qname, qtype, answer, authority: [], denialKind: 'none' };
  }

  const soa = signedFor(zone, zone.spec.apex, RR_TYPE.SOA);
  const authority: SignedRrset[] = soa ? [soa] : [];

  if (zone.spec.denial.kind === 'nsec') {
    if (exists) {
      const nsec = signedFor(zone, qname, RR_TYPE.NSEC);
      if (nsec) authority.push(nsec);
      return { rcode: 'NOERROR', qname, qtype, answer: null, authority, denialKind: 'nodata' };
    }
    const records = zone.denialRecords.filter((r) => r.rrset.type === RR_TYPE.NSEC);
    const covering = records.find((r) =>
      r.rrset.rdatas.some((rdata) => nsecCovers(toNsecRecord(r.rrset.name, rdata), qname))
    );
    if (covering) authority.push(covering);
    const wildcard: Labels = [Uint8Array.of(0x2a), ...zone.spec.apex];
    const wildcardCover = records.find((r) =>
      r.rrset.rdatas.some((rdata) => nsecCovers(toNsecRecord(r.rrset.name, rdata), wildcard))
    );
    if (wildcardCover && wildcardCover !== covering) authority.push(wildcardCover);
    return { rcode: 'NXDOMAIN', qname, qtype, answer: null, authority, denialKind: 'nxdomain' };
  }

  // NSEC3: the record for a name is owned by its hash, not by the name.
  const params = zone.spec.denial.params;
  const records = zone.denialRecords.filter((r) => r.rrset.type === RR_TYPE.NSEC3);
  const asRecord = (r: SignedRrset, rdata: Uint8Array): Nsec3Record | null => {
    const first = r.rrset.name[0];
    if (!first) return null;
    return toNsec3Record(r.rrset.name, rdata, fromBase32Hex(new TextDecoder().decode(first)));
  };
  const findByHash = (hash: Uint8Array, want: 'match' | 'cover'): SignedRrset | undefined =>
    records.find((r) =>
      r.rrset.rdatas.some((rdata) => {
        const record = asRecord(r, rdata);
        if (!record) return false;
        return want === 'match' ? hashEquals(record.ownerHash, hash) : coversHash(record, hash);
      })
    );

  if (exists) {
    const match = findByHash(nsec3Hash(qname, params), 'match');
    if (match) authority.push(match);
    return { rcode: 'NOERROR', qname, qtype, answer: null, authority, denialKind: 'nodata' };
  }

  // The closest encloser is the deepest ancestor of the query that the zone
  // actually holds, and the "next closer" name is one label below it. In a
  // flat zone that is always the apex, but deriving it rather than assuming it
  // is what keeps this server honest if a name with more labels is added.
  const encloser = closestEncloserIn(zone, qname);
  const apexMatch = findByHash(nsec3Hash(encloser, params), 'match');
  if (apexMatch) authority.push(apexMatch);
  const nextCloser = qname.slice(qname.length - encloser.length - 1);
  const cover = findByHash(nsec3Hash(nextCloser, params), 'cover');
  if (cover && !authority.includes(cover)) authority.push(cover);
  const wildcard: Labels = [Uint8Array.of(0x2a), ...encloser];
  const wildcardCover = findByHash(nsec3Hash(wildcard, params), 'cover');
  if (wildcardCover && !authority.includes(wildcardCover)) authority.push(wildcardCover);
  return { rcode: 'NXDOMAIN', qname, qtype, answer: null, authority, denialKind: 'nxdomain' };
}

/** The deepest ancestor of `name` that this zone actually holds. */
function closestEncloserIn(zone: SignedZone, name: Labels): Labels {
  for (let strip = 1; strip <= name.length - zone.spec.apex.length; strip += 1) {
    const candidate = name.slice(strip);
    if (zone.owners.some((o) => nameEquals(o, candidate))) return candidate;
  }
  return zone.spec.apex;
}

function hashEquals(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function coversHash(record: Nsec3Record, hash: Uint8Array): boolean {
  const cmp = (x: Uint8Array, y: Uint8Array): number => {
    const shared = Math.min(x.length, y.length);
    for (let i = 0; i < shared; i += 1) if (x[i] !== y[i]) return x[i]! - y[i]!;
    return x.length - y.length;
  };
  const vsOwner = cmp(hash, record.ownerHash);
  const vsNext = cmp(hash, record.rdata.nextHashedOwner);
  const wraps = cmp(record.rdata.nextHashedOwner, record.ownerHash) <= 0;
  if (wraps) return vsOwner > 0 || vsNext < 0;
  return vsOwner > 0 && vsNext < 0;
}

/**
 * Verify a response's denial proof, whichever kind it is.
 *
 * The records come from `response.authority` -- from the ANSWER -- and never
 * from the zone's own chain. That distinction is the whole honesty of the walk
 * panel: a validator judges what it was sent, so a response that omits,
 * truncates or substitutes its denial records has to FAIL here. Rebuilding the
 * record set from the zone file instead would make the verdict a statement
 * about the zone rather than about the answer, and would hide any bug in the
 * server's denial construction behind a permanent green tick.
 */
export function checkDenial(
  zone: SignedZone,
  response: ZoneResponse
): DenialProof | Nsec3Denial | null {
  if (response.denialKind === 'none') return null;
  const apex = zone.spec.apex;
  if (zone.spec.denial.kind === 'nsec') {
    const records = nsecRecordsIn(response.authority);
    return response.denialKind === 'nodata'
      ? proveNoData(records, response.qname, response.qtype, apex)
      : proveNxdomain(records, response.qname, apex);
  }
  const records = nsec3RecordsIn(response.authority);
  const params = zone.spec.denial.params;
  return response.denialKind === 'nodata'
    ? proveNsec3NoData(records, response.qname, response.qtype, params, apex)
    : proveNsec3Nxdomain(records, response.qname, apex, params);
}

/** The NSEC records an answer actually carried. */
export function nsecRecordsIn(authority: readonly SignedRrset[]): NsecRecord[] {
  return authority
    .filter((r) => r.rrset.type === RR_TYPE.NSEC)
    .flatMap((r) => r.rrset.rdatas.map((rdata) => toNsecRecord(r.rrset.name, rdata)));
}

/** The NSEC3 records an answer actually carried. */
export function nsec3RecordsIn(authority: readonly SignedRrset[]): Nsec3Record[] {
  return authority
    .filter((r) => r.rrset.type === RR_TYPE.NSEC3)
    .flatMap((r) =>
      r.rrset.rdatas.map((rdata) => {
        const first = r.rrset.name[0];
        if (!first) throw new Error('NSEC3 owner name has no labels');
        return toNsec3Record(r.rrset.name, rdata, fromBase32Hex(new TextDecoder().decode(first)));
      })
    );
}

/** The NSEC a denial hands back, for the walker to read the next name off. */
export function nextNameFrom(response: ZoneResponse): Labels | null {
  for (const record of response.authority) {
    if (record.rrset.type !== RR_TYPE.NSEC) continue;
    const rdata = record.rrset.rdatas[0];
    if (!rdata) continue;
    return decodeNsec(rdata).nextName;
  }
  return null;
}

/** The type bit map a denial hands back, which inventories the named owner. */
export function typesFrom(response: ZoneResponse): { owner: Labels; types: readonly number[] } | null {
  for (const record of response.authority) {
    if (record.rrset.type !== RR_TYPE.NSEC) continue;
    const rdata = record.rrset.rdatas[0];
    if (!rdata) continue;
    return { owner: record.rrset.name, types: decodeNsec(rdata).types };
  }
  return null;
}

// ── The resolver ────────────────────────────────────────────────────────────

export interface DemoResolution {
  readonly input: ChainInput;
  readonly result: ChainResult;
  readonly response: ZoneResponse | null;
  readonly denial: DenialProof | Nsec3Denial | null;
}

export interface ResolveOptions {
  readonly now: number;
  /** Delegate to an unsigned child instead of the signed one. */
  readonly target?: 'signed' | 'unsigned';
}

/**
 * Resolve a name inside the demo hierarchy, validating every link.
 *
 * The `unsigned` target is the INSECURE act: `example.` delegates to
 * `unsigned.example.` with no DS, and proves it with a signed NSEC. Every
 * check still passes; the chain simply ends.
 */
export async function resolveInDemo(
  hierarchy: DemoHierarchy,
  qname: Labels,
  qtype: number,
  options: ResolveOptions
): Promise<DemoResolution> {
  const unsigned = options.target === 'unsigned';
  const zones: ZoneEvidence[] = [
    evidenceFor(hierarchy.root, ROOT, 'root zone', null, []),
    evidenceFor(hierarchy.tld, TLD, 'example.', hierarchy.root, [
      signedOrEmpty(hierarchy.root, TLD, RR_TYPE.DS),
    ]),
  ];

  if (unsigned) {
    // The parent's NSEC at the delegation, WITH its signature. The chain
    // verifies that signature before it will accept the proof -- an
    // unauthenticated denial must not be able to end a chain at INSECURE.
    const denial = lookup(hierarchy.tld, UNSIGNED_CHILD, RR_TYPE.NSEC);
    zones.push({
      zone: UNSIGNED_CHILD,
      title: 'unsigned.example.',
      dnskeys: null,
      dnskeyRrsigs: [],
      ds: null,
      dsRrsigs: [],
      noDsProof: {
        kind: 'nsec',
        records: denial ? nsecRecordsIn([denial]) : [],
        rrsets: denial ? [{ rrset: denial.rrset, rrsigs: denial.rrsigs }] : [],
      },
    });
  } else {
    const ds = signedOrEmpty(hierarchy.tld, ZONE, RR_TYPE.DS);
    zones.push({
      zone: ZONE,
      title: 'demo.example.',
      dnskeys: hierarchy.zone.dnskey.rrset,
      dnskeyRrsigs: hierarchy.zone.dnskey.rrsigs,
      ds: ds?.rrset ?? null,
      dsRrsigs: ds?.rrsigs ?? [],
    });
  }

  const response = unsigned ? null : queryZone(hierarchy.zone, qname, qtype);
  const answer =
    response?.answer !== null && response?.answer !== undefined
      ? { rrset: response.answer.rrset, rrsigs: response.answer.rrsigs }
      : null;

  const input: ChainInput = {
    anchors: [{ label: 'configured root anchor', rdata: hierarchy.anchorDs }],
    zones,
    answer,
    now: options.now,
  };
  const result = await validateChain(input);
  return {
    input,
    result,
    response,
    denial: response ? checkDenial(hierarchy.zone, response) : null,
  };
}

function evidenceFor(
  zone: SignedZone,
  name: Labels,
  title: string,
  parent: SignedZone | null,
  dsCandidates: readonly (SignedRrset | null)[]
): ZoneEvidence {
  const ds = dsCandidates.find((d): d is SignedRrset => d !== null) ?? null;
  void parent;
  return {
    zone: name,
    title,
    dnskeys: zone.dnskey.rrset,
    dnskeyRrsigs: zone.dnskey.rrsigs,
    ds: ds?.rrset ?? null,
    dsRrsigs: ds?.rrsigs ?? [],
  };
}

function signedOrEmpty(zone: SignedZone, owner: Labels, type: number): SignedRrset | null {
  return lookup(zone, owner, type);
}
