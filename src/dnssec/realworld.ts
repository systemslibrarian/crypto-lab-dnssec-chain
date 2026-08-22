/**
 * The pinned capture, assembled into the three things it can prove.
 *
 * All of it is real: real keys, real signatures, real denial proofs, captured
 * from the servers that are authoritative for the root, `.com` and
 * `cloudflare.com`. Nothing is synthesized, and nothing is fetched at run
 * time.
 *
 *  1. SECURE — the full chain, root trust anchor down to an A record.
 *  2. INSECURE — `.com` signing a statement that it holds no DS for
 *     `google.com`, so the chain ends there rather than breaking.
 *  3. Online minimally covering denial — Cloudflare answering a name that does
 *     not exist with an NSEC it made up for that query, covering as little as
 *     possible.
 */

import { fromBase32Hex } from '../dns/codec.ts';
import { presentName, type Labels } from '../dns/name.ts';
import { decodeNsec3 } from '../dns/rdata.ts';
import { RR_TYPE, toRRsets, type ResourceRecord, type RRset } from '../dns/types.ts';
import { PINNED_ZONES, PINNED_CHAIN, rrsetOf, rrsigsFor, section, type PinnedChain } from '../vectors/pinned.ts';
import { ROOT_TRUST_ANCHORS } from '../vectors/rfc.ts';
import { fromHex } from '../dns/codec.ts';
import { encodeDs } from '../dns/rdata.ts';
import type { AnchorDs, ChainInput, ZoneEvidence } from './chain.ts';
import { toNsecRecord, type NsecRecord } from './nsec.ts';
import { paramsOf, toNsec3Record, type Nsec3Params, type Nsec3Record } from './nsec3.ts';

/** The IANA anchors, rendered as DS RDATA so the same code path handles them. */
export const ANCHORS: readonly AnchorDs[] = ROOT_TRUST_ANCHORS.map((a) => ({
  label: `${a.label} (tag ${a.keyTag}, valid from ${a.validFrom})`,
  rdata: encodeDs({
    keyTag: a.keyTag,
    algorithm: a.algorithm,
    digestType: a.digestType,
    digest: fromHex(a.digestHex),
  }),
}));

/**
 * Rebuild an NSEC3 record from a captured one.
 *
 * The owner's own hash is not in the RDATA — it is the FIRST LABEL of the
 * owner name, base32hex-encoded — so it has to be decoded back out. That
 * asymmetry (owner hash in the name, next hash in the RDATA) is a real source
 * of implementation bugs and is worth seeing spelled out.
 */
export function nsec3From(record: ResourceRecord): Nsec3Record {
  const first = record.name[0];
  if (!first) throw new Error('an NSEC3 owner name must have at least one label');
  const label = new TextDecoder().decode(first);
  return toNsec3Record(record.name, record.rdata, fromBase32Hex(label));
}

export function nsecFrom(record: ResourceRecord): NsecRecord {
  return toNsecRecord(record.name, record.rdata);
}

function requireRrset(records: readonly ResourceRecord[], owner: Labels, type: number): RRset {
  const found = rrsetOf(records, owner, type);
  if (!found) {
    throw new Error(`pinned capture has no ${type} RRset at ${presentName(owner)}`);
  }
  return found;
}

export interface RealWorldOptions {
  /** Validation instant. Defaults to the capture instant. */
  readonly now?: number;
  /**
   * Optional surgery on the captured evidence, for the break-it-yourself acts.
   * Applied to the assembled chain, never to the committed capture.
   */
  readonly mutate?: (input: ChainInput) => ChainInput;
}

/** Root -> .com -> cloudflare.com, ending at the A RRset. */
export function buildSecureChain(
  chain: PinnedChain = PINNED_CHAIN,
  options: RealWorldOptions = {}
): ChainInput {
  const rootDnskey = section(chain, 'root-dnskey').answer;
  const comDs = section(chain, 'root-ds-for-com').answer;
  const comDnskey = section(chain, 'com-dnskey').answer;
  const cfDs = section(chain, 'com-ds-for-cloudflare').answer;
  const cfDnskey = section(chain, 'cloudflare-dnskey').answer;
  const cfA = section(chain, 'cloudflare-a').answer;

  const zones: ZoneEvidence[] = [
    {
      zone: PINNED_ZONES.root,
      title: 'root zone',
      dnskeys: requireRrset(rootDnskey, PINNED_ZONES.root, RR_TYPE.DNSKEY),
      dnskeyRrsigs: rrsigsFor(rootDnskey, PINNED_ZONES.root, RR_TYPE.DNSKEY),
      ds: null,
      dsRrsigs: [],
    },
    {
      zone: PINNED_ZONES.com,
      title: 'com',
      dnskeys: requireRrset(comDnskey, PINNED_ZONES.com, RR_TYPE.DNSKEY),
      dnskeyRrsigs: rrsigsFor(comDnskey, PINNED_ZONES.com, RR_TYPE.DNSKEY),
      ds: requireRrset(comDs, PINNED_ZONES.com, RR_TYPE.DS),
      dsRrsigs: rrsigsFor(comDs, PINNED_ZONES.com, RR_TYPE.DS),
    },
    {
      zone: PINNED_ZONES.cloudflare,
      title: 'cloudflare.com',
      dnskeys: requireRrset(cfDnskey, PINNED_ZONES.cloudflare, RR_TYPE.DNSKEY),
      dnskeyRrsigs: rrsigsFor(cfDnskey, PINNED_ZONES.cloudflare, RR_TYPE.DNSKEY),
      ds: requireRrset(cfDs, PINNED_ZONES.cloudflare, RR_TYPE.DS),
      dsRrsigs: rrsigsFor(cfDs, PINNED_ZONES.cloudflare, RR_TYPE.DS),
    },
  ];

  const input: ChainInput = {
    anchors: ANCHORS,
    zones,
    answer: {
      rrset: requireRrset(cfA, PINNED_ZONES.cloudflare, RR_TYPE.A),
      rrsigs: rrsigsFor(cfA, PINNED_ZONES.cloudflare, RR_TYPE.A),
    },
    now: options.now ?? chain.capturedAt,
  };
  return options.mutate ? options.mutate(input) : input;
}

/**
 * Root -> .com -> google.com, where `.com` proves it holds no DS.
 *
 * The evidence is `.com`'s real answer to a DS query for a domain that has
 * never been signed. Note what is signed: an NSEC3 covering the gap the name
 * would fall in, with the Opt-Out flag set. `.com` is not saying "nothing is
 * here" — it is saying "I am not vouching for anything here", which is a
 * weaker and entirely legitimate statement.
 */
export function buildInsecureChain(
  chain: PinnedChain = PINNED_CHAIN,
  options: RealWorldOptions = {}
): ChainInput {
  const base = buildSecureChain(chain, options);
  const denial = section(chain, 'com-ds-for-google-none').authority;
  const nsec3Records = denial.filter((r) => r.type === RR_TYPE.NSEC3).map(nsec3From);
  const first = nsec3Records[0];
  if (!first) throw new Error('the captured no-DS answer carries no NSEC3 records');
  const params: Nsec3Params = paramsOf(first);

  // Each captured NSEC3 with the RRSIG `.com` actually sent for it. The chain
  // verifies these under `.com`'s keys before it will read the proof, so the
  // INSECURE verdict rests on a signature rather than on an assertion.
  const rrsets = toRRsets(denial.filter((r) => r.type === RR_TYPE.NSEC3)).map((rrset) => ({
    rrset,
    rrsigs: rrsigsFor(denial, rrset.name, RR_TYPE.NSEC3),
  }));

  const zones: ZoneEvidence[] = [
    base.zones[0]!,
    base.zones[1]!,
    {
      zone: PINNED_ZONES.google,
      title: 'google.com',
      dnskeys: null,
      dnskeyRrsigs: [],
      ds: null,
      dsRrsigs: [],
      noDsProof: { kind: 'nsec3', records: nsec3Records, rrsets, params },
    },
  ];
  return { ...base, zones, answer: null };
}

export interface DenialEvidence {
  readonly queried: Labels;
  readonly zone: Labels;
  readonly nsec: readonly NsecRecord[];
  /** The RRSIGs over each NSEC, so the proof itself can be verified. */
  readonly records: readonly ResourceRecord[];
  readonly rcodeIsNoError: boolean;
}

/**
 * Cloudflare's answer for a name that does not exist.
 *
 * Read the captured section and two things stand out. The status is NOERROR,
 * not NXDOMAIN — the server is answering "this name exists but has no A
 * record" rather than "this name does not exist". And the NSEC's next name is
 * the queried name with a single NUL octet prepended as a new label, which is
 * the smallest possible step forward in canonical order: RFC 4470's increment
 * function, applied to the query rather than to the zone.
 *
 * The effect is that the denial covers a gap containing nothing but the name
 * that was asked about. There is no neighbour to learn, so there is nothing to
 * walk to. The cost is that the signature has to be made per query, which
 * means a signing key on an Internet-facing server — a real trade, not a free
 * upgrade, and RFC 4470 says so in its own security considerations.
 */
export function buildBlackLieDenial(chain: PinnedChain = PINNED_CHAIN): DenialEvidence {
  const captured = section(chain, 'cloudflare-nxdomain');
  const nsecRecords = captured.authority.filter((r) => r.type === RR_TYPE.NSEC);
  // The response code is read from THIS section and no further: slicing only
  // from the section marker would run on into every later section, so a
  // NOERROR anywhere below would answer for this one.
  const start = chain.rawText.indexOf(';; ==== cloudflare-nxdomain');
  const end = chain.rawText.indexOf(';; ====', start + 1);
  const body = chain.rawText.slice(start, end === -1 ? undefined : end);
  return {
    queried: PINNED_ZONES.nxdomain,
    zone: PINNED_ZONES.cloudflare,
    nsec: nsecRecords.map(nsecFrom),
    records: captured.authority,
    rcodeIsNoError: /status: NOERROR/.test(body),
  };
}

/** The Opt-Out flag as `.com` actually sets it, read off the wire. */
export function capturedOptOutFlag(chain: PinnedChain = PINNED_CHAIN): boolean {
  const first = section(chain, 'com-ds-for-google-none').authority.find((r) => r.type === RR_TYPE.NSEC3);
  return first ? (decodeNsec3(first.rdata).flags & 0x01) !== 0 : false;
}
