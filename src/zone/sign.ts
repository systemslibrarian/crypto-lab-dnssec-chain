/**
 * Signing a zone for real, in the browser.
 *
 * Everything the interactive acts operate on is produced here: real ECDSA and
 * Ed25519 signatures over the byte string RFC 4034 section 3.1.8.1 defines,
 * over records this page assembled, verified afterwards by the same validator
 * that verifies the pinned real-world chain. There is no separate "demo mode":
 * if a signature made here did not verify, the page would say so.
 *
 * Signing is what makes the break-it-yourself acts honest. A learner who
 * corrupts a DS digest and RE-SIGNS the parent zone produces a validly signed,
 * genuinely wrong delegation — which is the actual `DS_MISMATCH` failure, and
 * the actual mistake a registrar makes when a key is rolled and the DS is not.
 * Corrupting bytes without re-signing can only ever produce a broken
 * signature, and would teach that every DNSSEC failure looks the same.
 */

import { concatBytes } from '../dns/codec.ts';
import { canonicalWire, compareNames, presentName, rrsigLabelCount, type Labels } from '../dns/name.ts';
import {
  encodeDnskey,
  encodeDs,
  encodeNsec,
  encodeNsec3,
  encodeRrsig,
  type RrsigRdata,
} from '../dns/rdata.ts';
import {
  CLASS_IN,
  DNSKEY_FLAG_SEP,
  DNSKEY_FLAG_ZONE,
  RR_TYPE,
  toRRsets,
  type ResourceRecord,
  type RRset,
} from '../dns/types.ts';
import { buildSignedData } from '../dnssec/canonical.ts';
import { digest, sign, type SigningKey } from '../dnssec/crypto.ts';
import { keyTag } from '../dnssec/keytag.ts';
import { nsec3Hash, type Nsec3Params } from '../dnssec/nsec3.ts';
import { toBase32Hex } from '../dns/codec.ts';

/** How a zone proves that a name does not exist. */
export type DenialStyle =
  | { readonly kind: 'nsec' }
  | { readonly kind: 'nsec3'; readonly params: Nsec3Params };

export interface KeyRole {
  readonly key: SigningKey;
  /** Zone Key is required to sign; SEP is a hint that marks a KSK. */
  readonly flags: number;
  readonly rdata: Uint8Array;
  readonly tag: number;
}

export function keyRole(key: SigningKey, isSep: boolean): KeyRole {
  const flags = DNSKEY_FLAG_ZONE | (isSep ? DNSKEY_FLAG_SEP : 0);
  const rdata = encodeDnskey({ flags, protocol: 3, algorithm: key.algorithm, publicKey: key.publicKey });
  return { key, flags, rdata, tag: keyTag(rdata) };
}

export interface ZoneSpec {
  readonly apex: Labels;
  /** Human title for the UI. */
  readonly title: string;
  readonly ksk: KeyRole;
  /** Every key that signs ordinary RRsets. More than one during a rollover. */
  readonly zsks: readonly KeyRole[];
  /** Extra DNSKEYs published but not signing — a pre-published successor. */
  readonly publishedOnly?: readonly KeyRole[];
  readonly ttl: number;
  readonly inception: number;
  readonly expiration: number;
  readonly denial: DenialStyle;
  /** Ordinary records: everything but DNSKEY, RRSIG, NSEC and NSEC3. */
  readonly records: readonly ResourceRecord[];
}

export interface SignedRrset {
  readonly rrset: RRset;
  readonly rrsigs: readonly Uint8Array[];
  readonly signedBy: readonly number[];
}

export interface SignedZone {
  readonly spec: ZoneSpec;
  /** Every RRset in the zone, signed, keyed by owner|class|type. */
  readonly signed: ReadonlyMap<string, SignedRrset>;
  readonly dnskey: SignedRrset;
  /** Every owner name in the zone, in canonical order. */
  readonly owners: readonly Labels[];
  /** The NSEC or NSEC3 chain, signed. */
  readonly denialRecords: readonly SignedRrset[];
  /** For NSEC3 only: hashed owner label to original name. */
  readonly hashedOwners: ReadonlyMap<string, Labels>;
}

const key = (name: Labels, type: number): string =>
  `${presentName(name).toLowerCase()}|${CLASS_IN}|${type}`;

/**
 * Produce the RRSIG for one RRset under one key.
 *
 * The signature field starts empty because it cannot cover itself: RFC 4034's
 * `RRSIG_RDATA` is precisely the RRSIG's own RDATA with that field removed.
 */
export interface SigningWindow {
  readonly apex: Labels;
  readonly inception: number;
  readonly expiration: number;
}

/**
 * Sign one RRset under an arbitrary signer name and window.
 *
 * Exposed because two of the break-it-yourself acts need a signature that is
 * cryptographically perfect and still unusable: one made by a NEIGHBOURING
 * zone's key (so the signer name does not match), and one made outside its own
 * validity window. Producing those by signing for real, rather than by
 * corrupting bytes, is what makes the validator's answer specific.
 */
export async function signRrsetAs(
  rrset: RRset,
  signer: KeyRole,
  window: SigningWindow
): Promise<Uint8Array> {
  const template: RrsigRdata = {
    typeCovered: rrset.type,
    algorithm: signer.key.algorithm,
    labels: rrsigLabelCount(rrset.name),
    originalTtl: rrset.ttl,
    expiration: window.expiration,
    inception: window.inception,
    keyTag: signer.tag,
    signerName: window.apex,
    signature: new Uint8Array(0),
  };
  const { signedData } = buildSignedData(rrset, template);
  return encodeRrsig({ ...template, signature: await sign(signer.key, signedData) });
}

async function signRrset(
  rrset: RRset,
  signer: KeyRole,
  spec: ZoneSpec
): Promise<{ rdata: Uint8Array; tag: number }> {
  const template: RrsigRdata = {
    typeCovered: rrset.type,
    algorithm: signer.key.algorithm,
    labels: rrsigLabelCount(rrset.name),
    originalTtl: rrset.ttl,
    expiration: spec.expiration,
    inception: spec.inception,
    keyTag: signer.tag,
    signerName: spec.apex,
    signature: new Uint8Array(0),
  };
  const { signedData } = buildSignedData(rrset, template);
  const signature = await sign(signer.key, signedData);
  return { rdata: encodeRrsig({ ...template, signature }), tag: signer.tag };
}

/**
 * Sign a whole zone: every RRset, the DNSKEY RRset, and the denial chain.
 *
 * The split of duties is the ordinary operational one. The KSK signs only the
 * DNSKEY RRset — it is the key the parent's DS points at, so it is the one
 * whose rotation costs a conversation with the registrar. The ZSK signs
 * everything else, which is why it can be rolled by the zone alone.
 */
export async function signZone(spec: ZoneSpec): Promise<SignedZone> {
  const signed = new Map<string, SignedRrset>();
  const hashedOwners = new Map<string, Labels>();

  // ── Ordinary RRsets, signed by every active ZSK ──────────────────────────
  const rrsets = toRRsets([...spec.records]);
  for (const rrset of rrsets) {
    const rrsigs: Uint8Array[] = [];
    const signedBy: number[] = [];
    for (const zsk of spec.zsks) {
      const { rdata, tag } = await signRrset(rrset, zsk, spec);
      rrsigs.push(rdata);
      signedBy.push(tag);
    }
    signed.set(key(rrset.name, rrset.type), { rrset, rrsigs, signedBy });
  }

  // ── The DNSKEY RRset, signed by the KSK ──────────────────────────────────
  const published = [spec.ksk, ...spec.zsks, ...(spec.publishedOnly ?? [])];
  const dnskeyRrset: RRset = {
    name: spec.apex,
    type: RR_TYPE.DNSKEY,
    class: CLASS_IN,
    ttl: spec.ttl,
    rdatas: published.map((k) => k.rdata),
  };
  const dnskeySig = await signRrset(dnskeyRrset, spec.ksk, spec);
  const dnskey: SignedRrset = {
    rrset: dnskeyRrset,
    rrsigs: [dnskeySig.rdata],
    signedBy: [dnskeySig.tag],
  };
  signed.set(key(spec.apex, RR_TYPE.DNSKEY), dnskey);

  // ── Owner names, in canonical order ──────────────────────────────────────
  const owners = dedupeNames([spec.apex, ...rrsets.map((r) => r.name)]).sort(compareNames);

  // ── The denial chain ─────────────────────────────────────────────────────
  const typesAt = (owner: Labels): number[] => {
    const types = new Set<number>();
    for (const rrset of rrsets) if (presentName(rrset.name) === presentName(owner)) types.add(rrset.type);
    if (presentName(owner) === presentName(spec.apex)) types.add(RR_TYPE.DNSKEY);
    types.add(RR_TYPE.RRSIG);
    types.add(spec.denial.kind === 'nsec' ? RR_TYPE.NSEC : RR_TYPE.NSEC3);
    if (spec.denial.kind === 'nsec3' && presentName(owner) === presentName(spec.apex)) {
      types.add(RR_TYPE.NSEC3PARAM);
    }
    return [...types].sort((a, b) => a - b);
  };

  const denialRecords: SignedRrset[] = [];

  if (spec.denial.kind === 'nsec') {
    // Each name points at the next in canonical order; the last wraps to the
    // apex, closing the ring. That wrap is what makes the chain a complete
    // statement about the zone rather than a list with an end.
    for (let i = 0; i < owners.length; i += 1) {
      const owner = owners[i]!;
      const next = owners[(i + 1) % owners.length]!;
      const rrset: RRset = {
        name: owner,
        type: RR_TYPE.NSEC,
        class: CLASS_IN,
        ttl: spec.ttl,
        rdatas: [encodeNsec({ nextName: next, types: typesAt(owner) })],
      };
      const rrsigs: Uint8Array[] = [];
      const signedBy: number[] = [];
      for (const zsk of spec.zsks) {
        const { rdata, tag } = await signRrset(rrset, zsk, spec);
        rrsigs.push(rdata);
        signedBy.push(tag);
      }
      const entry = { rrset, rrsigs, signedBy };
      denialRecords.push(entry);
      signed.set(key(owner, RR_TYPE.NSEC), entry);
    }
  } else {
    const { params } = spec.denial;
    // Sort by HASH, not by name. The whole point of NSEC3 is that the chain
    // order no longer follows the zone's own order, so neighbours in the chain
    // are unrelated names.
    const entries = owners
      .map((owner) => ({ owner, hash: nsec3Hash(owner, params) }))
      .sort((a, b) => compareBytesLocal(a.hash, b.hash));
    for (const entry of entries) {
      hashedOwners.set(toBase32Hex(entry.hash).toLowerCase(), entry.owner);
    }
    for (let i = 0; i < entries.length; i += 1) {
      const here = entries[i]!;
      const next = entries[(i + 1) % entries.length]!;
      const label = new TextEncoder().encode(toBase32Hex(here.hash).toLowerCase());
      const owner: Labels = [label, ...spec.apex];
      const rrset: RRset = {
        name: owner,
        type: RR_TYPE.NSEC3,
        class: CLASS_IN,
        ttl: spec.ttl,
        rdatas: [
          encodeNsec3({
            hashAlgorithm: params.hashAlgorithm,
            flags: 0,
            iterations: params.iterations,
            salt: params.salt,
            nextHashedOwner: next.hash,
            types: typesAt(here.owner),
          }),
        ],
      };
      const rrsigs: Uint8Array[] = [];
      const signedBy: number[] = [];
      for (const zsk of spec.zsks) {
        const { rdata, tag } = await signRrset(rrset, zsk, spec);
        rrsigs.push(rdata);
        signedBy.push(tag);
      }
      const record = { rrset, rrsigs, signedBy };
      denialRecords.push(record);
      signed.set(key(owner, RR_TYPE.NSEC3), record);
    }
  }

  return { spec, signed, dnskey, owners, denialRecords, hashedOwners };
}

/** The DS a parent would publish for this zone's KSK. */
export function dsForZone(zone: SignedZone, digestType: number): Uint8Array {
  const preimage = concatBytes(canonicalWire(zone.spec.apex), zone.spec.ksk.rdata);
  return encodeDs({
    keyTag: zone.spec.ksk.tag,
    algorithm: zone.spec.ksk.key.algorithm,
    digestType,
    digest: digest(digestType, preimage),
  });
}

function dedupeNames(names: readonly Labels[]): Labels[] {
  const seen = new Map<string, Labels>();
  for (const name of names) seen.set(presentName(name).toLowerCase(), name);
  return [...seen.values()];
}

function compareBytesLocal(a: Uint8Array, b: Uint8Array): number {
  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i += 1) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
}

/** Look one RRset up in a signed zone. */
export function lookup(zone: SignedZone, name: Labels, type: number): SignedRrset | null {
  return zone.signed.get(key(name, type)) ?? null;
}
