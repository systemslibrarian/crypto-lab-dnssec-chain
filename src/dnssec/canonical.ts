/**
 * Exactly which bytes a DNSSEC signature covers.
 *
 * This is the single most unforgiving thing in DNSSEC and the place where a
 * validator that "looks right" quietly fails: everything downstream — the
 * pinned root-to-zone chain, every RFC known-answer test, every signature this
 * lab makes — reduces to whether these bytes are assembled the way RFC 4034
 * section 3.1.8.1 says. One wrong TTL, one label left uppercase, one RDATA out
 * of order, and a perfectly valid signature reports as forged.
 *
 *     signature = sign( RRSIG_RDATA | RR(1) | RR(2) | ... )
 *
 * where RRSIG_RDATA is the RRSIG's own RDATA with the signature field removed,
 * and each
 *
 *     RR(i) = owner | type | class | ORIGINAL TTL | RDATA length | RDATA
 *
 * with the records sorted into canonical RDATA order and the owner name in
 * canonical form. The TTL is deliberately NOT the TTL the record arrived with:
 * a TTL counts down as an answer is cached, so signing the served value would
 * invalidate every signature the moment it passed through a resolver. The
 * ORIGINAL TTL travels inside the RRSIG for exactly this reason, and this
 * module uses it — the served TTL is never signed.
 */

import { compareBytes, concatBytes, u16, u32 } from '../dns/codec.ts';
import { canonicalWire, rrsigLabelCount, type Labels } from '../dns/name.ts';
import { decodeRrsig, encodeRrsigPrefix, type RrsigRdata } from '../dns/rdata.ts';
import { RR_TYPE, type RRset } from '../dns/types.ts';

/**
 * RR types whose embedded domain names are down-cased in canonical RDATA
 * (RFC 4034 section 6.2, item 3), restricted to the types this lab handles.
 *
 * NSEC is deliberately ABSENT. RFC 4034 listed it; RFC 6840 section 5.1
 * corrects that — "DNS names in the RDATA section of NSEC resource records are
 * not converted to lowercase. DNS names in the RDATA section of RRSIG
 * resource records are converted to lowercase." Following the older text
 * breaks validation against any signer that follows current practice, which is
 * all of them.
 */
const DOWNCASED_RDATA_TYPES: ReadonlySet<number> = new Set([
  RR_TYPE.NS,
  RR_TYPE.CNAME,
  RR_TYPE.SOA,
  RR_TYPE.MX,
  RR_TYPE.RRSIG,
]);

/** Re-emit an embedded name from RDATA in canonical (down-cased) form. */
function downcaseNameAt(rdata: Uint8Array, offset: number): { bytes: Uint8Array; next: number } {
  const labels: Uint8Array[] = [];
  let i = offset;
  for (;;) {
    const length = rdata[i];
    if (length === undefined) throw new Error('name runs past the end of the RDATA');
    if (length === 0) return { bytes: canonicalWire(labels), next: i + 1 };
    if (length >= 0xc0) throw new Error('compressed name in RDATA');
    labels.push(rdata.subarray(i + 1, i + 1 + length));
    i += 1 + length;
  }
}

/**
 * Canonical RDATA form (RFC 4034 section 6.2).
 *
 * For every type outside the down-casing list the wire RDATA is already
 * canonical and is returned untouched — which matters, because "canonicalize"
 * must never mean "re-serialize": re-rendering DNSKEY or DS RDATA through a
 * printer and a parser would be a chance to change a byte the signer signed.
 */
export function canonicalRdata(type: number, rdata: Uint8Array): Uint8Array {
  if (!DOWNCASED_RDATA_TYPES.has(type)) return rdata;
  switch (type) {
    case RR_TYPE.NS:
    case RR_TYPE.CNAME: {
      return downcaseNameAt(rdata, 0).bytes;
    }
    case RR_TYPE.MX: {
      const name = downcaseNameAt(rdata, 2);
      return concatBytes(rdata.subarray(0, 2), name.bytes);
    }
    case RR_TYPE.SOA: {
      const mname = downcaseNameAt(rdata, 0);
      const rname = downcaseNameAt(rdata, mname.next);
      return concatBytes(mname.bytes, rname.bytes, rdata.subarray(rname.next));
    }
    case RR_TYPE.RRSIG: {
      const sig = decodeRrsig(rdata);
      return concatBytes(encodeRrsigPrefix(sig), sig.signature);
    }
    default:
      return rdata;
  }
}

/**
 * The owner name that goes into RR(i).
 *
 * Normally the RRset's own owner. But when the RRSIG's Labels field counts
 * FEWER labels than the owner name has, the answer was synthesized from a
 * wildcard, and RFC 4034 section 3.1.8.1 says the name signed was
 * `*.<the remaining suffix>` — the wildcard as it exists in the zone, not the
 * name that was asked for. Reconstructing the asked-for name instead is a
 * classic validator bug: every wildcard answer in the zone then reads as
 * forged.
 */
export function signedOwnerName(owner: Labels, rrsigLabels: number): Labels {
  const actual = rrsigLabelCount(owner);
  if (rrsigLabels > actual) {
    throw new Error(`RRSIG labels=${rrsigLabels} exceeds the owner name's ${actual} labels`);
  }
  if (rrsigLabels === actual) return owner;
  const suffix = owner.slice(owner.length - rrsigLabels);
  return [Uint8Array.of(0x2a), ...suffix]; // '*'
}

/** Did this answer come from a wildcard? Reported to the learner, not hidden. */
export function isWildcardExpansion(owner: Labels, rrsigLabels: number): boolean {
  return rrsigLabels < rrsigLabelCount(owner);
}

export interface SignedDataParts {
  /** The RRSIG RDATA minus the signature field. */
  readonly rrsigPrefix: Uint8Array;
  /** One entry per record, in canonical order, each already fully encoded. */
  readonly records: readonly { readonly bytes: Uint8Array; readonly rdata: Uint8Array }[];
  /** The concatenation actually handed to the verifier. */
  readonly signedData: Uint8Array;
  /** The owner name used, after any wildcard reconstruction. */
  readonly owner: Labels;
}

/**
 * Build the byte string RFC 4034 section 3.1.8.1 signs, and hand back its
 * parts as well as the whole.
 *
 * The parts are returned because this lab's point is that the learner can SEE
 * the construction: the UI lays out the RRSIG prefix and each canonicalized
 * record as separate runs of bytes, so "the signature covers these exact
 * octets" is something shown rather than asserted.
 */
export function buildSignedData(rrset: RRset, sig: RrsigRdata): SignedDataParts {
  const owner = signedOwnerName(rrset.name, sig.labels);
  const ownerWire = canonicalWire(owner);
  const rrsigPrefix = encodeRrsigPrefix(sig);

  // Section 6.3: sort by canonical RDATA, as unsigned octet strings.
  const canonicalRdatas = rrset.rdatas
    .map((rdata) => canonicalRdata(rrset.type, rdata))
    .sort(compareBytes);

  const records = canonicalRdatas.map((rdata) => ({
    rdata,
    bytes: concatBytes(
      ownerWire,
      u16(rrset.type),
      u16(rrset.class),
      u32(sig.originalTtl), // the ORIGINAL TTL, never the served one
      u16(rdata.length),
      rdata
    ),
  }));

  return {
    rrsigPrefix,
    records,
    owner,
    signedData: concatBytes(rrsigPrefix, ...records.map((r) => r.bytes)),
  };
}

/**
 * The bytes hashed to make a DS record (RFC 4034 section 5.1.4):
 *
 *     digest = H( DNSKEY owner name in canonical form | DNSKEY RDATA )
 *
 * The owner name is the child zone's apex, which is why a DS lifted from one
 * zone and pasted into another never matches: the name is inside the hash.
 */
export function dsPreimage(ownerName: Labels, dnskeyRdata: Uint8Array): Uint8Array {
  return concatBytes(canonicalWire(ownerName), dnskeyRdata);
}
