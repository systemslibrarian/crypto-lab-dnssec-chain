/**
 * NSEC3: the same denial proof, over hashes instead of names.
 *
 * NSEC3 sorts the SHA-1 hashes of the zone's names instead of the names
 * themselves, and signs the gaps between those. A denial still hands back the
 * neighbouring entries — the ring is just as walkable — but each entry is now
 * a 20-byte hash rather than a name, so the walk yields hashes and the
 * attacker has to invert them.
 *
 * State the effect in the direction that is actually true: NSEC3 REPLACES
 * TRIVIAL WALKING WITH AN OFFLINE GUESSING PROBLEM. It does not eliminate
 * enumeration. Every hash in the zone is handed out on request, the salt and
 * iteration count come with them, and cracking is then a purely offline
 * exercise against a namespace that is usually small and usually guessable —
 * `www`, `mail`, `dev`, `vpn`, a first name, a ticket number. Predictable
 * labels still fall; genuinely unpredictable ones do not.
 *
 * RFC 9276 is blunt about the iteration count, and this lab follows it: extra
 * iterations cost the zone's own servers far more than they cost an attacker,
 * and the recommended value is zero, with an empty salt.
 *
 *     IH(salt, x, 0) = H( x || salt )
 *     IH(salt, x, k) = H( IH(salt, x, k-1) || salt )   for k > 0
 *
 * `x` is the owner name in canonical, uncompressed, down-cased wire form, and
 * `iterations` counts the ADDITIONAL hashes — so the total is iterations + 1.
 */

import { compareBytes, concatBytes } from '../dns/codec.ts';
import { canonicalWire, isAtOrBelow, presentName, type Labels } from '../dns/name.ts';
import { decodeNsec3, type Nsec3Rdata } from '../dns/rdata.ts';
import { RR_TYPE, typeName } from '../dns/types.ts';
import { nsec3Digest } from './crypto.ts';

/** The Opt-Out flag (RFC 5155 section 3.1.2.1), bit 0 of the Flags octet. */
export const NSEC3_FLAG_OPT_OUT = 0x01;

export interface Nsec3Params {
  readonly hashAlgorithm: number;
  readonly iterations: number;
  readonly salt: Uint8Array;
}

/** Hash one name. Returns the raw digest; callers encode it themselves. */
export function nsec3Hash(name: Labels, params: Nsec3Params): Uint8Array {
  const wire = canonicalWire(name);
  let current = nsec3Digest(params.hashAlgorithm, concatBytes(wire, params.salt));
  for (let i = 0; i < params.iterations; i += 1) {
    current = nsec3Digest(params.hashAlgorithm, concatBytes(current, params.salt));
  }
  return current;
}

/**
 * Each intermediate value of the iterated hash, for the UI to step through.
 *
 * Shown rather than described because the shape of the recursion is the whole
 * argument about iterations: every round costs the attacker exactly what it
 * costs the server, one hash per candidate, so multiplying it does not change
 * which side wins — it only raises the price of every ordinary query the zone
 * answers.
 */
export function nsec3HashTrace(
  name: Labels,
  params: Nsec3Params
): { readonly input: Uint8Array; readonly rounds: readonly Uint8Array[] } {
  const wire = canonicalWire(name);
  const rounds: Uint8Array[] = [];
  let current = nsec3Digest(params.hashAlgorithm, concatBytes(wire, params.salt));
  rounds.push(current);
  for (let i = 0; i < params.iterations; i += 1) {
    current = nsec3Digest(params.hashAlgorithm, concatBytes(current, params.salt));
    rounds.push(current);
  }
  return { input: wire, rounds };
}

export interface Nsec3Record {
  /** The full owner name, whose first label is the base32hex hash. */
  readonly owner: Labels;
  /** The owner's hash, decoded from that first label. */
  readonly ownerHash: Uint8Array;
  readonly rdata: Nsec3Rdata;
}

export function toNsec3Record(owner: Labels, rdata: Uint8Array, ownerHash: Uint8Array): Nsec3Record {
  return { owner, ownerHash, rdata: decodeNsec3(rdata) };
}

/** Does this NSEC3 span `hash`? Same half-open interval and wrap as NSEC. */
export function nsec3Covers(record: Nsec3Record, hash: Uint8Array): boolean {
  const vsOwner = compareBytes(hash, record.ownerHash);
  const vsNext = compareBytes(hash, record.rdata.nextHashedOwner);
  const wraps = compareBytes(record.rdata.nextHashedOwner, record.ownerHash) <= 0;
  if (wraps) return vsOwner > 0 || vsNext < 0;
  return vsOwner > 0 && vsNext < 0;
}

export function nsec3Matches(record: Nsec3Record, hash: Uint8Array): boolean {
  return compareBytes(record.ownerHash, hash) === 0;
}

export function paramsOf(record: Nsec3Record): Nsec3Params {
  return {
    hashAlgorithm: record.rdata.hashAlgorithm,
    iterations: record.rdata.iterations,
    salt: record.rdata.salt,
  };
}

export function paramsMatch(a: Nsec3Params, b: Nsec3Params): boolean {
  return (
    a.hashAlgorithm === b.hashAlgorithm &&
    a.iterations === b.iterations &&
    compareBytes(a.salt, b.salt) === 0
  );
}

export function isOptOut(record: Nsec3Record): boolean {
  return (record.rdata.flags & NSEC3_FLAG_OPT_OUT) !== 0;
}

export interface Nsec3DenialStep {
  readonly label: string;
  readonly passed: boolean;
  readonly detail: string;
}

export interface Nsec3Denial {
  readonly proven: boolean;
  readonly steps: readonly Nsec3DenialStep[];
  readonly optOut: boolean;
}

/**
 * The NSEC3 half of the bailiwick rule. See `inBailiwick` in `nsec.ts` for why
 * this is a hole rather than a formality: the hash ring wraps too, so its last
 * record covers every hash after the last owner's, and hashes do not carry any
 * hint of which zone they came from.
 */
function inBailiwick3(steps: Nsec3DenialStep[], name: Labels, zone: Labels): boolean {
  const inside = isAtOrBelow(name, zone);
  steps.push({
    label: 'Query is inside this zone',
    passed: inside,
    detail: inside
      ? `${presentName(name)} is at or below ${presentName(zone)}, so this zone's records can speak about it`
      : `${presentName(name)} is outside ${presentName(zone)} — no record from this zone can deny it`,
  });
  return inside;
}

/**
 * The closest-encloser proof (RFC 5155 section 8.3).
 *
 * NSEC3 cannot name the closest encloser directly — the record only carries a
 * hash — so a validator strips labels from the queried name one at a time,
 * hashes each ancestor, and looks for the deepest one an NSEC3 MATCHES. The
 * ancestor one label below that is the "next closer" name, which must be
 * COVERED, and the wildcard at the encloser must be covered too.
 *
 * The opt-out flag is reported rather than swallowed: with opt-out set, an
 * unsigned delegation may exist inside a covered gap without any NSEC3 of its
 * own, so a covering record proves less than it looks like it does.
 */
export function proveNsec3Nxdomain(
  records: readonly Nsec3Record[],
  name: Labels,
  zone: Labels,
  params: Nsec3Params
): Nsec3Denial {
  const steps: Nsec3DenialStep[] = [];
  if (!inBailiwick3(steps, name, zone)) return { proven: false, steps, optOut: false };
  const mismatched = records.filter((r) => !paramsMatch(paramsOf(r), params));
  if (mismatched.length > 0) {
    steps.push({
      label: 'NSEC3 parameters agree',
      passed: false,
      detail: `${mismatched.length} record(s) use different hash parameters from the zone's NSEC3PARAM, so they cannot be compared against it`,
    });
    return { proven: false, steps, optOut: false };
  }
  steps.push({
    label: 'NSEC3 parameters agree',
    passed: true,
    detail: `all records use algorithm ${params.hashAlgorithm}, ${params.iterations} extra iteration${params.iterations === 1 ? '' : 's'}, salt ${params.salt.length === 0 ? '(empty)' : `${params.salt.length} octets`}`,
  });

  // Deepest ancestor with a MATCHING NSEC3 is the closest encloser.
  let encloser: Labels | null = null;
  for (let strip = 0; strip <= name.length - zone.length; strip += 1) {
    const candidate = name.slice(strip);
    const hash = nsec3Hash(candidate, params);
    if (records.some((r) => nsec3Matches(r, hash))) {
      encloser = candidate;
      break;
    }
  }
  if (!encloser) {
    steps.push({
      label: 'Closest encloser proved',
      passed: false,
      detail: `no NSEC3 matches the hash of any ancestor of ${presentName(name)}, so the closest encloser is unproved`,
    });
    return { proven: false, steps, optOut: false };
  }
  steps.push({
    label: 'Closest encloser proved',
    passed: true,
    detail: `an NSEC3 matches the hash of ${presentName(encloser)}, proving that ancestor exists`,
  });

  if (encloser.length === name.length) {
    steps.push({
      label: 'Next closer name covered',
      passed: false,
      detail: `${presentName(name)} is itself the closest encloser, so it exists — this is a NODATA case, not NXDOMAIN`,
    });
    return { proven: false, steps, optOut: false };
  }

  const nextCloser = name.slice(name.length - encloser.length - 1);
  const nextCloserHash = nsec3Hash(nextCloser, params);
  const nextCloserCover = records.find((r) => nsec3Covers(r, nextCloserHash));
  if (!nextCloserCover) {
    steps.push({
      label: 'Next closer name covered',
      passed: false,
      detail: `no NSEC3 spans the hash of ${presentName(nextCloser)}`,
    });
    return { proven: false, steps, optOut: false };
  }
  const optOut = isOptOut(nextCloserCover);
  steps.push({
    label: 'Next closer name covered',
    passed: true,
    detail:
      `an NSEC3 spans the hash of ${presentName(nextCloser)}, so that name does not exist` +
      (optOut
        ? ' — but its Opt-Out flag is set, so an unsigned delegation could exist inside this gap without an NSEC3 of its own'
        : ''),
  });

  const wildcard: Labels = [Uint8Array.of(0x2a), ...encloser];
  const wildcardHash = nsec3Hash(wildcard, params);
  const wildcardCover = records.find((r) => nsec3Covers(r, wildcardHash));
  if (!wildcardCover) {
    steps.push({
      label: 'Wildcard at the encloser covered',
      passed: false,
      detail: `no NSEC3 spans the hash of ${presentName(wildcard)}, so nothing rules out a wildcard answer`,
    });
    return { proven: false, steps, optOut };
  }
  steps.push({
    label: 'Wildcard at the encloser covered',
    passed: true,
    detail: `an NSEC3 spans the hash of ${presentName(wildcard)}, so no wildcard could have synthesized an answer`,
  });

  return { proven: true, steps, optOut };
}

/** NODATA under NSEC3: a matching record whose bit map omits the type. */
export function proveNsec3NoData(
  records: readonly Nsec3Record[],
  name: Labels,
  type: number,
  params: Nsec3Params,
  zone: Labels
): Nsec3Denial {
  const steps: Nsec3DenialStep[] = [];
  if (!inBailiwick3(steps, name, zone)) return { proven: false, steps, optOut: false };
  const hash = nsec3Hash(name, params);
  const match = records.find((r) => nsec3Matches(r, hash));
  if (!match) {
    steps.push({
      label: 'NSEC3 matching the queried name',
      passed: false,
      detail: `no NSEC3 owner equals the hash of ${presentName(name)}`,
    });
    return { proven: false, steps, optOut: false };
  }
  steps.push({
    label: 'NSEC3 matching the queried name',
    passed: true,
    detail: `an NSEC3 owner equals the hash of ${presentName(name)}, listing ${match.rdata.types.map(typeName).join(', ')}`,
  });
  const hasType = match.rdata.types.includes(type);
  steps.push({
    label: 'Queried type absent from the bit map',
    passed: !hasType,
    detail: hasType
      ? `the bit map DOES list ${typeName(type)}`
      : `${typeName(type)} is absent from the bit map, which is the denial`,
  });
  return { proven: !hasType, steps, optOut: isOptOut(match) };
}

/**
 * Proving a delegation is UNSIGNED — the case the chain of trust ends on.
 *
 * RFC 5155 section 8.9 gives two shapes, and an Opt-Out zone almost always
 * uses the second:
 *
 *  1. an NSEC3 that MATCHES the delegation name, whose bit map has neither DS
 *     nor CNAME set; or
 *  2. no matching NSEC3 at all — the delegation has no NSEC3 of its own,
 *     because Opt-Out let the signer skip it — in which case the closest
 *     encloser must be proved and the NSEC3 covering the NEXT CLOSER name
 *     MUST have the Opt-Out flag set.
 *
 * The captured `.com` response for `google.com` in `src/vectors/` is exactly
 * form 2, and it is worth reading closely: `.com` signs a statement whose
 * content is "I am not vouching for anything under this name." A chain that
 * ends here has not failed. It has been correctly told where it stops.
 */
export function proveNsec3NoDs(
  records: readonly Nsec3Record[],
  delegation: Labels,
  zone: Labels,
  params: Nsec3Params
): Nsec3Denial {
  const steps: Nsec3DenialStep[] = [];
  if (!inBailiwick3(steps, delegation, zone)) return { proven: false, steps, optOut: false };
  const hash = nsec3Hash(delegation, params);
  const match = records.find((r) => nsec3Matches(r, hash));
  if (match) {
    // RFC 5155 section 8.9 imposes THREE conditions here, not one. The NS bit
    // must be set, the DS bit must not be, and the SOA bit must not be either
    // -- that last one is how the validator knows the record came from the
    // PARENT side of the cut. Without it, a child's own apex NSEC3 (which
    // carries SOA, NS and DNSKEY and never carries DS) would prove that the
    // child's delegation is unsigned, and a signed zone could downgrade
    // itself.
    const types = match.rdata.types;
    steps.push({
      label: 'NSEC3 matching the delegation',
      passed: true,
      detail: `an NSEC3 owner equals the hash of ${presentName(delegation)}, listing ${types.map(typeName).join(', ') || '(nothing)'}`,
    });

    const hasNs = types.includes(RR_TYPE.NS);
    steps.push({
      label: 'NS present — this is a delegation',
      passed: hasNs,
      detail: hasNs
        ? 'the bit map lists NS'
        : 'the bit map has no NS, so this name is not a delegation point',
    });

    const hasSoa = types.includes(RR_TYPE.SOA);
    steps.push({
      label: 'SOA absent — the parent is speaking',
      passed: !hasSoa,
      detail: hasSoa
        ? 'the bit map lists SOA, so this NSEC3 came from the CHILD apex — a zone cannot testify about its own DS'
        : 'the bit map has no SOA, so this record was served by the parent side of the cut',
    });

    const hasDs = types.includes(RR_TYPE.DS);
    steps.push({
      label: 'DS absent from the bit map',
      passed: !hasDs,
      detail: hasDs
        ? 'the bit map DOES list DS, so this record cannot prove the delegation is unsigned'
        : 'DS is absent from the bit map, so the parent is signing that it holds no DS for this child',
    });
    return { proven: hasNs && !hasSoa && !hasDs, steps, optOut: isOptOut(match) };
  }

  steps.push({
    label: 'NSEC3 matching the delegation',
    passed: true,
    detail: `no NSEC3 exists for ${presentName(delegation)} itself — under Opt-Out the signer is allowed to skip one, so the proof takes the closest-encloser route instead`,
  });

  let encloser: Labels | null = null;
  for (let strip = 1; strip <= delegation.length - zone.length; strip += 1) {
    const candidate = delegation.slice(strip);
    if (records.some((r) => nsec3Matches(r, nsec3Hash(candidate, params)))) {
      encloser = candidate;
      break;
    }
  }
  if (!encloser) {
    steps.push({
      label: 'Closest encloser proved',
      passed: false,
      detail: `no NSEC3 matches the hash of any ancestor of ${presentName(delegation)}`,
    });
    return { proven: false, steps, optOut: false };
  }
  steps.push({
    label: 'Closest encloser proved',
    passed: true,
    detail: `an NSEC3 matches the hash of ${presentName(encloser)}, proving that ancestor exists`,
  });

  const nextCloser = delegation.slice(delegation.length - encloser.length - 1);
  const cover = records.find((r) => nsec3Covers(r, nsec3Hash(nextCloser, params)));
  if (!cover) {
    steps.push({
      label: 'Next closer name covered',
      passed: false,
      detail: `no NSEC3 spans the hash of ${presentName(nextCloser)}`,
    });
    return { proven: false, steps, optOut: false };
  }
  const optOut = isOptOut(cover);
  steps.push({
    label: 'Next closer name covered, Opt-Out set',
    passed: optOut,
    detail: optOut
      ? `an NSEC3 spans the hash of ${presentName(nextCloser)} with the Opt-Out flag set, which is what licenses the missing NSEC3 and proves this delegation is unsigned`
      : `an NSEC3 spans the hash of ${presentName(nextCloser)}, but its Opt-Out flag is CLEAR — without Opt-Out the delegation should have had an NSEC3 of its own`,
  });
  return { proven: optOut, steps, optOut };
}
