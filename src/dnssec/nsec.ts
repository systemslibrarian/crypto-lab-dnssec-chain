/**
 * NSEC: proving a name does not exist by naming the one that does.
 *
 * This is the mechanism the whole lab points at. A signed zone cannot sign
 * "no" on demand — an offline signer has no idea which nonexistent names will
 * be asked about, and there are infinitely many. So instead the signer sorts
 * every name that DOES exist into canonical order and signs the GAPS: each
 * NSEC record says "between me and this next name, nothing exists."
 *
 * That is a genuine proof, verifiable offline, and it is also a directory. A
 * denial for `q.example.` hands back an NSEC saying the next existing name is
 * `mail.example.` — so you now know `mail.example.` exists without ever having
 * guessed it. Ask about a name just after `mail.example.` and the next record
 * names the one after that. The zone falls out in as many queries as it has
 * names.
 *
 * This is not a defect in an implementation; it is what the construction does.
 * RFC 7129 spells it out, and it is the reason NSEC3 and online minimally
 * covering denial both exist.
 */

import { compareNames, nameEquals, presentName, type Labels } from '../dns/name.ts';
import { decodeNsec, type NsecRdata } from '../dns/rdata.ts';
import { RR_TYPE, typeName } from '../dns/types.ts';

export interface NsecRecord {
  readonly owner: Labels;
  readonly rdata: NsecRdata;
}

export function toNsecRecord(owner: Labels, rdata: Uint8Array): NsecRecord {
  return { owner, rdata: decodeNsec(rdata) };
}

/**
 * Does this NSEC prove `name` does not exist?
 *
 * The interval is half-open: `owner < name < next`. The last NSEC in a zone
 * wraps — its next name is the apex, which sorts before everything else in the
 * zone — so that record covers every name after its owner. Getting the wrap
 * case wrong is the classic NSEC validator bug: names at the very end of the
 * zone become undeniable, and a resolver either accepts a forged NXDOMAIN or
 * rejects a real one.
 */
export function nsecCovers(record: NsecRecord, name: Labels): boolean {
  const vsOwner = compareNames(name, record.owner);
  const vsNext = compareNames(name, record.rdata.nextName);
  const wraps = compareNames(record.rdata.nextName, record.owner) <= 0;
  if (wraps) return vsOwner > 0 || vsNext < 0;
  return vsOwner > 0 && vsNext < 0;
}

/** Does this NSEC sit exactly at `name`, i.e. assert that the name exists? */
export function nsecMatches(record: NsecRecord, name: Labels): boolean {
  return nameEquals(record.owner, name);
}

export function nsecHasType(record: NsecRecord, type: number): boolean {
  return record.rdata.types.includes(type);
}

export interface DenialStep {
  readonly label: string;
  readonly passed: boolean;
  readonly detail: string;
}

export interface DenialProof {
  readonly proven: boolean;
  readonly steps: readonly DenialStep[];
  /** Which of the offered NSEC records did the work, for the UI to highlight. */
  readonly usedOwners: readonly string[];
}

/**
 * NODATA: the name exists, this type does not (RFC 4035 section 5.4).
 *
 * The proof is a single NSEC sitting exactly at the queried name whose type
 * bit map omits the queried type. Because the bitmap lists every type the name
 * DOES have, a NODATA denial is also a free inventory of the name.
 */
export function proveNoData(records: readonly NsecRecord[], name: Labels, type: number): DenialProof {
  const steps: DenialStep[] = [];
  const match = records.find((r) => nsecMatches(r, name));
  if (!match) {
    steps.push({
      label: 'NSEC at the queried name',
      passed: false,
      detail: `no NSEC record has owner ${presentName(name)}, so nothing asserts this name exists`,
    });
    return { proven: false, steps, usedOwners: [] };
  }
  steps.push({
    label: 'NSEC at the queried name',
    passed: true,
    detail: `an NSEC owned by ${presentName(name)} asserts the name exists and lists its types: ${match.rdata.types.map(typeName).join(', ')}`,
  });
  const hasType = nsecHasType(match, type);
  steps.push({
    label: 'Queried type absent from the bit map',
    passed: !hasType,
    detail: hasType
      ? `the bit map DOES list ${typeName(type)}, so this record cannot deny it`
      : `${typeName(type)} is absent from the bit map, which is the denial`,
  });
  return { proven: !hasType, steps, usedOwners: [presentName(match.owner)] };
}

/**
 * NXDOMAIN: the name does not exist at all (RFC 4035 section 5.4).
 *
 * TWO things must be proved, and forgetting the second is a real vulnerability
 * rather than a technicality:
 *
 *  1. an NSEC covers the queried name — nothing exists in that gap; and
 *  2. an NSEC covers the wildcard that could have answered it — because a
 *     `*.example.` in the zone would have synthesized a perfectly valid answer
 *     for a name that does not literally exist. Without this half, an attacker
 *     who strips a wildcard answer can present the covering NSEC alone and
 *     turn a real answer into a forged NXDOMAIN.
 *
 * The wildcard proved here is at the closest encloser: the deepest existing
 * ancestor of the queried name, which the covering NSEC itself identifies.
 */
export function proveNxdomain(records: readonly NsecRecord[], name: Labels): DenialProof {
  const steps: DenialStep[] = [];
  const used: string[] = [];

  const covering = records.find((r) => nsecCovers(r, name));
  if (!covering) {
    steps.push({
      label: 'NSEC covering the queried name',
      passed: false,
      detail: `none of the ${records.length} NSEC record(s) offered spans ${presentName(name)}`,
    });
    return { proven: false, steps, usedOwners: [] };
  }
  used.push(presentName(covering.owner));
  steps.push({
    label: 'NSEC covering the queried name',
    passed: true,
    detail: `${presentName(covering.owner)} → ${presentName(covering.rdata.nextName)} spans ${presentName(name)}, so nothing exists in that gap`,
  });

  // The closest encloser is the longest suffix shared by the covering NSEC's
  // owner and its next name that is also a suffix of the queried name.
  const encloser = closestEncloser(covering, name);
  const wildcard: Labels = [Uint8Array.of(0x2a), ...encloser];
  steps.push({
    label: 'Closest encloser identified',
    passed: true,
    detail: `the deepest ancestor of ${presentName(name)} that exists is ${presentName(encloser)}, so the only wildcard that could have answered is ${presentName(wildcard)}`,
  });

  const wildcardCovering = records.find((r) => nsecCovers(r, wildcard));
  const wildcardExists = records.some((r) => nsecMatches(r, wildcard));
  if (wildcardExists) {
    steps.push({
      label: 'No wildcard could have answered',
      passed: false,
      detail: `${presentName(wildcard)} exists in the zone, so this name could have been answered by a wildcard — the denial is incomplete`,
    });
    return { proven: false, steps, usedOwners: used };
  }
  if (!wildcardCovering) {
    steps.push({
      label: 'No wildcard could have answered',
      passed: false,
      detail: `no NSEC offered spans ${presentName(wildcard)}, so nothing rules out a wildcard answer`,
    });
    return { proven: false, steps, usedOwners: used };
  }
  if (!used.includes(presentName(wildcardCovering.owner))) used.push(presentName(wildcardCovering.owner));
  steps.push({
    label: 'No wildcard could have answered',
    passed: true,
    detail: `${presentName(wildcardCovering.owner)} → ${presentName(wildcardCovering.rdata.nextName)} spans ${presentName(wildcard)}, so no wildcard exists that could have synthesized an answer`,
  });

  return { proven: true, steps, usedOwners: used };
}

/**
 * The deepest existing ancestor of `name`, read off the covering NSEC.
 *
 * The covering record's owner and its next name both exist, so the longest
 * suffix that `name` shares with either of them is an existing ancestor.
 */
export function closestEncloser(covering: NsecRecord, name: Labels): Labels {
  const sharedSuffix = (a: Labels, b: Labels): number => {
    let n = 0;
    while (
      n < a.length &&
      n < b.length &&
      compareNames([a[a.length - 1 - n]!], [b[b.length - 1 - n]!]) === 0
    ) {
      n += 1;
    }
    return n;
  };
  const viaOwner = sharedSuffix(name, covering.owner);
  const viaNext = sharedSuffix(name, covering.rdata.nextName);
  const depth = Math.max(viaOwner, viaNext);
  return name.slice(name.length - depth);
}

/** Types worth showing beside a walked name; RRSIG and NSEC are scaffolding. */
export function interestingTypes(types: readonly number[]): number[] {
  return types.filter((t) => t !== RR_TYPE.RRSIG && t !== RR_TYPE.NSEC);
}

/**
 * Proving with NSEC that a delegation is unsigned (RFC 4035 section 5.2).
 *
 * The NSEC at the delegation name must show NS set — this really is a
 * delegation — and DS clear. SOA must also be clear: an NSEC with SOA is the
 * zone's own apex, served by the CHILD, and a child cannot testify about its
 * own DS record. That last check is the one people leave out, and leaving it
 * out lets a child declare itself unsigned.
 */
export function proveNsecNoDs(records: readonly NsecRecord[], delegation: Labels): DenialProof {
  const steps: DenialStep[] = [];
  const match = records.find((r) => nsecMatches(r, delegation));
  if (!match) {
    steps.push({
      label: 'NSEC at the delegation',
      passed: false,
      detail: `no NSEC record is owned by ${presentName(delegation)}`,
    });
    return { proven: false, steps, usedOwners: [] };
  }
  const types = match.rdata.types;
  steps.push({
    label: 'NSEC at the delegation',
    passed: true,
    detail: `an NSEC owned by ${presentName(delegation)} lists ${types.map(typeName).join(', ')}`,
  });

  const hasNs = types.includes(RR_TYPE.NS);
  steps.push({
    label: 'NS present — this is a delegation',
    passed: hasNs,
    detail: hasNs ? 'the bit map lists NS' : 'the bit map has no NS, so this name is not a delegation point',
  });

  const hasSoa = types.includes(RR_TYPE.SOA);
  steps.push({
    label: 'SOA absent — the parent is speaking',
    passed: !hasSoa,
    detail: hasSoa
      ? 'the bit map lists SOA, so this NSEC came from the CHILD apex — a zone cannot testify about its own DS'
      : 'the bit map has no SOA, so this record was served by the parent side of the cut',
  });

  const hasDs = types.includes(RR_TYPE.DS);
  steps.push({
    label: 'DS absent from the bit map',
    passed: !hasDs,
    detail: hasDs
      ? 'the bit map lists DS, so this record cannot prove the delegation is unsigned'
      : 'DS is absent, so the parent is signing that it holds no DS for this child',
  });

  return {
    proven: hasNs && !hasSoa && !hasDs,
    steps,
    usedOwners: [presentName(match.owner)],
  };
}
