/**
 * Verifying one RRset against one RRSIG, as a sequence of named steps.
 *
 * RFC 4035 section 5.3 splits validation into three stages — decide whether an
 * RRSIG is usable at all, find the key it names, then do the cryptography —
 * and this module keeps them separate on purpose. Collapsing them is how a
 * validator ends up reporting "invalid signature" for an expired one, or for a
 * clock that is three days fast, and the learner never finds out which.
 *
 * Every check returns its own outcome with its own failure code, and the
 * checks run in a fixed order so the UI can show them as a checklist that
 * stops at the first real problem rather than as a verdict that appears from
 * nowhere.
 */

import { compareBytes } from '../dns/codec.ts';
import { isAtOrBelow, nameEquals, presentName, rrsigLabelCount, type Labels } from '../dns/name.ts';
import { decodeDs, decodeRrsig, type DsRdata, type RrsigRdata } from '../dns/rdata.ts';
import {
  algorithmName,
  digestTypeName,
  SUPPORTED_ALGORITHMS,
  SUPPORTED_DIGEST_TYPES,
  typeName,
  type RRset,
} from '../dns/types.ts';
import { buildSignedData, dsPreimage, isWildcardExpansion, type SignedDataParts } from './canonical.ts';
import { digest, UnsupportedAlgorithmError, verifySignature } from './crypto.ts';
import type { FailureCode } from './failures.ts';
import { describeKeys, type KeyInfo } from './keytag.ts';

export interface Check {
  readonly id: string;
  readonly label: string;
  readonly passed: boolean;
  /** What was compared, in concrete terms — the teaching payload. */
  readonly detail: string;
  readonly code: FailureCode | null;
}

const pass = (id: string, label: string, detail: string): Check => ({
  id,
  label,
  passed: true,
  detail,
  code: null,
});

const fail = (id: string, label: string, detail: string, code: FailureCode): Check => ({
  id,
  label,
  passed: false,
  detail,
  code,
});

export interface SignatureAttempt {
  readonly sig: RrsigRdata;
  readonly checks: readonly Check[];
  readonly verified: boolean;
  readonly failure: FailureCode | null;
  /** Present once the checks got far enough to assemble the signed bytes. */
  readonly signedData: SignedDataParts | null;
  /** The key the cryptography actually ran against, if it got that far. */
  readonly keyUsed: KeyInfo | null;
  /** Every key whose tag matched, in the order they were tried. */
  readonly candidateKeys: readonly KeyInfo[];
  readonly fromWildcard: boolean;
}

export interface RrsetVerification {
  readonly rrset: RRset;
  readonly attempts: readonly SignatureAttempt[];
  readonly verified: boolean;
  /** The failure of the best attempt — the one that got furthest. */
  readonly failure: FailureCode | null;
}

/**
 * How far an attempt got, so the reported failure is the most informative one.
 *
 * A zone mid-rollover legitimately carries an RRSIG whose key has already been
 * removed alongside one that verifies, and a zone with a stale signature
 * carries an expired RRSIG next to a fresh one. Reporting the FIRST failure in
 * either case names the wrong problem, so attempts are ranked by how many
 * checks they cleared and the deepest failure is the one shown.
 */
function depth(attempt: SignatureAttempt): number {
  return attempt.checks.filter((c) => c.passed).length;
}

export interface VerifyOptions {
  /** The zone whose DNSKEY RRset was supplied. Signer name must equal it. */
  readonly zone: Labels;
  /** Validation instant, in seconds since the epoch. Never `Date.now()` implicitly. */
  readonly now: number;
}

/**
 * Verify an RRset against every RRSIG offered for it.
 *
 * One valid signature is enough (RFC 4035 section 5.3.3), so this stops at the
 * first success — but it records every attempt, because "which of the four
 * signatures on this RRset actually carried it" is the interesting question
 * during a key rollover.
 */
export async function verifyRrset(
  rrset: RRset,
  rrsigRdatas: readonly Uint8Array[],
  dnskeyRdatas: readonly Uint8Array[],
  options: VerifyOptions
): Promise<RrsetVerification> {
  if (rrsigRdatas.length === 0) {
    return {
      rrset,
      attempts: [],
      verified: false,
      failure: 'NO_RRSIG',
    };
  }
  const keys = describeKeys(dnskeyRdatas);
  const attempts: SignatureAttempt[] = [];
  for (const rdata of rrsigRdatas) {
    const attempt = await verifyOne(rrset, decodeRrsig(rdata), keys, options);
    attempts.push(attempt);
    if (attempt.verified) break;
  }
  const winner = attempts.find((a) => a.verified);
  if (winner) return { rrset, attempts, verified: true, failure: null };
  const deepest = attempts.reduce((best, a) => (depth(a) > depth(best) ? a : best), attempts[0]!);
  return { rrset, attempts, verified: false, failure: deepest.failure };
}

async function verifyOne(
  rrset: RRset,
  sig: RrsigRdata,
  keys: readonly KeyInfo[],
  { zone, now }: VerifyOptions
): Promise<SignatureAttempt> {
  const checks: Check[] = [];
  const stop = (code: FailureCode): SignatureAttempt => ({
    sig,
    checks,
    verified: false,
    failure: code,
    signedData: null,
    keyUsed: null,
    candidateKeys: [],
    fromWildcard: false,
  });

  // 1. The signature must be about these records.
  if (sig.typeCovered !== rrset.type) {
    checks.push(
      fail(
        'type-covered',
        'Type covered',
        `signature covers ${typeName(sig.typeCovered)}, offered with a ${typeName(rrset.type)} RRset`,
        'TYPE_COVERED_MISMATCH'
      )
    );
    return stop('TYPE_COVERED_MISMATCH');
  }
  checks.push(pass('type-covered', 'Type covered', `RRSIG covers ${typeName(rrset.type)}, matching the RRset`));

  // 2. The signer must be the zone that supplied the keys, and the owner must
  //    sit at or below it. Without this, any zone could sign for any other.
  if (!nameEquals(sig.signerName, zone)) {
    checks.push(
      fail(
        'signer',
        'Signer name',
        `signature is by ${presentName(sig.signerName)}, but the keys offered are ${presentName(zone)}'s`,
        'SIGNER_NAME_MISMATCH'
      )
    );
    return stop('SIGNER_NAME_MISMATCH');
  }
  if (!isAtOrBelow(rrset.name, sig.signerName)) {
    checks.push(
      fail(
        'signer',
        'Signer name',
        `${presentName(rrset.name)} is not inside ${presentName(sig.signerName)}`,
        'SIGNER_NAME_MISMATCH'
      )
    );
    return stop('SIGNER_NAME_MISMATCH');
  }
  checks.push(
    pass('signer', 'Signer name', `signed by ${presentName(sig.signerName)}, which is this zone`)
  );

  // 3. Labels: fewer than the owner name means a wildcard expansion, more is
  //    impossible and makes the signed owner name unreconstructable.
  const ownLabels = rrsigLabelCount(rrset.name);
  if (sig.labels > ownLabels) {
    checks.push(
      fail(
        'labels',
        'Label count',
        `RRSIG claims ${sig.labels} labels; ${presentName(rrset.name)} has ${ownLabels}`,
        'LABELS_INVALID'
      )
    );
    return stop('LABELS_INVALID');
  }
  const fromWildcard = isWildcardExpansion(rrset.name, sig.labels);
  checks.push(
    pass(
      'labels',
      'Label count',
      fromWildcard
        ? `RRSIG counts ${sig.labels} labels against the name's ${ownLabels}: this answer was synthesized from a wildcard, so the signed owner is the wildcard`
        : `RRSIG counts ${sig.labels} labels, matching the owner name exactly (no wildcard)`
    )
  );

  // 4. The validity window. Checked BEFORE the cryptography, because an
  //    expired signature is arithmetically perfect and reporting it as a
  //    forgery sends you looking for an attacker who is not there.
  if (now > sig.expiration) {
    checks.push(
      fail(
        'validity',
        'Validity window',
        `expired ${describeGap(now - sig.expiration)} before the validation instant`,
        'RRSIG_EXPIRED'
      )
    );
    return stop('RRSIG_EXPIRED');
  }
  if (now < sig.inception) {
    checks.push(
      fail(
        'validity',
        'Validity window',
        `does not become valid for another ${describeGap(sig.inception - now)}`,
        'RRSIG_NOT_YET_VALID'
      )
    );
    return stop('RRSIG_NOT_YET_VALID');
  }
  checks.push(
    pass(
      'validity',
      'Validity window',
      `validation instant sits inside the signature's window, with ${describeGap(sig.expiration - now)} left`
    )
  );

  // 5. Find candidate keys. The key tag is a hint, so EVERY key carrying it is
  //    tried; a tag collision must not decide anything.
  if (keys.length === 0) {
    checks.push(fail('key', 'Signing key', 'the zone published no DNSKEY records', 'NO_DNSKEY'));
    return stop('NO_DNSKEY');
  }
  const sameAlgorithm = keys.filter((k) => k.algorithm === sig.algorithm);
  const candidateKeys = sameAlgorithm.filter((k) => k.tag === sig.keyTag);
  if (candidateKeys.length === 0) {
    const tags = keys.map((k) => `${k.tag}/${algorithmName(k.algorithm)}`).join(', ');
    checks.push(
      fail(
        'key',
        'Signing key',
        `RRSIG names key tag ${sig.keyTag} with ${algorithmName(sig.algorithm)}; the zone offers ${tags || 'nothing'}`,
        'KEYTAG_MISMATCH'
      )
    );
    return stop('KEYTAG_MISMATCH');
  }
  const zoneKeys = candidateKeys.filter((k) => k.isZoneKey);
  if (zoneKeys.length === 0) {
    checks.push(
      fail(
        'key',
        'Signing key',
        `key tag ${sig.keyTag} exists but its Zone Key flag (bit 7) is clear, so it may not sign this zone's RRsets`,
        'NOT_A_ZONE_KEY'
      )
    );
    return stop('NOT_A_ZONE_KEY');
  }
  checks.push(
    pass(
      'key',
      'Signing key',
      zoneKeys.length === 1
        ? `key tag ${sig.keyTag} (${algorithmName(sig.algorithm)}) found in the zone's DNSKEY RRset`
        : `${zoneKeys.length} keys share tag ${sig.keyTag} — a tag is a hint, not an identity, so every one is tried`
    )
  );

  // 6. Algorithm support is a statement about this validator, so it is its own
  //    step and its own outcome rather than a signature failure.
  if (!SUPPORTED_ALGORITHMS.has(sig.algorithm)) {
    checks.push(
      fail(
        'algorithm',
        'Algorithm support',
        `${algorithmName(sig.algorithm)} (${sig.algorithm}) is a real DNSSEC algorithm, but this lab implements only 8, 13 and 15`,
        'ALG_UNSUPPORTED'
      )
    );
    return stop('ALG_UNSUPPORTED');
  }
  checks.push(
    pass('algorithm', 'Algorithm support', `${algorithmName(sig.algorithm)} is implemented here`)
  );

  // 7. The cryptography, over the bytes RFC 4034 section 3.1.8.1 defines.
  const signedData = buildSignedData(rrset, sig);
  // Why a key was unusable, if one was. Kept so the reported detail is TRUE:
  // "these are not the records that were signed" is the right sentence for a
  // failed verification and the WRONG one for a key that could not be parsed
  // at all, and reporting the second as the first sends a reader looking for
  // an attacker who is not there.
  const keyProblems: string[] = [];
  for (const key of zoneKeys) {
    let ok = false;
    try {
      ok = await verifySignature(sig.algorithm, key.publicKey, sig.signature, signedData.signedData);
    } catch (error) {
      if (error instanceof UnsupportedAlgorithmError) {
        // Unreachable today: `SUPPORTED_ALGORITHMS` is checked a few lines
        // above, so an algorithm arriving here means that set and
        // `verifySignature`'s own switch have drifted apart. Rethrow rather
        // than report — an internal inconsistency should be loud, not
        // relabelled as a cryptographic failure.
        throw error;
      }
      keyProblems.push(`key ${key.tag}: ${(error as Error).message}`);
      ok = false;
    }
    if (ok) {
      checks.push(
        pass(
          'signature',
          'Signature',
          `${algorithmName(sig.algorithm)} verified over ${signedData.signedData.length} octets: the RRSIG's own RDATA followed by ${signedData.records.length} canonicalized record${signedData.records.length === 1 ? '' : 's'}`
        )
      );
      return {
        sig,
        checks,
        verified: true,
        failure: null,
        signedData,
        keyUsed: key,
        candidateKeys: zoneKeys,
        fromWildcard,
      };
    }
  }
  checks.push(
    fail(
      'signature',
      'Signature',
      keyProblems.length === zoneKeys.length
        ? `no candidate key could be used at all — ${keyProblems.join('; ')}`
        : `${algorithmName(sig.algorithm)} rejected the signature over all ${signedData.signedData.length} signed octets — the records offered are not the records signed` +
          (keyProblems.length > 0
            ? ` (and ${keyProblems.length} candidate key could not be parsed: ${keyProblems.join('; ')})`
            : ''),
      'SIGNATURE_INVALID'
    )
  );
  return {
    sig,
    checks,
    verified: false,
    failure: 'SIGNATURE_INVALID',
    signedData,
    keyUsed: null,
    candidateKeys: zoneKeys,
    fromWildcard,
  };
}

function describeGap(seconds: number): string {
  const abs = Math.abs(seconds);
  if (abs < 90) return `${abs} second${abs === 1 ? '' : 's'}`;
  if (abs < 5400) return `${Math.round(abs / 60)} minutes`;
  if (abs < 172800) return `${Math.round(abs / 3600)} hours`;
  return `${Math.round(abs / 86400)} days`;
}

// ── DS: the parent's fingerprint of the child's key ─────────────────────────

export interface DsMatch {
  readonly ds: DsRdata;
  readonly key: KeyInfo | null;
  readonly checks: readonly Check[];
  readonly matched: boolean;
  readonly failure: FailureCode | null;
  /** The octets that were hashed, so the UI can show them rather than claim them. */
  readonly preimage: Uint8Array | null;
  readonly computedDigest: Uint8Array | null;
}

/**
 * Match one DS record against a child's DNSKEY RRset.
 *
 * The digest covers the child apex name AND the DNSKEY RDATA, which is what
 * binds a key to one specific zone: the same key published at a different name
 * produces a different digest and the parent's DS stops matching.
 */
export function matchDs(dsRdata: Uint8Array, childZone: Labels, dnskeyRdatas: readonly Uint8Array[]): DsMatch {
  const ds = decodeDs(dsRdata);
  const checks: Check[] = [];
  const keys = describeKeys(dnskeyRdatas);

  // RFC 6840 section 5.2: "a validator disregards any authenticated DS records
  // that specify unknown or unsupported DNSKEY algorithms. If none are left,
  // the zone is treated as if it were unsigned." So an algorithm this lab does
  // not implement is reported as its own outcome, exactly like an unsupported
  // digest type -- and NOT as a key-tag mismatch, which would read as a
  // forgery and blame the zone for this validator's gap.
  if (!SUPPORTED_ALGORITHMS.has(ds.algorithm)) {
    checks.push(
      fail(
        'ds-algorithm',
        'Signing algorithm',
        `DS names ${algorithmName(ds.algorithm)} (${ds.algorithm}), a real DNSSEC algorithm this validator does not implement — RFC 6840 says to disregard such a DS rather than treat it as broken`,
        'ALG_UNSUPPORTED'
      )
    );
    return { ds, key: null, checks, matched: false, failure: 'ALG_UNSUPPORTED', preimage: null, computedDigest: null };
  }
  checks.push(
    pass('ds-algorithm', 'Signing algorithm', `${algorithmName(ds.algorithm)} is implemented here`)
  );

  if (!SUPPORTED_DIGEST_TYPES.has(ds.digestType)) {
    checks.push(
      fail(
        'digest-type',
        'Digest algorithm',
        `DS uses digest type ${ds.digestType}, which this validator cannot compute — RFC 6840 says to treat that as no DS at all`,
        'DIGEST_UNSUPPORTED'
      )
    );
    return { ds, key: null, checks, matched: false, failure: 'DIGEST_UNSUPPORTED', preimage: null, computedDigest: null };
  }
  checks.push(
    pass('digest-type', 'Digest algorithm', `DS digest type ${ds.digestType} is ${digestTypeName(ds.digestType)}`)
  );

  const candidates = keys.filter((k) => k.tag === ds.keyTag && k.algorithm === ds.algorithm);
  if (candidates.length === 0) {
    const offered = keys.map((k) => `${k.tag}/${algorithmName(k.algorithm)}`).join(', ');
    checks.push(
      fail(
        'ds-keytag',
        'Referenced key',
        `DS points at key tag ${ds.keyTag} with ${algorithmName(ds.algorithm)}; the child publishes ${offered || 'no keys'}`,
        'KEYTAG_MISMATCH'
      )
    );
    return { ds, key: null, checks, matched: false, failure: 'KEYTAG_MISMATCH', preimage: null, computedDigest: null };
  }
  checks.push(
    pass('ds-keytag', 'Referenced key', `DS points at key tag ${ds.keyTag}, which the child publishes`)
  );

  let lastPreimage: Uint8Array | null = null;
  let lastDigest: Uint8Array | null = null;
  for (const key of candidates) {
    const preimage = dsPreimage(childZone, key.rdata);
    const computed = digest(ds.digestType, preimage);
    lastPreimage = preimage;
    lastDigest = computed;
    if (compareBytes(computed, ds.digest) === 0) {
      checks.push(
        pass(
          'ds-digest',
          'Digest match',
          `${digestTypeName(ds.digestType)} over ${presentName(childZone)} plus the DNSKEY RDATA (${preimage.length} octets) equals the digest the parent published`
        )
      );
      return { ds, key, checks, matched: true, failure: null, preimage, computedDigest: computed };
    }
  }
  checks.push(
    fail(
      'ds-digest',
      'Digest match',
      `${digestTypeName(ds.digestType)} over the child's key gives a different value from the one the parent published`,
      'DS_MISMATCH'
    )
  );
  return {
    ds,
    key: candidates[0] ?? null,
    checks,
    matched: false,
    failure: 'DS_MISMATCH',
    preimage: lastPreimage,
    computedDigest: lastDigest,
  };
}
