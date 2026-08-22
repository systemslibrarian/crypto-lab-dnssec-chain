/**
 * Walking the chain of trust, one link at a time.
 *
 * A validating resolver starts from a key it was configured with — the IANA
 * root trust anchor, shipped in the software, never learned from the network —
 * and works downward. At every step it does the same two things:
 *
 *   1. the zone's own DNSKEY RRset must verify under a key the PARENT vouched
 *      for (or, at the root, under the trust anchor);
 *   2. the child's DS RRset, published at the parent, must verify under the
 *      parent's keys and must hash to one of the child's keys.
 *
 * The chain is therefore a sequence of local checks, not a global one, and
 * that is why each link is reported separately here. "The signature is valid"
 * is a claim about one RRset and one key; the interesting question is always
 * WHICH link stopped.
 *
 * The third outcome is the one that gets misread. If the parent proves — with
 * a signature — that the child has NO DS record, the chain has not broken: it
 * has ended, correctly, and everything below is INSECURE. That is most of the
 * DNS. Reporting it as a failure is wrong in a way that trains people to
 * ignore real failures.
 */

import { compareBytes } from '../dns/codec.ts';
import { presentName, type Labels } from '../dns/name.ts';
import { type RRset } from '../dns/types.ts';
import type { FailureCode, SecurityStatus } from './failures.ts';
import { describeKeys, type KeyInfo } from './keytag.ts';
import { proveNsecNoDs, type DenialProof, type NsecRecord } from './nsec.ts';
import { proveNsec3NoDs, type Nsec3Denial, type Nsec3Params, type Nsec3Record } from './nsec3.ts';
import { matchDs, verifyRrset, type Check, type DsMatch, type RrsetVerification } from './verify.ts';

/** A DS-shaped trust anchor, as IANA publishes the root's. */
export interface AnchorDs {
  readonly label: string;
  readonly rdata: Uint8Array;
}

/**
 * Proof, from the parent, that a child has no DS — i.e. is unsigned.
 *
 * `rrsets` carries the denial RRsets WITH their signatures, and it is not
 * optional. RFC 4035 section 5.2 makes authentication the precondition: "If
 * the validator AUTHENTICATES an NSEC RRset that proves that no DS RRset is
 * present for this zone, then there is no authentication path leading from the
 * parent to the child." Accepting an unauthenticated denial would let anyone
 * who can answer a query downgrade a signed zone to INSECURE simply by
 * asserting that it has no DS — which is a strictly better attack than
 * forging, because INSECURE answers are delivered to the client rather than
 * refused.
 */
export interface DenialEvidenceRrset {
  readonly rrset: RRset;
  readonly rrsigs: readonly Uint8Array[];
}

export type NoDsProof =
  | {
      readonly kind: 'nsec';
      readonly records: readonly NsecRecord[];
      readonly rrsets: readonly DenialEvidenceRrset[];
    }
  | {
      readonly kind: 'nsec3';
      readonly records: readonly Nsec3Record[];
      readonly rrsets: readonly DenialEvidenceRrset[];
      readonly params: Nsec3Params;
    };

/** Everything a validator was handed about one zone. */
export interface ZoneEvidence {
  readonly zone: Labels;
  /** Human label for the UI: "root", ".com", the zone's own name. */
  readonly title: string;
  readonly dnskeys: RRset | null;
  readonly dnskeyRrsigs: readonly Uint8Array[];
  /** The DS RRset published at the PARENT. Absent at the root. */
  readonly ds: RRset | null;
  readonly dsRrsigs: readonly Uint8Array[];
  /** Present when the parent instead proved this child has no DS. */
  readonly noDsProof?: NoDsProof;
}

export interface ChainLink {
  readonly title: string;
  readonly zone: Labels;
  readonly status: SecurityStatus;
  readonly failure: FailureCode | null;
  /** Ordered checks, exactly as the UI lists them. */
  readonly checks: readonly Check[];
  /** Keys this zone published, with their tags, for display. */
  readonly keys: readonly KeyInfo[];
  /** Which key the parent's DS vouched for, once one is found. */
  readonly vouchedKey: KeyInfo | null;
  readonly dsMatches: readonly DsMatch[];
  readonly dnskeyVerification: RrsetVerification | null;
  readonly dsVerification: RrsetVerification | null;
  readonly noDsProof: DenialProof | Nsec3Denial | null;
}

export interface ChainResult {
  readonly links: readonly ChainLink[];
  readonly answer: {
    readonly rrset: RRset;
    readonly verification: RrsetVerification;
  } | null;
  readonly status: SecurityStatus;
  readonly failure: FailureCode | null;
  /** The link index the chain stopped at, or -1 if it ran to the end. */
  readonly stoppedAt: number;
}

export interface ChainInput {
  readonly anchors: readonly AnchorDs[];
  /** Root first, then each child in turn. */
  readonly zones: readonly ZoneEvidence[];
  readonly answer: {
    readonly rrset: RRset;
    readonly rrsigs: readonly Uint8Array[];
  } | null;
  readonly now: number;
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

/**
 * Validate a chain from the trust anchor down to an answer.
 *
 * The walk stops at the first link that is not SECURE, and everything below is
 * simply not evaluated — which is what a real resolver does, and what makes
 * "which link" the whole diagnosis.
 */
export async function validateChain(input: ChainInput): Promise<ChainResult> {
  const links: ChainLink[] = [];
  let parentKeys: readonly Uint8Array[] = [];
  let parentZone: Labels | null = null;

  for (let i = 0; i < input.zones.length; i += 1) {
    const evidence = input.zones[i]!;
    const link = await validateLink(evidence, parentKeys, parentZone, input);
    links.push(link);
    if (link.status !== 'SECURE') {
      return {
        links,
        answer: null,
        status: link.status,
        failure: link.failure,
        stoppedAt: i,
      };
    }
    parentKeys = evidence.dnskeys?.rdatas ?? [];
    parentZone = evidence.zone;
  }

  if (!input.answer) {
    return { links, answer: null, status: 'SECURE', failure: null, stoppedAt: -1 };
  }

  const last = input.zones[input.zones.length - 1];
  const verification = await verifyRrset(
    input.answer.rrset,
    input.answer.rrsigs,
    last?.dnskeys?.rdatas ?? [],
    { zone: last?.zone ?? [], now: input.now }
  );
  return {
    links,
    answer: { rrset: input.answer.rrset, verification },
    status: verification.verified ? 'SECURE' : statusForFailure(verification.failure),
    failure: verification.failure,
    stoppedAt: verification.verified ? -1 : input.zones.length,
  };
}

function statusForFailure(code: FailureCode | null): SecurityStatus {
  if (code === null) return 'SECURE';
  if (code === 'ALG_UNSUPPORTED') return 'INDETERMINATE';
  if (code === 'DIGEST_UNSUPPORTED') return 'INSECURE';
  return 'BOGUS';
}

async function validateLink(
  evidence: ZoneEvidence,
  parentKeys: readonly Uint8Array[],
  parentZone: Labels | null,
  input: ChainInput
): Promise<ChainLink> {
  const checks: Check[] = [];
  const dsMatches: DsMatch[] = [];
  const keys = evidence.dnskeys ? describeKeys(evidence.dnskeys.rdatas) : [];
  const isRoot = parentZone === null;

  const stop = (code: FailureCode, status: SecurityStatus): ChainLink => ({
    title: evidence.title,
    zone: evidence.zone,
    status,
    failure: code,
    checks,
    keys,
    vouchedKey: null,
    dsMatches,
    dnskeyVerification: null,
    dsVerification: null,
    noDsProof: null,
  });

  // ── The parent's half: either a DS, or a signed proof there is none ───────
  let vouchedKey: KeyInfo | null = null;
  let dsVerification: RrsetVerification | null = null;

  if (isRoot) {
    // The root has no parent. Its keys are vouched for by the anchors the
    // validator was configured with -- the only keys in the whole system that
    // are not learned from the network.
    if (!evidence.dnskeys || evidence.dnskeys.rdatas.length === 0) {
      checks.push(fail('anchor', 'Trust anchor', 'the root published no DNSKEY records', 'NO_DNSKEY'));
      return stop('NO_DNSKEY', 'BOGUS');
    }
    let matched: DsMatch | null = null;
    for (const anchor of input.anchors) {
      const result = matchDs(anchor.rdata, evidence.zone, evidence.dnskeys.rdatas);
      dsMatches.push(result);
      if (result.matched) {
        matched = result;
        break;
      }
    }
    if (!matched || !matched.key) {
      checks.push(
        fail(
          'anchor',
          'Trust anchor',
          `none of the ${input.anchors.length} configured root anchors hashes to a key the root published`,
          matched?.failure ?? 'DS_MISMATCH'
        )
      );
      return stop(matched?.failure ?? 'DS_MISMATCH', 'BOGUS');
    }
    vouchedKey = matched.key;
    checks.push(
      pass(
        'anchor',
        'Trust anchor',
        `a configured root anchor hashes to the root key tagged ${matched.key.tag} — this is the one key in the system that is not learned from the network`
      )
    );
  } else if (evidence.noDsProof) {
    // The parent proved there is no DS. This is not a broken chain -- PROVIDED
    // the proof is authenticated. Verify every denial RRset under the parent's
    // keys FIRST; an unsigned or badly-signed denial is BOGUS, not INSECURE.
    const denialCode = evidence.noDsProof.kind === 'nsec' ? 'NSEC_PROOF_INVALID' : 'NSEC3_PROOF_INVALID';
    if (evidence.noDsProof.rrsets.length === 0) {
      checks.push(
        fail(
          'no-ds-signature',
          'Denial is signed',
          'the no-DS proof arrived with no records at all, so there is nothing to authenticate',
          denialCode
        )
      );
      return stop(denialCode, 'BOGUS');
    }
    for (const evidenceRrset of evidence.noDsProof.rrsets) {
      const denialVerification = await verifyRrset(
        evidenceRrset.rrset,
        evidenceRrset.rrsigs,
        parentKeys,
        { zone: parentZone, now: input.now }
      );
      if (!denialVerification.verified) {
        checks.push(
          fail(
            'no-ds-signature',
            'Denial is signed',
            `the ${presentName(evidenceRrset.rrset.name)} denial record does not verify under ${presentName(parentZone)}'s keys, so it proves nothing`,
            denialVerification.failure ?? denialCode
          )
        );
        return stop(denialVerification.failure ?? denialCode, statusForFailure(denialVerification.failure));
      }
    }
    checks.push(
      pass(
        'no-ds-signature',
        'Denial is signed',
        `${evidence.noDsProof.rrsets.length} denial record set${evidence.noDsProof.rrsets.length === 1 ? '' : 's'} verified under ${presentName(parentZone)}'s keys — the parent really is the one saying this`
      )
    );

    const proof =
      evidence.noDsProof.kind === 'nsec'
        ? proveNsecNoDs(evidence.noDsProof.records, evidence.zone, parentZone)
        : proveNsec3NoDs(
            evidence.noDsProof.records,
            evidence.zone,
            parentZone,
            evidence.noDsProof.params
          );
    for (const step of proof.steps) {
      checks.push(
        step.passed
          ? pass('no-ds', step.label, step.detail)
          : fail(
              'no-ds',
              step.label,
              step.detail,
              evidence.noDsProof.kind === 'nsec' ? 'NSEC_PROOF_INVALID' : 'NSEC3_PROOF_INVALID'
            )
      );
    }
    if (!proof.proven) {
      const code = evidence.noDsProof.kind === 'nsec' ? 'NSEC_PROOF_INVALID' : 'NSEC3_PROOF_INVALID';
      return stop(code, 'BOGUS');
    }
    return {
      title: evidence.title,
      zone: evidence.zone,
      status: 'INSECURE',
      failure: null,
      checks,
      keys,
      vouchedKey: null,
      dsMatches,
      dnskeyVerification: null,
      dsVerification: null,
      noDsProof: proof,
    };
  } else {
    if (!evidence.ds || evidence.ds.rdatas.length === 0) {
      checks.push(
        fail(
          'ds-present',
          'Delegation signer',
          `the parent published neither a DS for ${presentName(evidence.zone)} nor a proof that none exists`,
          'NO_RRSIG'
        )
      );
      return stop('NO_RRSIG', 'BOGUS');
    }
    // The DS lives at the PARENT and is signed by the PARENT's keys.
    dsVerification = await verifyRrset(evidence.ds, evidence.dsRrsigs, parentKeys, {
      zone: parentZone,
      now: input.now,
    });
    const deepest = dsVerification.attempts.reduce<Check[] | null>(
      (best, a) => (best === null || a.checks.length > best.length ? [...a.checks] : best),
      null
    );
    for (const check of deepest ?? []) {
      checks.push({ ...check, label: `DS at the parent — ${check.label}` });
    }
    if (!dsVerification.verified) {
      return stop(dsVerification.failure ?? 'SIGNATURE_INVALID', statusForFailure(dsVerification.failure));
    }

    if (!evidence.dnskeys || evidence.dnskeys.rdatas.length === 0) {
      checks.push(fail('dnskey-present', 'Child keys', 'the child published no DNSKEY records', 'NO_DNSKEY'));
      return stop('NO_DNSKEY', 'BOGUS');
    }

    let matched: DsMatch | null = null;
    // RFC 6840 section 5.2 covers BOTH kinds of "this validator cannot use
    // that": an unknown DS digest type and an unknown DNSKEY algorithm. Either
    // way the DS is disregarded, and if every DS the parent published is
    // disregarded then the delegation is UNSIGNED rather than broken. Treating
    // it as broken would raise a forgery alarm over a zone that is perfectly
    // correct and merely newer than this validator.
    const UNUSABLE: readonly (FailureCode | null)[] = ['DIGEST_UNSUPPORTED', 'ALG_UNSUPPORTED'];
    let unusableOnly = true;
    for (const rdata of evidence.ds.rdatas) {
      const result = matchDs(rdata, evidence.zone, evidence.dnskeys.rdatas);
      dsMatches.push(result);
      if (!UNUSABLE.includes(result.failure)) unusableOnly = false;
      if (result.matched) {
        matched = result;
        unusableOnly = false;
        break;
      }
    }
    if (!matched || !matched.key) {
      const shown = dsMatches[dsMatches.length - 1];
      for (const check of shown?.checks ?? []) {
        checks.push({ ...check, label: `DS digest — ${check.label}` });
      }
      if (unusableOnly) return stop(shown?.failure ?? 'DIGEST_UNSUPPORTED', 'INSECURE');
      return stop(shown?.failure ?? 'DS_MISMATCH', 'BOGUS');
    }
    // The vouched key must be allowed to sign this zone's RRsets at all
    // (RFC 4034 section 2.1.1). A DS pointing at a key with the Zone Key bit
    // clear vouches for something that may not sign anything here.
    if (!matched.key.isZoneKey) {
      checks.push(
        fail(
          'ds-zone-flag',
          'Vouched key is a zone key',
          `the DS points at key ${matched.key.tag}, whose Zone Key flag (bit 7) is clear — it may not sign this zone's RRsets`,
          'NOT_A_ZONE_KEY'
        )
      );
      return stop('NOT_A_ZONE_KEY', 'BOGUS');
    }
    vouchedKey = matched.key;
    for (const check of matched.checks) {
      checks.push({ ...check, label: `DS digest — ${check.label}` });
    }
  }

  // ── The child's half: its DNSKEY RRset must verify under a vouched key ────
  if (!evidence.dnskeys) {
    checks.push(fail('dnskey-present', 'Zone keys', 'this zone published no DNSKEY records', 'NO_DNSKEY'));
    return stop('NO_DNSKEY', 'BOGUS');
  }
  const dnskeyVerification = await verifyRrset(
    evidence.dnskeys,
    evidence.dnskeyRrsigs,
    evidence.dnskeys.rdatas,
    { zone: evidence.zone, now: input.now }
  );
  const winning = dnskeyVerification.attempts.find((a) => a.verified) ?? dnskeyVerification.attempts[0];
  for (const check of winning?.checks ?? []) {
    checks.push({ ...check, label: `DNSKEY self-signature — ${check.label}` });
  }
  if (!dnskeyVerification.verified) {
    return {
      title: evidence.title,
      zone: evidence.zone,
      status: statusForFailure(dnskeyVerification.failure),
      failure: dnskeyVerification.failure,
      checks,
      keys,
      vouchedKey,
      dsMatches,
      dnskeyVerification,
      dsVerification,
      noDsProof: null,
    };
  }

  // The key that signed the DNSKEY RRset must be THE VERY KEY the parent
  // vouched for -- compared as bytes, never by key tag.
  //
  // Comparing tags here would be a real vulnerability, not a stylistic point.
  // A tag is a 16-bit checksum, so an attacker can grind roughly 2^16 keypairs
  // until one collides with a zone's real KSK tag, persuade the zone to
  // publish it alongside the real key, and sign the DNSKEY RRset with theirs.
  // `verifyRrset` tries every key carrying the tag and stops at the one that
  // verifies, so the key that VERIFIED would be the attacker's while the key
  // the DS matched is the real one -- and a tag comparison would call that a
  // match. RFC 4035 section 5.2 requires that "the corresponding private key
  // has signed the child zone's apex DNSKEY RRset", which is a statement about
  // the key, not about its index.
  const signer = dnskeyVerification.attempts.find((a) => a.verified)?.keyUsed ?? null;
  const sameKey =
    signer !== null && vouchedKey !== null && compareBytes(signer.rdata, vouchedKey.rdata) === 0;
  if (!sameKey) {
    checks.push(
      fail(
        'binding',
        'Vouched key signed the set',
        signer && vouchedKey && signer.tag === vouchedKey.tag
          ? `the DNSKEY RRset was signed by a DIFFERENT key that happens to share tag ${signer.tag} with the one the parent vouched for — a tag is a checksum, so a collision proves nothing`
          : signer
            ? `the DNSKEY RRset was signed by key ${signer.tag}, but the parent vouched for key ${vouchedKey?.tag}`
            : 'no key could be identified as the signer of the DNSKEY RRset',
        'KEYTAG_MISMATCH'
      )
    );
    return stop('KEYTAG_MISMATCH', 'BOGUS');
  }
  checks.push(
    pass(
      'binding',
      'Vouched key signed the set',
      `the key that signed this zone's DNSKEY RRset is byte-for-byte the key the parent vouched for (tag ${signer.tag}), so trust carries across the cut`
    )
  );

  return {
    title: evidence.title,
    zone: evidence.zone,
    status: 'SECURE',
    failure: null,
    checks,
    keys,
    vouchedKey,
    dsMatches,
    dnskeyVerification,
    dsVerification,
    // A link that reaches this point took the DS route, not the no-DS route:
    // the unsigned-delegation branch returns from inside the `if` above.
    noDsProof: null,
  };
}
