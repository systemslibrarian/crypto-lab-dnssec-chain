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

/** Proof, from the parent, that a child has no DS — i.e. is unsigned. */
export type NoDsProof =
  | { readonly kind: 'nsec'; readonly records: readonly NsecRecord[] }
  | {
      readonly kind: 'nsec3';
      readonly records: readonly Nsec3Record[];
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
  let noDsProof: DenialProof | Nsec3Denial | null = null;

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
    // The parent proved there is no DS. This is not a broken chain.
    const proof =
      evidence.noDsProof.kind === 'nsec'
        ? proveNsecNoDs(evidence.noDsProof.records, evidence.zone)
        : proveNsec3NoDs(
            evidence.noDsProof.records,
            evidence.zone,
            parentZone,
            evidence.noDsProof.params
          );
    noDsProof = proof;
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
    checks.push(...dsVerification.attempts.flatMap((a) => a.checks).slice(0, 0));
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
    let unsupportedOnly = true;
    for (const rdata of evidence.ds.rdatas) {
      const result = matchDs(rdata, evidence.zone, evidence.dnskeys.rdatas);
      dsMatches.push(result);
      if (result.failure !== 'DIGEST_UNSUPPORTED') unsupportedOnly = false;
      if (result.matched) {
        matched = result;
        unsupportedOnly = false;
        break;
      }
    }
    if (!matched || !matched.key) {
      const shown = dsMatches[dsMatches.length - 1];
      for (const check of shown?.checks ?? []) {
        checks.push({ ...check, label: `DS digest — ${check.label}` });
      }
      // RFC 6840 section 5.2: a DS whose digest algorithm the validator cannot
      // compute must be treated exactly like no DS at all. If EVERY DS is like
      // that, the delegation is unsigned rather than broken.
      if (unsupportedOnly) return stop('DIGEST_UNSUPPORTED', 'INSECURE');
      return stop(shown?.failure ?? 'DS_MISMATCH', 'BOGUS');
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

  // The key that signed the DNSKEY RRset must be the very key the parent
  // vouched for. Without this the DS would prove nothing: a zone could publish
  // an attacker's key alongside its own and sign the set with the attacker's.
  const signer = dnskeyVerification.attempts.find((a) => a.verified)?.keyUsed ?? null;
  if (!signer || !vouchedKey || signer.tag !== vouchedKey.tag) {
    checks.push(
      fail(
        'binding',
        'Vouched key signed the set',
        signer
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
      `key ${signer.tag} is both the key the parent vouched for and the key that signed this zone's DNSKEY RRset, so trust carries across the cut`
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
    noDsProof,
  };
}
