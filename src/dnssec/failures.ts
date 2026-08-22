/**
 * Named failures.
 *
 * A validator that answers "invalid" has told you nothing. DNSSEC has a small
 * number of genuinely different ways to fail, they have different causes, and
 * two of them are not failures at all — so every rejection in this lab carries
 * a code, a plain-language cause, and the section of the RFC that defines it.
 *
 * The distinction that matters most, and that this lab exists partly to fix:
 * INSECURE is not a weaker BOGUS. BOGUS means the data is signed and the
 * signatures do not check out — someone is lying, or something is broken, and
 * a validating resolver returns SERVFAIL. INSECURE means the chain of trust
 * legitimately ends: a parent zone PROVED, with a signature, that its child
 * has no DS record, so the child is simply unsigned. That answer is delivered
 * normally. Reading INSECURE as an attack, or as a soft failure, is a routine
 * misreading and it is exactly backwards — the proof of insecurity is itself a
 * cryptographically verified statement.
 */

/** RFC 4033 section 5: the four things a validator can conclude. */
export type SecurityStatus = 'SECURE' | 'INSECURE' | 'BOGUS' | 'INDETERMINATE';

export type FailureCode =
  | 'DS_MISMATCH'
  | 'RRSIG_EXPIRED'
  | 'RRSIG_NOT_YET_VALID'
  | 'KEYTAG_MISMATCH'
  | 'ALG_UNSUPPORTED'
  | 'DIGEST_UNSUPPORTED'
  | 'SIGNER_NAME_MISMATCH'
  | 'TYPE_COVERED_MISMATCH'
  | 'LABELS_INVALID'
  | 'SIGNATURE_INVALID'
  | 'NO_RRSIG'
  | 'NO_DNSKEY'
  | 'NOT_A_ZONE_KEY'
  | 'NSEC_PROOF_INVALID'
  | 'NSEC3_PROOF_INVALID';

export interface FailureInfo {
  /** Short heading, as the UI labels the failed step. */
  readonly title: string;
  /** One sentence a newcomer can act on. No jargon that is not introduced. */
  readonly plain: string;
  /** Where the rule lives, so an expert can check the claim. */
  readonly reference: string;
  /**
   * Whether this failure makes the answer BOGUS, or ends the chain of trust
   * legitimately at INSECURE. Getting this wrong in either direction is the
   * classic DNSSEC implementation bug.
   */
  readonly verdict: Exclude<SecurityStatus, 'SECURE'>;
}

export const FAILURES: Readonly<Record<FailureCode, FailureInfo>> = {
  DS_MISMATCH: {
    title: 'DS digest does not match the child key',
    plain:
      'The parent published a fingerprint of the child zone’s key. Hashing the key the child actually served gives a different value, so the parent is not vouching for this key.',
    reference: 'RFC 4034 section 5.1.4, RFC 4035 section 5.2',
    verdict: 'BOGUS',
  },
  RRSIG_EXPIRED: {
    title: 'Signature has expired',
    plain:
      'Every DNSSEC signature carries its own expiry. This one’s expiration is in the past relative to the clock in use, so it is no longer usable no matter how good the maths is.',
    reference: 'RFC 4035 section 5.3.1',
    verdict: 'BOGUS',
  },
  RRSIG_NOT_YET_VALID: {
    title: 'Signature is not valid yet',
    plain:
      'The signature’s inception time is in the future relative to the clock in use. A validator with a wrong clock produces this against perfectly good data — DNSSEC validity is wall-clock, so a bad clock is a real outage.',
    reference: 'RFC 4035 section 5.3.1',
    verdict: 'BOGUS',
  },
  KEYTAG_MISMATCH: {
    title: 'No key in the zone claims to be the signer',
    plain:
      'The signature names a key by its 16-bit tag, and no DNSKEY in this zone has that tag. The tag is only a lookup hint — it never authenticates anything — but with no candidate key there is nothing to try.',
    reference: 'RFC 4034 Appendix B, RFC 4035 section 5.3.1',
    verdict: 'BOGUS',
  },
  ALG_UNSUPPORTED: {
    title: 'Signing algorithm not implemented here',
    plain:
      'The signature uses a real DNSSEC algorithm this lab does not implement. That is a statement about this validator, not about the data — which is why it is reported separately rather than as a forgery.',
    reference: 'RFC 4035 section 5.2, RFC 6840 section 5.2',
    verdict: 'INDETERMINATE',
  },
  DIGEST_UNSUPPORTED: {
    title: 'DS digest algorithm not implemented here',
    plain:
      'The DS uses a digest algorithm this validator cannot compute. RFC 6840 says to treat that exactly like having no DS at all — the delegation becomes unsigned, not broken.',
    reference: 'RFC 6840 section 5.2',
    verdict: 'INSECURE',
  },
  SIGNER_NAME_MISMATCH: {
    title: 'Signer name is not this zone',
    plain:
      'The signature says it was made by a key in a different zone. Accepting it would let any zone sign for any other, which is the whole property the hierarchy exists to prevent.',
    reference: 'RFC 4035 section 5.3.1',
    verdict: 'BOGUS',
  },
  TYPE_COVERED_MISMATCH: {
    title: 'Signature covers a different record type',
    plain:
      'The RRSIG’s Type Covered field names a type other than the records it was offered with. A signature over the A records says nothing about the MX records.',
    reference: 'RFC 4035 section 5.3.1',
    verdict: 'BOGUS',
  },
  LABELS_INVALID: {
    title: 'Label count is impossible for this name',
    plain:
      'The signature claims more labels than the owner name has. The Labels field is how a validator learns an answer came from a wildcard, so a value it cannot reconcile is unusable.',
    reference: 'RFC 4034 section 3.1.3, RFC 4035 section 5.3.1',
    verdict: 'BOGUS',
  },
  SIGNATURE_INVALID: {
    title: 'Signature does not verify over these bytes',
    plain:
      'The key, the algorithm, and the timing were all fine, and the cryptographic check still failed: the records handed over are not the records that were signed.',
    reference: 'RFC 4035 section 5.3.3',
    verdict: 'BOGUS',
  },
  NO_RRSIG: {
    title: 'No signature at all',
    plain:
      'The zone is signed, so this record should have come with an RRSIG and did not. Missing data inside a signed zone is a failure, not an absence.',
    reference: 'RFC 4035 section 5.3',
    verdict: 'BOGUS',
  },
  NO_DNSKEY: {
    title: 'Zone published no usable key',
    plain: 'There is no DNSKEY RRset to check the signature against, so nothing can be verified.',
    reference: 'RFC 4035 section 5.3.1',
    verdict: 'BOGUS',
  },
  NOT_A_ZONE_KEY: {
    title: 'Key is not marked as a zone key',
    plain:
      'Bit 7 of the DNSKEY flags says whether a key is allowed to sign RRsets in its own zone. This one is not, so it may not be used to validate this RRset.',
    reference: 'RFC 4034 section 2.1.1, RFC 4035 section 5.3.1',
    verdict: 'BOGUS',
  },
  NSEC_PROOF_INVALID: {
    title: 'Denial proof does not cover the name',
    plain:
      'The NSEC record offered as proof that a name does not exist does not actually span that name. A denial is only as good as the interval it names.',
    reference: 'RFC 4035 section 5.4',
    verdict: 'BOGUS',
  },
  NSEC3_PROOF_INVALID: {
    title: 'Hashed denial proof does not cover the name',
    plain:
      'The NSEC3 record offered as proof does not span the hash of the queried name, or its parameters do not match the zone’s.',
    reference: 'RFC 5155 section 8',
    verdict: 'BOGUS',
  },
};

/**
 * The failure CODES the break-it-yourself exhibit lists, in the order it shows
 * them.
 *
 * Six, not eight. `BOGUS` and `INSECURE` belong to the outcome vocabulary
 * above rather than to this one — they are what a validator CONCLUDES, not
 * what went wrong — so they cannot appear in a `FailureCode[]`, and the two
 * exhibits that teach them say so in their own words instead.
 */
export const HEADLINE_FAILURE_CODES: readonly FailureCode[] = [
  'DS_MISMATCH',
  'RRSIG_EXPIRED',
  'RRSIG_NOT_YET_VALID',
  'KEYTAG_MISMATCH',
  'ALG_UNSUPPORTED',
  'NSEC_PROOF_INVALID',
];

export interface StatusInfo {
  readonly title: string;
  readonly plain: string;
  readonly reference: string;
}

export const STATUS: Readonly<Record<SecurityStatus, StatusInfo>> = {
  SECURE: {
    title: 'Secure',
    plain:
      'An unbroken chain of signatures runs from the trust anchor to this answer, and every link verified.',
    reference: 'RFC 4033 section 5',
  },
  INSECURE: {
    title: 'Insecure',
    plain:
      'The chain of trust ends legitimately: a signed parent proved this child has no DS record, so the child is unsigned. This is a normal answer, not a failure — most of the DNS is here.',
    reference: 'RFC 4033 section 5, RFC 4035 section 5.2',
  },
  BOGUS: {
    title: 'Bogus',
    plain:
      'The data claims to be signed and the signatures do not check out. A validating resolver refuses to return it at all and answers SERVFAIL.',
    reference: 'RFC 4033 section 5',
  },
  INDETERMINATE: {
    title: 'Indeterminate',
    plain:
      'There is no trust anchor covering this name, or no algorithm here can judge it. The validator is declining to have an opinion rather than making one up.',
    reference: 'RFC 4033 section 5',
  },
};
