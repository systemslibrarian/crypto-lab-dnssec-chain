/**
 * The DNSKEY key tag (RFC 4034 Appendix B), hand-rolled from the RFC's own C.
 *
 * The key tag is not a hash and is not a fingerprint: it is a 16-bit
 * ones-complement-style checksum over the DNSKEY RDATA, and it exists only as
 * a HINT so a validator can pick likely keys out of a DNSKEY RRset instead of
 * trying all of them. Two distinct keys in the same zone can share a tag, and
 * a zone can even carry a key whose tag collides deliberately.
 *
 * That distinction is load-bearing for this lab. A validator that treats a
 * matching key tag as evidence of anything has confused a lookup index with an
 * authentication check — the signature is the only thing that authenticates.
 * So the tag gets its own named failure (`KEYTAG_MISMATCH`, meaning "no key in
 * this RRset even claims to be the signer"), and `verifyRrset` still tries
 * EVERY key whose tag matches rather than stopping at the first.
 *
 * RFC 4034 Appendix B:
 *
 *     ac = 0
 *     for i in 0..keysize-1:
 *         ac += (i & 1) ? key[i] : key[i] << 8
 *     ac += (ac >> 16) & 0xFFFF
 *     return ac & 0xFFFF
 *
 * where `key` is the DNSKEY RDATA — flags, protocol, algorithm, public key —
 * and NOT the public key on its own.
 */

import { decodeDnskey } from '../dns/rdata.ts';

/**
 * Compute the key tag over DNSKEY RDATA.
 *
 * Algorithm 1 (RSA/MD5) uses the different rule in Appendix B.1 — the most
 * significant 16 bits of the least significant 24 bits of the modulus. It is
 * implemented for completeness and because omitting it silently is how a
 * validator ends up computing a confidently wrong tag; algorithm 1 has been
 * MUST NOT-for-signing since RFC 6944 and this lab does not verify it.
 */
export function keyTag(dnskeyRdata: Uint8Array): number {
  if (dnskeyRdata.length < 4) throw new Error('DNSKEY RDATA too short to carry a key tag');
  const algorithm = dnskeyRdata[3]!;
  if (algorithm === 1) {
    if (dnskeyRdata.length < 7) throw new Error('RSA/MD5 DNSKEY RDATA too short for the B.1 rule');
    const hi = dnskeyRdata[dnskeyRdata.length - 3]!;
    const lo = dnskeyRdata[dnskeyRdata.length - 2]!;
    return (hi << 8) | lo;
  }
  let ac = 0;
  for (let i = 0; i < dnskeyRdata.length; i += 1) {
    ac += i & 1 ? dnskeyRdata[i]! : dnskeyRdata[i]! << 8;
  }
  // Verified Errata 4552 rewrote Appendix B's prose here: the sum is kept at
  // "at least 32-bit precision, retaining any carry bits", the carries are
  // then folded back in, and only the low 16 bits are the tag. The fold is
  // written with division rather than `>>` on purpose — JavaScript's bitwise
  // operators coerce to a SIGNED 32-bit integer, and a maximum-length DNSKEY
  // RDATA can push this accumulator past 2^31, where `ac >> 16` would go
  // negative and quietly return the wrong tag.
  ac += Math.floor(ac / 0x10000) & 0xffff;
  return ac & 0xffff;
}

/** A DNSKEY paired with its computed tag and the flag bits that classify it. */
export interface KeyInfo {
  readonly rdata: Uint8Array;
  readonly tag: number;
  readonly flags: number;
  readonly protocol: number;
  readonly algorithm: number;
  readonly publicKey: Uint8Array;
  /** Bit 7 of the flags: this key signs RRsets in its own zone. */
  readonly isZoneKey: boolean;
  /**
   * Bit 15, the Secure Entry Point bit. Conventionally set on a KSK — but it
   * is a HINT with no protocol meaning, exactly like the key tag. A validator
   * that refused to follow a DS to a key without the SEP bit would reject
   * perfectly valid zones, so nothing in this lab branches on it.
   */
  readonly isSep: boolean;
}

export function describeKey(dnskeyRdata: Uint8Array): KeyInfo {
  const k = decodeDnskey(dnskeyRdata);
  return {
    rdata: dnskeyRdata,
    tag: keyTag(dnskeyRdata),
    flags: k.flags,
    protocol: k.protocol,
    algorithm: k.algorithm,
    publicKey: k.publicKey,
    isZoneKey: (k.flags & 0x0100) !== 0,
    isSep: (k.flags & 0x0001) !== 0,
  };
}

/** Every DNSKEY in an RRset, described. */
export function describeKeys(rdatas: readonly Uint8Array[]): KeyInfo[] {
  return rdatas.map(describeKey);
}
