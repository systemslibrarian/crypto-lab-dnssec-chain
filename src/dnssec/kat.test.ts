/**
 * Known-answer tests against the specifications.
 *
 * These are the tests that decide whether anything else in this lab means
 * something. A demo can render a beautiful chain of green ticks while
 * assembling the signed data wrongly — the only thing that catches it is a
 * signature made by somebody else, over bytes published by somebody else,
 * verifying here.
 */

import { describe, expect, it } from 'vitest';

import { fromBase32Hex, fromHex, toBase32Hex, toHex } from '../dns/codec.ts';
import { parseName, presentName } from '../dns/name.ts';
import { decodeDs } from '../dns/rdata.ts';
import { RR_TYPE, toRRsets } from '../dns/types.ts';
import { parseRecords } from '../dns/zonefile.ts';
import { dsPreimage } from './canonical.ts';
import { digest } from './crypto.ts';
import { keyTag } from './keytag.ts';
import {
  isOptOut,
  nsec3Covers,
  nsec3Hash,
  nsec3Matches,
  toNsec3Record,
  type Nsec3Params,
} from './nsec3.ts';
import { matchDs, verifyRrset } from './verify.ts';
import {
  RFC4034_DSKEY,
  RFC4034_DSKEY_TAG,
  RFC5155_HASHES,
  RFC5155_KEYS,
  RFC5155_KSK_TAG,
  RFC5155_NSEC3,
  RFC5155_PARAMS,
  RFC5155_ZSK_TAG,
  RFC6605_P256,
  RFC6605_P256_TAG,
  RFC6605_P384,
  RFC6605_P384_TAG,
  RFC8080_ED25519_1,
  RFC8080_ED25519_1_TAG,
  RFC8080_ED25519_2,
  RFC8080_ED25519_2_TAG,
  RFC8080_ED448,
  RFC8080_ED448_TAG,
} from '../vectors/rfc.ts';

/** Flip bits in a copy, so a mutation test cannot corrupt the shared vector. */
const flip = (bytes: Uint8Array, index: number, mask: number): Uint8Array => {
  const copy = Uint8Array.from(bytes);
  const at = copy[index];
  if (at === undefined) throw new Error(`index ${index} is past the end of the buffer`);
  copy[index] = at ^ mask;
  return copy;
};

const rdataOf = (text: string, type: number, index = 0): Uint8Array => {
  const matches = parseRecords(text).filter((r) => r.type === type);
  const record = matches[index];
  if (!record) throw new Error(`no record of type ${type} at index ${index}`);
  return record.rdata;
};

describe('key tag (RFC 4034 Appendix B)', () => {
  it('reproduces the tag the RFC 4034 section 5.4 example states (60485)', () => {
    expect(keyTag(rdataOf(RFC4034_DSKEY, RR_TYPE.DNSKEY))).toBe(RFC4034_DSKEY_TAG);
  });

  it('reproduces the RFC 6605 example tags (55648, 10771)', () => {
    expect(keyTag(rdataOf(RFC6605_P256, RR_TYPE.DNSKEY))).toBe(RFC6605_P256_TAG);
    expect(keyTag(rdataOf(RFC6605_P384, RR_TYPE.DNSKEY))).toBe(RFC6605_P384_TAG);
  });

  it('reproduces the RFC 8080 example tags (3613, 35217, 9713)', () => {
    expect(keyTag(rdataOf(RFC8080_ED25519_1, RR_TYPE.DNSKEY))).toBe(RFC8080_ED25519_1_TAG);
    expect(keyTag(rdataOf(RFC8080_ED25519_2, RR_TYPE.DNSKEY))).toBe(RFC8080_ED25519_2_TAG);
    expect(keyTag(rdataOf(RFC8080_ED448, RR_TYPE.DNSKEY))).toBe(RFC8080_ED448_TAG);
  });

  it('reproduces the RFC 5155 Appendix A tags, pinned by that zone’s own RRSIGs', () => {
    // The ZSK signs the zone at tag 40430; the KSK signs the DNSKEY RRset at
    // tag 12708. Both numbers come from RRSIG records in the appendix.
    expect(keyTag(rdataOf(RFC5155_KEYS, RR_TYPE.DNSKEY, 0))).toBe(RFC5155_ZSK_TAG);
    expect(keyTag(rdataOf(RFC5155_KEYS, RR_TYPE.DNSKEY, 1))).toBe(RFC5155_KSK_TAG);
  });

  it('is a checksum over the whole RDATA, so flipping any octet moves it', () => {
    const rdata = rdataOf(RFC6605_P256, RR_TYPE.DNSKEY);
    expect(keyTag(flip(rdata, rdata.length - 1, 0x01))).not.toBe(RFC6605_P256_TAG);
  });
});

describe('DS digest (RFC 4034 section 5.1.4)', () => {
  const dsCase = (text: string, owner: string): void => {
    const key = rdataOf(text, RR_TYPE.DNSKEY);
    const ds = decodeDs(rdataOf(text, RR_TYPE.DS));
    const computed = digest(ds.digestType, dsPreimage(parseName(owner), key));
    expect(toHex(computed)).toBe(toHex(ds.digest));
  };

  it('reproduces the SHA-1 digest in RFC 4034 section 5.4', () => {
    dsCase(RFC4034_DSKEY, 'dskey.example.com.');
  });

  it('reproduces the SHA-256 digest in RFC 6605 section 6.1', () => {
    dsCase(RFC6605_P256, 'example.net.');
  });

  it('reproduces the SHA-384 digest in RFC 6605 section 6.2', () => {
    dsCase(RFC6605_P384, 'example.net.');
  });

  it('reproduces both SHA-256 digests in RFC 8080 section 6.1', () => {
    dsCase(RFC8080_ED25519_1, 'example.com.');
    dsCase(RFC8080_ED25519_2, 'example.com.');
  });

  it('reproduces the Ed448 DS digest even though algorithm 16 is unimplemented', () => {
    // The digest is over bytes, so it is computable for an algorithm this
    // validator cannot verify signatures for. Conflating the two is how a
    // validator reports DS_MISMATCH for a zone whose DS is perfectly correct.
    dsCase(RFC8080_ED448, 'example.com.');
  });

  it('binds the key to its owner name: the same key at another name fails', () => {
    const key = rdataOf(RFC6605_P256, RR_TYPE.DNSKEY);
    const ds = decodeDs(rdataOf(RFC6605_P256, RR_TYPE.DS));
    const elsewhere = digest(ds.digestType, dsPreimage(parseName('example.org.'), key));
    expect(toHex(elsewhere)).not.toBe(toHex(ds.digest));
  });

  it('reports a corrupted digest as DS_MISMATCH, not as a missing key', () => {
    const records = parseRecords(RFC6605_P256);
    const original = rdataOf(RFC6605_P256, RR_TYPE.DS);
    const dsRdata = flip(original, original.length - 1, 0xff);
    const keys = records.filter((r) => r.type === RR_TYPE.DNSKEY).map((r) => r.rdata);
    const result = matchDs(dsRdata, parseName('example.net.'), keys);
    expect(result.matched).toBe(false);
    expect(result.failure).toBe('DS_MISMATCH');
  });
});

describe('RRSIG verification over the signed-data construction (RFC 4034 section 3.1.8.1)', () => {
  /**
   * Verify a vector's RRSIG against its own DNSKEY. This is the whole
   * canonicalization pipeline under test at once: canonical owner name,
   * original TTL, RDATA ordering, the RRSIG prefix with its down-cased signer
   * name, and the algorithm's own encoding rules.
   */
  // Absolute instants inside each vector's own printed validity window, so a
  // vector is judged at a time the RFC itself chose rather than at "now".
  const INSIDE_RFC6605 = Date.UTC(2010, 7, 15) / 1000; // 20100812..20100909
  const INSIDE_RFC8080 = 1_439_000_000; // 1438207200..1440021600

  const verifyVector = async (
    text: string,
    owner: string,
    zone: string,
    type: number,
    now: number
  ): Promise<Awaited<ReturnType<typeof verifyRrset>>> => {
    const records = parseRecords(text);
    const covered = toRRsets(records.filter((r) => r.type === type && presentName(r.name) === owner));
    const sigs = records.filter((r) => r.type === RR_TYPE.RRSIG).map((r) => r.rdata);
    const keys = records.filter((r) => r.type === RR_TYPE.DNSKEY).map((r) => r.rdata);
    const rrset = covered[0];
    if (!rrset) throw new Error('vector has no covered RRset');
    return verifyRrset(rrset, sigs, keys, { zone: parseName(zone), now });
  };

  it('verifies the RFC 6605 section 6.1 ECDSA P-256 signature', async () => {
    const result = await verifyVector(
      RFC6605_P256,
      'www.example.net.',
      'example.net.',
      RR_TYPE.A,
      INSIDE_RFC6605
    );
    expect(result.failure).toBeNull();
    expect(result.verified).toBe(true);
    expect(result.attempts[0]?.keyUsed?.tag).toBe(RFC6605_P256_TAG);
  });

  it('reports RFC 6605 section 6.2 (P-384, algorithm 14) as ALG_UNSUPPORTED, not forged', async () => {
    const result = await verifyVector(
      RFC6605_P384,
      'www.example.net.',
      'example.net.',
      RR_TYPE.A,
      INSIDE_RFC6605
    );
    expect(result.verified).toBe(false);
    expect(result.failure).toBe('ALG_UNSUPPORTED');
  });

  it('verifies both RFC 8080 Ed25519 signatures (errata 4935 text)', async () => {
    for (const [vector, tag] of [
      [RFC8080_ED25519_1, RFC8080_ED25519_1_TAG],
      [RFC8080_ED25519_2, RFC8080_ED25519_2_TAG],
    ] as const) {
      const result = await verifyVector(
        vector,
        'example.com.',
        'example.com.',
        RR_TYPE.MX,
        INSIDE_RFC8080
      );
      expect(result.failure).toBeNull();
      expect(result.verified).toBe(true);
      expect(result.attempts[0]?.keyUsed?.tag).toBe(tag);
    }
  });

  it('rejects the RFC 6605 vector when one RDATA octet is flipped', async () => {
    const records = parseRecords(RFC6605_P256);
    const a = records.find((r) => r.type === RR_TYPE.A);
    if (!a) throw new Error('vector lost its A record');
    const tampered = flip(a.rdata, 3, 0x01); // 192.0.2.1 -> 192.0.2.0
    const rrset = { name: a.name, type: a.type, class: a.class, ttl: a.ttl, rdatas: [tampered] };
    const result = await verifyRrset(
      rrset,
      records.filter((r) => r.type === RR_TYPE.RRSIG).map((r) => r.rdata),
      records.filter((r) => r.type === RR_TYPE.DNSKEY).map((r) => r.rdata),
      { zone: parseName('example.net.'), now: INSIDE_RFC6605 }
    );
    expect(result.verified).toBe(false);
    expect(result.failure).toBe('SIGNATURE_INVALID');
  });

  it('reports an out-of-window instant as expired or not-yet-valid, never as forged', async () => {
    const records = parseRecords(RFC6605_P256);
    const rrset = toRRsets(records.filter((r) => r.type === RR_TYPE.A))[0]!;
    const sigs = records.filter((r) => r.type === RR_TYPE.RRSIG).map((r) => r.rdata);
    const keys = records.filter((r) => r.type === RR_TYPE.DNSKEY).map((r) => r.rdata);
    const zone = parseName('example.net.');

    const late = await verifyRrset(rrset, sigs, keys, { zone, now: 1_400_000_000 });
    expect(late.failure).toBe('RRSIG_EXPIRED');

    const early = await verifyRrset(rrset, sigs, keys, { zone, now: 1_000_000_000 });
    expect(early.failure).toBe('RRSIG_NOT_YET_VALID');
  });

  it('reports a signer name from another zone as SIGNER_NAME_MISMATCH', async () => {
    const records = parseRecords(RFC6605_P256);
    const rrset = toRRsets(records.filter((r) => r.type === RR_TYPE.A))[0]!;
    const result = await verifyRrset(
      rrset,
      records.filter((r) => r.type === RR_TYPE.RRSIG).map((r) => r.rdata),
      records.filter((r) => r.type === RR_TYPE.DNSKEY).map((r) => r.rdata),
      { zone: parseName('example.org.'), now: INSIDE_RFC6605 }
    );
    expect(result.failure).toBe('SIGNER_NAME_MISMATCH');
  });

  it('reports NO_RRSIG when a signed zone serves an RRset with no signature', async () => {
    const records = parseRecords(RFC6605_P256);
    const rrset = toRRsets(records.filter((r) => r.type === RR_TYPE.A))[0]!;
    const result = await verifyRrset(rrset, [], [], {
      zone: parseName('example.net.'),
      now: INSIDE_RFC6605,
    });
    expect(result.failure).toBe('NO_RRSIG');
  });
});

describe('NSEC3 hash (RFC 5155 section 5 and Appendix A)', () => {
  const params: Nsec3Params = {
    hashAlgorithm: RFC5155_PARAMS.hashAlgorithm,
    iterations: RFC5155_PARAMS.iterations,
    salt: fromHex(RFC5155_PARAMS.saltHex),
  };

  it.each(RFC5155_HASHES)('hashes %s to %s', (name, expected) => {
    expect(toBase32Hex(nsec3Hash(parseName(name), params)).toLowerCase()).toBe(expected);
  });

  it('counts iterations as ADDITIONAL hashes, so 12 means 13 invocations', () => {
    // The off-by-one this catches is the most common NSEC3 bug there is: the
    // whole Appendix A table only reproduces at k+1 total hashes.
    const off = { ...params, iterations: RFC5155_PARAMS.iterations - 1 };
    expect(toBase32Hex(nsec3Hash(parseName('example.'), off)).toLowerCase()).not.toBe(
      RFC5155_HASHES[0]?.[1]
    );
  });

  it('hashes the WIRE form, not the presentation text', () => {
    // The appendix includes `2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.` on
    // purpose: it is a real name whose first label looks like a hash. An
    // implementation that hashed the printed string would still produce a
    // plausible answer, and a different one.
    const entry = RFC5155_HASHES.find(([n]) => n.startsWith('2t7b4g4'));
    if (!entry) throw new Error('vector table lost its hash-shaped owner name');
    expect(toBase32Hex(nsec3Hash(parseName(entry[0]), params)).toLowerCase()).toBe(entry[1]);
  });

  it('leaves a wildcard label unexpanded', () => {
    const entry = RFC5155_HASHES.find(([n]) => n === '*.w.example.');
    if (!entry) throw new Error('vector table lost its wildcard entry');
    expect(toBase32Hex(nsec3Hash(parseName(entry[0]), params)).toLowerCase()).toBe(entry[1]);
  });

  it('changes completely when the salt changes', () => {
    const other = { ...params, salt: fromHex('aabbccde') };
    expect(toBase32Hex(nsec3Hash(parseName('example.'), other)).toLowerCase()).not.toBe(
      RFC5155_HASHES[0]?.[1]
    );
  });
});

describe('NSEC3 coverage against the RFC 5155 Appendix A chain', () => {
  const params: Nsec3Params = {
    hashAlgorithm: RFC5155_PARAMS.hashAlgorithm,
    iterations: RFC5155_PARAMS.iterations,
    salt: fromHex(RFC5155_PARAMS.saltHex),
  };
  const records = parseRecords(RFC5155_NSEC3)
    .filter((r) => r.type === RR_TYPE.NSEC3)
    .map((r) => {
      const first = r.name[0];
      if (!first) throw new Error('NSEC3 owner has no labels');
      return toNsec3Record(r.name, r.rdata, fromBase32Hex(new TextDecoder().decode(first)));
    });

  it('parses the appendix records with their published parameters', () => {
    expect(records).toHaveLength(3);
    for (const record of records) {
      expect(record.rdata.hashAlgorithm).toBe(1);
      expect(record.rdata.iterations).toBe(12);
      expect(toHex(record.rdata.salt)).toBe('AABBCCDD');
      // Every record in that appendix has the Opt-Out flag set, even though
      // the zone's NSEC3PARAM has flags 0. Both are correct: RFC 5155 section
      // 4.1.2 requires NSEC3PARAM's flag to be zero. An implementation that
      // compared the two for equality would reject this real zone.
      expect(isOptOut(record)).toBe(true);
    }
  });

  it('spans the interval its own owner and next-hash define', () => {
    // `2t7b4g4vsa5smi47k61mv5bv1a22bojr` is the hash of `ns1.example.`, and it
    // is the NEXT hash of the apex record — so the apex record must cover
    // everything strictly between the two, and match neither endpoint.
    const apex = records[0];
    const nsOne = nsec3Hash(parseName('ns1.example.'), params);
    if (!apex) throw new Error('appendix chain lost its apex record');
    expect(nsec3Matches(apex, nsec3Hash(parseName('example.'), params))).toBe(true);
    expect(nsec3Matches(apex, nsOne)).toBe(false);
    expect(nsec3Covers(apex, nsOne)).toBe(false); // the interval is half-open
  });

  it('covers a hash that falls inside a gap and refuses one that does not', () => {
    const apex = records[0];
    if (!apex) throw new Error('appendix chain lost its apex record');
    // A hash that sorts strictly between the apex's own hash (which starts
    // '0p9…') and its next hash ('2t7…'). Every character is inside the
    // extended-hex alphabet, 0-9 then A-V — using a letter past V is the
    // classic way to reach for the wrong base32 table.
    const inside = fromBase32Hex('1abcdefghijklmnopqrstuv012345678');
    const outside = fromBase32Hex('gjeqe526plbf1g8mklp59enfd789njgi'); // ai.example.
    expect(nsec3Covers(apex, inside)).toBe(true);
    expect(nsec3Covers(apex, outside)).toBe(false);
  });
});
