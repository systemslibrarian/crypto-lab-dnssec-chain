/**
 * The real cryptography: digests, signature verification, signature
 * generation.
 *
 * Nothing here is simulated. Signatures are verified by WebCrypto (RSASSA-
 * PKCS1-v1_5 for algorithm 8, ECDSA P-256 for algorithm 13) and by
 * `@noble/curves` (Ed25519 for algorithm 15). A rejected signature in this lab
 * is a genuine cryptographic rejection, which is the only reason the
 * break-it-yourself acts teach anything.
 *
 * WHY A LIBRARY FOR ED25519 AND NOT FOR THE OTHER TWO. WebCrypto's Ed25519
 * support arrived late and is still not everywhere a learner might open this
 * page, and a demo that silently skipped algorithm 15 on an older browser
 * would be teaching a chain it had quietly replaced. `@noble/curves` is the
 * audited, dependency-free implementation this fleet already uses, and it is
 * SYNCHRONOUS — which also matters for `@noble/hashes`, because the NSEC3
 * dictionary act hashes tens of thousands of candidate names and one
 * `crypto.subtle.digest` promise per hash would turn a demonstration into a
 * progress bar.
 *
 * What is hand-rolled is everything DNSSEC-specific: RFC 3110's RSA public-key
 * layout, DNSSEC's fixed-width r|s signature encoding, and the DS/NSEC3 digest
 * inputs. Those are the parts a learner is here to inspect.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha384 } from '@noble/hashes/sha2.js';

import { toBase64, readU16 } from '../dns/codec.ts';
import { ALGORITHM, DIGEST_TYPE } from '../dns/types.ts';

/** Base64url without padding, the encoding JWK fields use. */
function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── Digests ─────────────────────────────────────────────────────────────────

/**
 * Synchronous digests, keyed by the DS Digest Type registry.
 *
 * SHA-1 is here because the protocol requires it, not because it is a good
 * hash: DS digest type 1 is still deployed, and NSEC3 (RFC 5155) defines
 * exactly one hash algorithm and it is SHA-1. A lab that quietly substituted
 * SHA-256 for NSEC3 would produce owner names no real zone contains.
 */
export function digest(digestType: number, data: Uint8Array): Uint8Array {
  switch (digestType) {
    case DIGEST_TYPE.SHA1:
      return sha1(data);
    case DIGEST_TYPE.SHA256:
      return sha256(data);
    case DIGEST_TYPE.SHA384:
      return sha384(data);
    default:
      throw new Error(`unsupported DS digest type ${digestType}`);
  }
}

/** The one hash algorithm RFC 5155 defines for NSEC3: 1 = SHA-1. */
export function nsec3Digest(hashAlgorithm: number, data: Uint8Array): Uint8Array {
  if (hashAlgorithm !== 1) throw new Error(`unsupported NSEC3 hash algorithm ${hashAlgorithm}`);
  return sha1(data);
}

// ── RFC 3110 RSA public keys ────────────────────────────────────────────────

/**
 * Split an algorithm-8 DNSKEY public key into exponent and modulus.
 *
 * RFC 3110 section 2: a leading zero octet means the next two octets are a
 * big-endian exponent length; otherwise the first octet IS the exponent
 * length. The one-octet form covers the universal 65537 exponent, so the
 * three-octet branch is rare in the wild and correspondingly easy to get wrong
 * — which is why it is written out rather than assumed away.
 */
export function parseRsaPublicKey(publicKey: Uint8Array): {
  exponent: Uint8Array;
  modulus: Uint8Array;
} {
  if (publicKey.length < 3) throw new Error('RSA DNSKEY public key is too short');
  const first = publicKey[0]!;
  const exponentLength = first === 0 ? readU16(publicKey, 1) : first;
  const exponentStart = first === 0 ? 3 : 1;
  if (exponentLength === 0) throw new Error('RSA DNSKEY declares a zero-length exponent');
  const modulusStart = exponentStart + exponentLength;
  if (modulusStart >= publicKey.length) {
    throw new Error('RSA DNSKEY exponent runs past the end of the key');
  }
  return {
    exponent: publicKey.subarray(exponentStart, modulusStart),
    modulus: publicKey.subarray(modulusStart),
  };
}

// ── Verification ────────────────────────────────────────────────────────────

/**
 * Verify a DNSSEC signature over `signedData` with a DNSKEY public key.
 *
 * `signedData` is the byte string `canonical.ts` assembles — RRSIG_RDATA
 * followed by every canonicalized RR. The hashing is inside each algorithm's
 * definition (WebCrypto hashes as part of `verify`; Ed25519 is PureEdDSA and
 * hashes the message itself), so nothing here pre-hashes.
 *
 * Throws `UnsupportedAlgorithmError` rather than returning false for an
 * algorithm this lab does not implement. "I cannot check this" and "this is
 * forged" are different answers and a validator that conflates them turns an
 * unsupported-algorithm zone into a security alarm.
 */
export class UnsupportedAlgorithmError extends Error {
  constructor(readonly algorithm: number) {
    super(`algorithm ${algorithm} is not implemented in this lab`);
    this.name = 'UnsupportedAlgorithmError';
  }
}

export async function verifySignature(
  algorithm: number,
  publicKey: Uint8Array,
  signature: Uint8Array,
  signedData: Uint8Array
): Promise<boolean> {
  switch (algorithm) {
    case ALGORITHM.RSASHA256: {
      const { exponent, modulus } = parseRsaPublicKey(publicKey);
      const key = await crypto.subtle.importKey(
        'jwk',
        {
          kty: 'RSA',
          n: toBase64Url(modulus),
          e: toBase64Url(exponent),
          alg: 'RS256',
          ext: true,
        },
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
      );
      return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, bufferOf(signature), bufferOf(signedData));
    }
    case ALGORITHM.ECDSAP256SHA256: {
      // RFC 6605 section 4: the DNSKEY carries the uncompressed point WITHOUT
      // the 0x04 prefix, and the RRSIG carries r|s at fixed width rather than
      // DER. WebCrypto's 'raw' import wants the prefix back, and its verify
      // wants exactly the fixed-width r|s DNSSEC already uses.
      if (publicKey.length !== 64) {
        throw new Error(`algorithm 13 public key must be 64 octets, got ${publicKey.length}`);
      }
      if (signature.length !== 64) {
        throw new Error(`algorithm 13 signature must be 64 octets, got ${signature.length}`);
      }
      const point = new Uint8Array(65);
      point[0] = 0x04;
      point.set(publicKey, 1);
      const key = await crypto.subtle.importKey(
        'raw',
        bufferOf(point),
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
      );
      return crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        bufferOf(signature),
        bufferOf(signedData)
      );
    }
    case ALGORITHM.ED25519: {
      // RFC 8080: a raw 32-octet public key and a raw 64-octet PureEdDSA
      // signature, with no pre-hash.
      if (publicKey.length !== 32) {
        throw new Error(`algorithm 15 public key must be 32 octets, got ${publicKey.length}`);
      }
      if (signature.length !== 64) {
        throw new Error(`algorithm 15 signature must be 64 octets, got ${signature.length}`);
      }
      try {
        return ed25519.verify(signature, signedData, publicKey);
      } catch {
        // A malformed point is a rejection, not a crash.
        return false;
      }
    }
    default:
      throw new UnsupportedAlgorithmError(algorithm);
  }
}

/**
 * `Uint8Array` to a plain `ArrayBuffer` view WebCrypto will accept.
 *
 * A `subarray()` shares its parent's buffer, so passing one straight to
 * WebCrypto hands it the WHOLE buffer — every RDATA slice in this codebase is
 * a subarray of the record it came from, so skipping this copy silently
 * verifies against the wrong bytes.
 */
function bufferOf(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

// ── Signing (the in-page zone signs for real) ───────────────────────────────

/** A key pair the demo zone uses. Private material is per-session, in memory. */
export interface SigningKey {
  readonly algorithm: number;
  /** DNSKEY public-key field, exactly as it appears in the RDATA. */
  readonly publicKey: Uint8Array;
  readonly privateKey: CryptoKey | Uint8Array;
}

/**
 * Import a pinned P-256 key so the demo zone is byte-for-byte reproducible
 * across reloads and across CI. The JWK holds a teaching key generated for
 * this repo; it protects nothing and is committed on purpose.
 */
export async function importPinnedEcdsaKey(jwk: JsonWebKey): Promise<SigningKey> {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  if (jwk.x === undefined || jwk.y === undefined) {
    throw new Error('pinned P-256 JWK is missing its public coordinates');
  }
  const publicJwk: JsonWebKey = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true };
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  return { algorithm: ALGORITHM.ECDSAP256SHA256, publicKey: raw.subarray(1), privateKey };
}

export function importPinnedEd25519Key(secret: Uint8Array): SigningKey {
  return {
    algorithm: ALGORITHM.ED25519,
    publicKey: ed25519.getPublicKey(secret),
    privateKey: secret,
  };
}

export async function sign(key: SigningKey, signedData: Uint8Array): Promise<Uint8Array> {
  if (key.algorithm === ALGORITHM.ECDSAP256SHA256) {
    const raw = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      key.privateKey as CryptoKey,
      bufferOf(signedData)
    );
    return new Uint8Array(raw); // WebCrypto emits r|s, which is DNSSEC's encoding
  }
  if (key.algorithm === ALGORITHM.ED25519) {
    return ed25519.sign(signedData, key.privateKey as Uint8Array);
  }
  throw new UnsupportedAlgorithmError(key.algorithm);
}
