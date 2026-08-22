/**
 * The three encodings DNSSEC presentation format uses, hand-rolled.
 *
 * Base 32 with the extended hex alphabet is the one worth reading closely: it
 * is not the familiar RFC 4648 section 6 alphabet, and using the wrong one
 * produces a plausible-looking string that names a different owner. NSEC3
 * owner names are the extended-hex ("base32hex") flavour precisely because it
 * preserves sort order — the encoded label sorts the same way the raw hash
 * does, which is what lets a chain of NSEC3 records cover the hash space in
 * order at all.
 */

/** Uppercase hex, no separators. */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out.toUpperCase();
}

/** Parse hex, tolerating the whitespace `dig` wraps long digests with. */
export function fromHex(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error(`hex string has an odd length: ${clean.length}`);
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('hex string contains a non-hex character');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function toBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += B64[b0 >> 2]!;
    out += B64[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)]!;
    out += b1 === undefined ? '=' : B64[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)]!;
    out += b2 === undefined ? '=' : B64[b2 & 0x3f]!;
  }
  return out;
}

/**
 * Parse base64, joining the whitespace-separated groups that RFC text and
 * `dig` output both wrap long keys and signatures into. Every DNSKEY and
 * RRSIG vector in this repo arrives that way, so tolerating the whitespace is
 * required rather than lenient — but a character outside the alphabet is still
 * a hard failure, because silently dropping one shifts every byte after it.
 */
export function fromBase64(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
    throw new Error('base64 string contains a character outside the alphabet');
  }
  const body = clean.replace(/=+$/, '');
  const out = new Uint8Array(Math.floor((body.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const ch of body) {
    const value = B64.indexOf(ch);
    if (value < 0) throw new Error('base64 string contains a character outside the alphabet');
    acc = (acc << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
}

/**
 * RFC 4648 section 7 — "Base 32 Encoding with Extended Hex Alphabet".
 *
 * The alphabet is 0-9 then A-V, which is what makes it order-preserving:
 * comparing two encoded strings as text gives the same answer as comparing the
 * raw values they encode. RFC 5155 relies on that property, and it is the
 * reason NSEC3 owner labels are readable as a sorted ring at all.
 *
 * NSEC3 uses the unpadded form and lowercases the resulting label.
 */
const B32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

export function toBase32Hex(bytes: Uint8Array): string {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32HEX[(acc >> bits) & 0x1f]!;
    }
  }
  if (bits > 0) out += B32HEX[(acc << (5 - bits)) & 0x1f]!;
  return out;
}

export function fromBase32Hex(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of clean) {
    const value = B32HEX.indexOf(ch);
    if (value < 0) throw new Error(`base32hex string contains ${JSON.stringify(ch)}`);
    acc = (acc << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/**
 * Unsigned lexicographic comparison of two byte strings, shorter-first on a
 * shared prefix. This is the ordering RFC 4034 section 6.3 puts RDATA into
 * before signing, and RFC 5155's hash ring uses the same rule.
 */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i += 1) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

/** Concatenate byte runs into one buffer. */
export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Big-endian writers, used all over the wire encoders. */
export function u8(value: number): Uint8Array {
  return Uint8Array.of(value & 0xff);
}

export function u16(value: number): Uint8Array {
  return Uint8Array.of((value >> 8) & 0xff, value & 0xff);
}

export function u32(value: number): Uint8Array {
  return Uint8Array.of(
    Math.floor(value / 0x1000000) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  );
}

export function readU16(bytes: Uint8Array, offset: number): number {
  const hi = bytes[offset];
  const lo = bytes[offset + 1];
  if (hi === undefined || lo === undefined) throw new Error('truncated 16-bit field');
  return (hi << 8) | lo;
}

export function readU32(bytes: Uint8Array, offset: number): number {
  if (offset + 4 > bytes.length) throw new Error('truncated 32-bit field');
  return (
    bytes[offset]! * 0x1000000 + ((bytes[offset + 1]! << 16) | (bytes[offset + 2]! << 8) | bytes[offset + 3]!)
  );
}
