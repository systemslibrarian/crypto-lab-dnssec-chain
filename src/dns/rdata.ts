/**
 * RDATA: presentation text to wire octets and back, for the record types this
 * lab reads.
 *
 * The parsers are strict on purpose. A DNSSEC validator's whole job is to
 * decide whether a specific run of bytes was signed, so a parser that guesses
 * — accepting a short digest, a truncated key, a salt it could not decode —
 * hands the validator bytes nobody signed and lets it report a signature
 * failure whose real cause was a typo. Every failure here names what it saw.
 *
 * Down-casing of embedded names for canonical form (RFC 4034 section 6.2, as
 * CORRECTED by RFC 6840 section 5.1) is handled in `canonical.ts`, not here:
 * this module preserves the case a record was written with so it can be
 * printed back faithfully.
 */

import {
  concatBytes,
  fromBase32Hex,
  fromBase64,
  fromHex,
  readU16,
  readU32,
  toBase32Hex,
  toBase64,
  toHex,
  u16,
  u32,
  u8,
} from './codec.ts';
import { canonicalWire, parseName, presentName, type Labels } from './name.ts';
import { RR_TYPE, typeName, typeNumber } from './types.ts';

export class RdataError extends Error {
  constructor(
    message: string,
    readonly detail: string
  ) {
    super(message);
    this.name = 'RdataError';
  }
}

// ── Type bit maps (RFC 4034 section 4.1.2) ──────────────────────────────────

/**
 * A type bit map is a sequence of window blocks: a window number octet, a
 * length octet, then that many bitmap octets, most significant bit first. Type
 * `w * 256 + i` is present when bit `i` of window `w` is set.
 *
 * Windows exist because the type space is 16 bits and a zone typically uses a
 * handful of low numbers plus, occasionally, something far away — Cloudflare's
 * synthesized NSEC in the pinned capture lists `TYPE128`, which lands in
 * window 0 alongside RRSIG and NSEC, while a zone using a type above 255 would
 * emit a second window rather than 32 wasted octets.
 */
export function encodeTypeBitmap(types: readonly number[]): Uint8Array {
  const windows = new Map<number, Uint8Array>();
  for (const type of [...new Set(types)].sort((a, b) => a - b)) {
    const windowNumber = type >> 8;
    const bit = type & 0xff;
    let bitmap = windows.get(windowNumber);
    if (!bitmap) {
      bitmap = new Uint8Array(32);
      windows.set(windowNumber, bitmap);
    }
    bitmap[bit >> 3]! |= 0x80 >> (bit & 7);
  }
  const parts: Uint8Array[] = [];
  for (const [windowNumber, bitmap] of [...windows].sort((a, b) => a[0] - b[0])) {
    let length = 32;
    while (length > 0 && bitmap[length - 1] === 0) length -= 1;
    parts.push(u8(windowNumber), u8(length), bitmap.subarray(0, length));
  }
  return concatBytes(...parts);
}

export function decodeTypeBitmap(bytes: Uint8Array): number[] {
  const types: number[] = [];
  let i = 0;
  while (i < bytes.length) {
    const windowNumber = bytes[i];
    const length = bytes[i + 1];
    if (windowNumber === undefined || length === undefined) {
      throw new RdataError('truncated type bit map window header', toHex(bytes));
    }
    if (length < 1 || length > 32) {
      throw new RdataError(`type bit map window length ${length} is outside 1..32`, toHex(bytes));
    }
    if (i + 2 + length > bytes.length) {
      throw new RdataError('type bit map window runs past the end of the RDATA', toHex(bytes));
    }
    for (let b = 0; b < length; b += 1) {
      const octet = bytes[i + 2 + b]!;
      for (let bit = 0; bit < 8; bit += 1) {
        if (octet & (0x80 >> bit)) types.push(windowNumber * 256 + b * 8 + bit);
      }
    }
    i += 2 + length;
  }
  return types;
}

// ── RRSIG time fields ───────────────────────────────────────────────────────

/**
 * RRSIG inception and expiration are seconds since the Unix epoch on the wire,
 * and RFC 4034 section 3.2 allows either a bare decimal or `YYYYMMDDHHmmSS` in
 * presentation format. `dig` prints the second, which is what the pinned
 * capture and every RFC example in `src/vectors/` use.
 */
export function parseRrsigTime(text: string): number {
  if (/^\d{14}$/.test(text)) {
    const year = Number(text.slice(0, 4));
    const month = Number(text.slice(4, 6));
    const day = Number(text.slice(6, 8));
    const hour = Number(text.slice(8, 10));
    const minute = Number(text.slice(10, 12));
    const second = Number(text.slice(12, 14));
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) {
      throw new RdataError(`RRSIG time ${text} is not a valid UTC timestamp`, text);
    }
    return Math.floor(Date.UTC(year, month - 1, day, hour, minute, second) / 1000);
  }
  if (/^\d{1,10}$/.test(text)) return Number(text);
  throw new RdataError(`RRSIG time ${JSON.stringify(text)} is neither YYYYMMDDHHmmSS nor a decimal`, text);
}

export function formatRrsigTime(epochSeconds: number): string {
  const d = new Date(epochSeconds * 1000);
  const p = (n: number, w = 2): string => String(n).padStart(w, '0');
  return (
    `${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
    `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`
  );
}

// ── Structured views over specific RDATA ────────────────────────────────────

export interface DnskeyRdata {
  readonly flags: number;
  readonly protocol: number;
  readonly algorithm: number;
  readonly publicKey: Uint8Array;
}

export interface DsRdata {
  readonly keyTag: number;
  readonly algorithm: number;
  readonly digestType: number;
  readonly digest: Uint8Array;
}

export interface RrsigRdata {
  readonly typeCovered: number;
  readonly algorithm: number;
  readonly labels: number;
  readonly originalTtl: number;
  readonly expiration: number;
  readonly inception: number;
  readonly keyTag: number;
  readonly signerName: Labels;
  readonly signature: Uint8Array;
}

export interface NsecRdata {
  readonly nextName: Labels;
  readonly types: readonly number[];
}

export interface Nsec3Rdata {
  readonly hashAlgorithm: number;
  readonly flags: number;
  readonly iterations: number;
  readonly salt: Uint8Array;
  readonly nextHashedOwner: Uint8Array;
  readonly types: readonly number[];
}

export function encodeDnskey(r: DnskeyRdata): Uint8Array {
  return concatBytes(u16(r.flags), u8(r.protocol), u8(r.algorithm), r.publicKey);
}

export function decodeDnskey(rdata: Uint8Array): DnskeyRdata {
  if (rdata.length < 5) throw new RdataError('DNSKEY RDATA shorter than its fixed header', toHex(rdata));
  return {
    flags: readU16(rdata, 0),
    protocol: rdata[2]!,
    algorithm: rdata[3]!,
    publicKey: rdata.subarray(4),
  };
}

export function encodeDs(r: DsRdata): Uint8Array {
  return concatBytes(u16(r.keyTag), u8(r.algorithm), u8(r.digestType), r.digest);
}

export function decodeDs(rdata: Uint8Array): DsRdata {
  if (rdata.length < 5) throw new RdataError('DS RDATA shorter than its fixed header', toHex(rdata));
  return {
    keyTag: readU16(rdata, 0),
    algorithm: rdata[2]!,
    digestType: rdata[3]!,
    digest: rdata.subarray(4),
  };
}

export function encodeRrsig(r: RrsigRdata): Uint8Array {
  return concatBytes(encodeRrsigPrefix(r), r.signature);
}

/**
 * The RRSIG RDATA *without* the signature field — the `RRSIG_RDATA` of RFC
 * 4034 section 3.1.8.1, which is the first thing fed to the signer.
 *
 * The signer's name is written in canonical wire form: uncompressed and
 * down-cased. RFC 6840 section 5.1 settles the question RFC 4034 and RFC 3755
 * disagreed on — names in RRSIG RDATA *are* converted to lowercase.
 */
export function encodeRrsigPrefix(r: RrsigRdata): Uint8Array {
  return concatBytes(
    u16(r.typeCovered),
    u8(r.algorithm),
    u8(r.labels),
    u32(r.originalTtl),
    u32(r.expiration),
    u32(r.inception),
    u16(r.keyTag),
    canonicalWire(r.signerName)
  );
}

/** Read an uncompressed name out of RDATA, returning it and the next offset. */
function readName(rdata: Uint8Array, start: number): { labels: Labels; next: number } {
  const labels: Uint8Array[] = [];
  let i = start;
  for (;;) {
    const length = rdata[i];
    if (length === undefined) throw new RdataError('name runs past the end of the RDATA', toHex(rdata));
    if (length === 0) return { labels, next: i + 1 };
    if (length >= 0xc0) {
      // A compression pointer in RDATA cannot be resolved without the whole
      // message, and DNSSEC forbids compression in signed RDATA anyway.
      throw new RdataError('compressed name in RDATA (forbidden in DNSSEC canonical form)', toHex(rdata));
    }
    if (length > 63) throw new RdataError(`label length ${length} exceeds 63`, toHex(rdata));
    if (i + 1 + length > rdata.length) throw new RdataError('label runs past the end of the RDATA', toHex(rdata));
    labels.push(rdata.subarray(i + 1, i + 1 + length));
    i += 1 + length;
  }
}

export function decodeRrsig(rdata: Uint8Array): RrsigRdata {
  if (rdata.length < 18) throw new RdataError('RRSIG RDATA shorter than its fixed header', toHex(rdata));
  const { labels, next } = readName(rdata, 18);
  return {
    typeCovered: readU16(rdata, 0),
    algorithm: rdata[2]!,
    labels: rdata[3]!,
    originalTtl: readU32(rdata, 4),
    expiration: readU32(rdata, 8),
    inception: readU32(rdata, 12),
    keyTag: readU16(rdata, 16),
    signerName: labels,
    signature: rdata.subarray(next),
  };
}

export function encodeNsec(r: NsecRdata): Uint8Array {
  // The Next Domain Name is written uncompressed but NOT down-cased -- see
  // RFC 6840 section 5.1, which corrects RFC 4034 section 6.2 on exactly this
  // field. `wireNoCase` preserves the octets as written.
  return concatBytes(wireNoCase(r.nextName), encodeTypeBitmap([...r.types]));
}

export function decodeNsec(rdata: Uint8Array): NsecRdata {
  const { labels, next } = readName(rdata, 0);
  return { nextName: labels, types: decodeTypeBitmap(rdata.subarray(next)) };
}

/** Uncompressed wire form with the original case preserved. */
export function wireNoCase(labels: Labels): Uint8Array {
  const size = labels.reduce((n, l) => n + 1 + l.length, 1);
  const out = new Uint8Array(size);
  let o = 0;
  for (const label of labels) {
    out[o++] = label.length;
    out.set(label, o);
    o += label.length;
  }
  out[o] = 0;
  return out;
}

export function encodeNsec3(r: Nsec3Rdata): Uint8Array {
  return concatBytes(
    u8(r.hashAlgorithm),
    u8(r.flags),
    u16(r.iterations),
    u8(r.salt.length),
    r.salt,
    u8(r.nextHashedOwner.length),
    r.nextHashedOwner,
    encodeTypeBitmap([...r.types])
  );
}

export function decodeNsec3(rdata: Uint8Array): Nsec3Rdata {
  if (rdata.length < 5) throw new RdataError('NSEC3 RDATA shorter than its fixed header', toHex(rdata));
  const saltLength = rdata[4]!;
  const hashOffset = 5 + saltLength;
  if (hashOffset >= rdata.length) throw new RdataError('NSEC3 salt runs past the end of the RDATA', toHex(rdata));
  const hashLength = rdata[hashOffset]!;
  const typesOffset = hashOffset + 1 + hashLength;
  if (typesOffset > rdata.length) {
    throw new RdataError('NSEC3 next hashed owner runs past the end of the RDATA', toHex(rdata));
  }
  return {
    hashAlgorithm: rdata[0]!,
    flags: rdata[1]!,
    iterations: readU16(rdata, 2),
    salt: rdata.subarray(5, 5 + saltLength),
    nextHashedOwner: rdata.subarray(hashOffset + 1, typesOffset),
    types: decodeTypeBitmap(rdata.subarray(typesOffset)),
  };
}

// ── Presentation format ─────────────────────────────────────────────────────

/** Split an RDATA presentation string into tokens, honouring quoted strings. */
function tokenize(text: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === ' ' || ch === '\t') {
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let value = '';
      while (j < text.length && text[j] !== '"') {
        if (text[j] === '\\' && j + 1 < text.length) {
          value += text[j + 1];
          j += 2;
          continue;
        }
        value += text[j];
        j += 1;
      }
      if (j >= text.length) throw new RdataError('unterminated quoted string in RDATA', text);
      tokens.push(value);
      i = j + 1;
      continue;
    }
    let j = i;
    while (j < text.length && text[j] !== ' ' && text[j] !== '\t') j += 1;
    tokens.push(text.slice(i, j));
    i = j;
  }
  return tokens;
}

function requireInt(token: string | undefined, field: string, max: number): number {
  if (token === undefined) throw new RdataError(`missing ${field}`, String(token));
  if (!/^\d+$/.test(token)) throw new RdataError(`${field} ${JSON.stringify(token)} is not a number`, token);
  const value = Number(token);
  if (value > max) throw new RdataError(`${field} ${value} exceeds ${max}`, token);
  return value;
}

function parseIpv4(token: string): Uint8Array {
  const parts = token.split('.');
  if (parts.length !== 4) throw new RdataError(`${JSON.stringify(token)} is not an IPv4 address`, token);
  return Uint8Array.from(parts, (p) => {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) {
      throw new RdataError(`${JSON.stringify(token)} is not an IPv4 address`, token);
    }
    return Number(p);
  });
}

function parseIpv6(token: string): Uint8Array {
  const halves = token.split('::');
  if (halves.length > 2) throw new RdataError(`${JSON.stringify(token)} is not an IPv6 address`, token);
  const toGroups = (text: string): number[] =>
    text === '' ? [] : text.split(':').map((g) => {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
        throw new RdataError(`${JSON.stringify(token)} is not an IPv6 address`, token);
      }
      return parseInt(g, 16);
    });
  const head = toGroups(halves[0]!);
  const tail = halves.length === 2 ? toGroups(halves[1]!) : [];
  const groups =
    halves.length === 2
      ? [...head, ...new Array<number>(8 - head.length - tail.length).fill(0), ...tail]
      : head;
  if (groups.length !== 8) throw new RdataError(`${JSON.stringify(token)} is not an IPv6 address`, token);
  const out = new Uint8Array(16);
  groups.forEach((g, i) => {
    out[i * 2] = g >> 8;
    out[i * 2 + 1] = g & 0xff;
  });
  return out;
}

function encodeCharacterStrings(tokens: readonly string[]): Uint8Array {
  return concatBytes(
    ...tokens.map((t) => {
      const bytes = new TextEncoder().encode(t);
      if (bytes.length > 255) throw new RdataError('TXT character-string exceeds 255 octets', t);
      return concatBytes(u8(bytes.length), bytes);
    })
  );
}

/** Presentation RDATA to wire octets, for the types this lab handles. */
export function parseRdata(type: number, text: string): Uint8Array {
  // RFC 3597 generic form: `\# <length> <hex>`. Real zones use it for types a
  // server does not know, and it is the only honest way to carry one through.
  const generic = /^\\#\s+(\d+)\s*([0-9a-fA-F\s]*)$/.exec(text.trim());
  if (generic) {
    const bytes = fromHex(generic[2] ?? '');
    const declared = Number(generic[1]);
    if (bytes.length !== declared) {
      throw new RdataError(`\\# declares ${declared} octets but supplies ${bytes.length}`, text);
    }
    return bytes;
  }

  const t = tokenize(text);
  switch (type) {
    case RR_TYPE.A:
      return parseIpv4(t[0] ?? '');
    case RR_TYPE.AAAA:
      return parseIpv6(t[0] ?? '');
    case RR_TYPE.NS:
    case RR_TYPE.CNAME:
      return wireNoCase(parseName(t[0] ?? ''));
    case RR_TYPE.MX:
      return concatBytes(u16(requireInt(t[0], 'MX preference', 65535)), wireNoCase(parseName(t[1] ?? '')));
    case RR_TYPE.TXT:
      return encodeCharacterStrings(t);
    case RR_TYPE.SOA:
      return concatBytes(
        wireNoCase(parseName(t[0] ?? '')),
        wireNoCase(parseName(t[1] ?? '')),
        u32(requireInt(t[2], 'SOA serial', 0xffffffff)),
        u32(requireInt(t[3], 'SOA refresh', 0xffffffff)),
        u32(requireInt(t[4], 'SOA retry', 0xffffffff)),
        u32(requireInt(t[5], 'SOA expire', 0xffffffff)),
        u32(requireInt(t[6], 'SOA minimum', 0xffffffff))
      );
    case RR_TYPE.DNSKEY:
      return encodeDnskey({
        flags: requireInt(t[0], 'DNSKEY flags', 65535),
        protocol: requireInt(t[1], 'DNSKEY protocol', 255),
        algorithm: requireInt(t[2], 'DNSKEY algorithm', 255),
        publicKey: fromBase64(t.slice(3).join('')),
      });
    case RR_TYPE.DS:
      return encodeDs({
        keyTag: requireInt(t[0], 'DS key tag', 65535),
        algorithm: requireInt(t[1], 'DS algorithm', 255),
        digestType: requireInt(t[2], 'DS digest type', 255),
        digest: fromHex(t.slice(3).join('')),
      });
    case RR_TYPE.RRSIG:
      return encodeRrsig({
        typeCovered: typeNumber(t[0] ?? ''),
        algorithm: requireInt(t[1], 'RRSIG algorithm', 255),
        labels: requireInt(t[2], 'RRSIG labels', 255),
        originalTtl: requireInt(t[3], 'RRSIG original TTL', 0xffffffff),
        expiration: parseRrsigTime(t[4] ?? ''),
        inception: parseRrsigTime(t[5] ?? ''),
        keyTag: requireInt(t[6], 'RRSIG key tag', 65535),
        signerName: parseName(t[7] ?? ''),
        signature: fromBase64(t.slice(8).join('')),
      });
    case RR_TYPE.NSEC:
      return encodeNsec({
        nextName: parseName(t[0] ?? ''),
        types: t.slice(1).map(typeNumber),
      });
    case RR_TYPE.NSEC3:
      return encodeNsec3({
        hashAlgorithm: requireInt(t[0], 'NSEC3 hash algorithm', 255),
        flags: requireInt(t[1], 'NSEC3 flags', 255),
        iterations: requireInt(t[2], 'NSEC3 iterations', 65535),
        salt: t[3] === '-' ? new Uint8Array(0) : fromHex(t[3] ?? ''),
        nextHashedOwner: fromBase32Hex(t[4] ?? ''),
        types: t.slice(5).map(typeNumber),
      });
    case RR_TYPE.NSEC3PARAM:
      return concatBytes(
        u8(requireInt(t[0], 'NSEC3PARAM hash algorithm', 255)),
        u8(requireInt(t[1], 'NSEC3PARAM flags', 255)),
        u16(requireInt(t[2], 'NSEC3PARAM iterations', 65535)),
        (() => {
          const salt = t[3] === '-' ? new Uint8Array(0) : fromHex(t[3] ?? '');
          return concatBytes(u8(salt.length), salt);
        })()
      );
    default:
      throw new RdataError(
        `${typeName(type)} RDATA has no parser here — write it as RFC 3597 generic form (\\# len hex)`,
        text
      );
  }
}

/** Wire octets back to the presentation spelling, for display and round-trip tests. */
export function presentRdata(type: number, rdata: Uint8Array): string {
  switch (type) {
    case RR_TYPE.A:
      return Array.from(rdata).join('.');
    case RR_TYPE.AAAA: {
      const groups: string[] = [];
      for (let i = 0; i < 16; i += 2) groups.push(((rdata[i]! << 8) | rdata[i + 1]!).toString(16));
      return groups.join(':');
    }
    case RR_TYPE.NS:
    case RR_TYPE.CNAME:
      return presentName(readName(rdata, 0).labels);
    case RR_TYPE.MX: {
      const { labels } = readName(rdata, 2);
      return `${readU16(rdata, 0)} ${presentName(labels)}`;
    }
    case RR_TYPE.TXT: {
      const out: string[] = [];
      let i = 0;
      while (i < rdata.length) {
        const length = rdata[i]!;
        out.push(`"${new TextDecoder().decode(rdata.subarray(i + 1, i + 1 + length))}"`);
        i += 1 + length;
      }
      return out.join(' ');
    }
    case RR_TYPE.SOA: {
      const mname = readName(rdata, 0);
      const rname = readName(rdata, mname.next);
      const nums: number[] = [];
      for (let k = 0; k < 5; k += 1) nums.push(readU32(rdata, rname.next + k * 4));
      return `${presentName(mname.labels)} ${presentName(rname.labels)} ${nums.join(' ')}`;
    }
    case RR_TYPE.DNSKEY: {
      const k = decodeDnskey(rdata);
      return `${k.flags} ${k.protocol} ${k.algorithm} ${toBase64(k.publicKey)}`;
    }
    case RR_TYPE.DS: {
      const d = decodeDs(rdata);
      return `${d.keyTag} ${d.algorithm} ${d.digestType} ${toHex(d.digest)}`;
    }
    case RR_TYPE.RRSIG: {
      const s = decodeRrsig(rdata);
      return (
        `${typeName(s.typeCovered)} ${s.algorithm} ${s.labels} ${s.originalTtl} ` +
        `${formatRrsigTime(s.expiration)} ${formatRrsigTime(s.inception)} ${s.keyTag} ` +
        `${presentName(s.signerName)} ${toBase64(s.signature)}`
      );
    }
    case RR_TYPE.NSEC: {
      const n = decodeNsec(rdata);
      return [presentName(n.nextName), ...n.types.map(typeName)].join(' ');
    }
    case RR_TYPE.NSEC3: {
      const n = decodeNsec3(rdata);
      return [
        n.hashAlgorithm,
        n.flags,
        n.iterations,
        n.salt.length === 0 ? '-' : toHex(n.salt),
        toBase32Hex(n.nextHashedOwner),
        ...n.types.map(typeName),
      ].join(' ');
    }
    case RR_TYPE.NSEC3PARAM: {
      const saltLength = rdata[4]!;
      const salt = rdata.subarray(5, 5 + saltLength);
      return `${rdata[0]} ${rdata[1]} ${readU16(rdata, 2)} ${salt.length === 0 ? '-' : toHex(salt)}`;
    }
    default:
      return `\\# ${rdata.length} ${toHex(rdata)}`;
  }
}
