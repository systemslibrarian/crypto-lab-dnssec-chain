/**
 * Domain names: presentation text in, canonical wire bytes out, and the
 * ordering DNSSEC signs against.
 *
 * Every byte a validator hashes or signs starts here, so this module is
 * deliberately strict and hand-rolled rather than borrowed. Three separate
 * things travel under the word "name" and conflating any two of them silently
 * breaks a signature:
 *
 *  - PRESENTATION text — what a zone file and `dig` print, with backslash
 *    escapes for octets that are not printable ASCII (`\000`, `\.`).
 *  - WIRE format — length-prefixed labels ending in a zero byte.
 *  - CANONICAL wire form (RFC 4034 section 6.1) — wire format, uncompressed,
 *    fully qualified, with US-ASCII A-Z mapped to a-z. This is the only form
 *    that ever reaches a hash or a signature.
 *
 * The captured real-world chain in `src/vectors/pinned-chain.txt` contains a
 * live example of why the escaping matters: Cloudflare's synthesized denial
 * names the next owner as `\000.no-such-name-9x7q.cloudflare.com.`, whose
 * first label is a single NUL octet. Read that as five literal characters and
 * the NSEC proof stops covering the name it exists to deny.
 */

/** RFC 1035 section 2.3.4 limits. Strict parsing is a stated invariant. */
export const MAX_LABEL_OCTETS = 63;
export const MAX_NAME_OCTETS = 255;

/** A parse failure carries the offending text so the UI can name the cause. */
export class NameError extends Error {
  constructor(
    message: string,
    readonly input: string
  ) {
    super(message);
    this.name = 'NameError';
  }
}

/**
 * A domain name as a list of labels, each already decoded to raw octets.
 * The root is the empty list. Labels are stored exactly as written; the
 * down-casing that canonical form requires happens in `canonicalWire`, so a
 * name can still be printed back the way its zone file spelled it.
 */
export type Labels = readonly Uint8Array[];

const isDigit = (c: number): boolean => c >= 0x30 && c <= 0x39;

/**
 * Decode one presentation label, resolving `\DDD` decimal escapes and `\X`
 * literal escapes. Returns the octets plus the index just past the label's
 * terminating dot (or the end of the string).
 *
 * A backslash followed by three digits is ONE octet, which is why the escape
 * has to be resolved before the length check: `\000` is 1 octet, not 4, and a
 * label of 63 escaped octets is 252 characters of presentation text.
 */
function decodeLabel(text: string, start: number): { octets: Uint8Array; next: number } {
  const out: number[] = [];
  let i = start;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '.') break;
    if (ch !== '\\') {
      const code = text.charCodeAt(i);
      // Presentation format is octet-oriented. A character outside Latin-1 has
      // no single-octet spelling, so accepting it would silently invent bytes.
      if (code > 0xff) throw new NameError(`non-octet character ${JSON.stringify(ch)} in name`, text);
      out.push(code);
      i += 1;
      continue;
    }
    // Escape sequence.
    if (i + 1 >= text.length) throw new NameError('name ends with a dangling backslash', text);
    if (isDigit(text.charCodeAt(i + 1))) {
      const digits = text.slice(i + 1, i + 4);
      if (digits.length !== 3 || ![...digits].every((d) => isDigit(d.charCodeAt(0)))) {
        throw new NameError(`\\${digits} is not a three-digit decimal escape`, text);
      }
      const value = Number(digits);
      if (value > 255) throw new NameError(`decimal escape \\${digits} exceeds 255`, text);
      out.push(value);
      i += 4;
      continue;
    }
    const code = text.charCodeAt(i + 1);
    if (code > 0xff) throw new NameError('non-octet character after backslash', text);
    out.push(code);
    i += 2;
  }
  if (out.length > MAX_LABEL_OCTETS) {
    throw new NameError(`label of ${out.length} octets exceeds the 63-octet limit`, text);
  }
  return { octets: Uint8Array.from(out), next: i + 1 };
}

/**
 * Parse presentation text into labels.
 *
 * Only fully qualified names are accepted — a trailing dot is required, or the
 * bare `.` for the root. Origin-relative names are a zone-file convenience
 * this lab deliberately does not implement: every name it handles is one that
 * will be hashed or signed, and guessing an origin is exactly how a validator
 * ends up authenticating the wrong name.
 */
export function parseName(text: string): Labels {
  if (text.length === 0) throw new NameError('empty name', text);
  if (text === '.') return [];
  // The trailing dot only terminates the name if it is not itself escaped.
  // `ab\.` ends with the character `.`, but that dot is a literal octet inside
  // the label, so the name is relative and this parser will not guess at an
  // origin for it.
  let backslashes = 0;
  while (text[text.length - 2 - backslashes] === '\\') backslashes += 1;
  if (!text.endsWith('.') || backslashes % 2 === 1) {
    throw new NameError('name must be fully qualified (end with an unescaped dot)', text);
  }
  const labels: Uint8Array[] = [];
  let i = 0;
  while (i < text.length) {
    const { octets, next } = decodeLabel(text, i);
    if (octets.length === 0) {
      throw new NameError('empty label (a doubled or leading dot)', text);
    }
    labels.push(octets);
    i = next;
  }
  // 1 length octet per label + the octets + the root terminator.
  const wireLength = labels.reduce((n, l) => n + 1 + l.length, 1);
  if (wireLength > MAX_NAME_OCTETS) {
    throw new NameError(`name of ${wireLength} wire octets exceeds the 255-octet limit`, text);
  }
  return labels;
}

/** Print labels back to presentation text, escaping what must be escaped. */
export function presentName(labels: Labels): string {
  if (labels.length === 0) return '.';
  return (
    labels
      .map((label) =>
        Array.from(label)
          .map((b) => {
            if (b === 0x2e || b === 0x5c) return `\\${String.fromCharCode(b)}`; // . and \
            if (b > 0x20 && b < 0x7f) return String.fromCharCode(b);
            return `\\${String(b).padStart(3, '0')}`;
          })
          .join('')
      )
      .join('.') + '.'
  );
}

/**
 * Canonical wire form (RFC 4034 section 6.1): uncompressed, fully qualified,
 * every US-ASCII uppercase letter mapped to lowercase.
 *
 * Note what is NOT down-cased: octets outside A-Z. DNS name comparison is
 * ASCII-case-insensitive only, so a 0xC3 byte in a UTF-8 label is left alone.
 */
export function canonicalWire(labels: Labels): Uint8Array {
  const size = labels.reduce((n, l) => n + 1 + l.length, 1);
  const out = new Uint8Array(size);
  let o = 0;
  for (const label of labels) {
    out[o++] = label.length;
    for (const b of label) out[o++] = b >= 0x41 && b <= 0x5a ? b + 0x20 : b;
  }
  out[o] = 0;
  return out;
}

/** Case-insensitive equality, the way DNS itself compares names. */
export function nameEquals(a: Labels, b: Labels): boolean {
  const wa = canonicalWire(a);
  const wb = canonicalWire(b);
  if (wa.length !== wb.length) return false;
  return wa.every((byte, i) => byte === wb[i]);
}

/**
 * Canonical DNS name order (RFC 4034 section 6.1).
 *
 * Names sort by comparing their labels from the RIGHTMOST leftward, each label
 * treated as a left-justified unsigned-octet string with A-Z down-cased, and a
 * name that runs out of labels sorting first. That right-to-left rule is what
 * makes the NSEC chain a tour of the zone rather than an alphabetical listing
 * of strings: `x.w.example.` sorts after `w.example.` because the comparison
 * reaches `w` on both sides before either name runs out.
 *
 * Returns a negative number, zero, or a positive number, so it drops straight
 * into `Array.prototype.sort`.
 */
export function compareNames(a: Labels, b: Labels): number {
  const down = (label: Uint8Array): Uint8Array =>
    Uint8Array.from(label, (byte) => (byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte));
  for (let i = 1; i <= Math.max(a.length, b.length); i += 1) {
    const la = a[a.length - i];
    const lb = b[b.length - i];
    if (la === undefined && lb === undefined) return 0;
    if (la === undefined) return -1; // a ran out of labels: it sorts first
    if (lb === undefined) return 1;
    const da = down(la);
    const db = down(lb);
    const shared = Math.min(da.length, db.length);
    for (let j = 0; j < shared; j += 1) {
      if (da[j]! !== db[j]!) return da[j]! - db[j]!;
    }
    // Left-justified: the shorter label sorts first when one is a prefix.
    if (da.length !== db.length) return da.length - db.length;
  }
  return 0;
}

/**
 * The RRSIG Labels field (RFC 4034 section 3.1.3): the number of labels in the
 * owner name, NOT counting the null root label and NOT counting a leading
 * wildcard label.
 *
 * A validator compares this against the answer's actual label count to learn
 * whether the RRset it is holding was synthesized from a wildcard — which
 * changes which owner name goes into the signed data.
 */
export function rrsigLabelCount(labels: Labels): number {
  const first = labels[0];
  const isWildcard = first !== undefined && first.length === 1 && first[0] === 0x2a; // '*'
  return labels.length - (isWildcard ? 1 : 0);
}

/** Is `child` equal to, or below, `ancestor`? */
export function isAtOrBelow(child: Labels, ancestor: Labels): boolean {
  if (ancestor.length > child.length) return false;
  return nameEquals(child.slice(child.length - ancestor.length), ancestor);
}
