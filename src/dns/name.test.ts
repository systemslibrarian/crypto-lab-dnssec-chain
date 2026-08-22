import { describe, expect, it } from 'vitest';

import {
  canonicalWire,
  compareNames,
  isAtOrBelow,
  NameError,
  nameEquals,
  parseName,
  presentName,
  rrsigLabelCount,
} from './name.ts';
import { toHex } from './codec.ts';
import { parseRdata, presentRdata } from './rdata.ts';
import { RR_TYPE } from './types.ts';

describe('presentation parsing', () => {
  it('requires a fully qualified name', () => {
    expect(() => parseName('example.com')).toThrow(NameError);
    expect(parseName('example.com.')).toHaveLength(2);
    expect(parseName('.')).toHaveLength(0);
  });

  it('rejects empty and oversized labels', () => {
    expect(() => parseName('a..b.')).toThrow(/empty label/);
    expect(() => parseName(`${'a'.repeat(64)}.`)).toThrow(/63-octet/);
    expect(parseName(`${'a'.repeat(63)}.`)).toHaveLength(1);
  });

  it('rejects a name whose wire form exceeds 255 octets', () => {
    const label = `${'a'.repeat(63)}.`;
    expect(() => parseName(label.repeat(4))).toThrow(/255-octet/);
  });

  it('decodes \\DDD escapes as single octets', () => {
    // The live Cloudflare denial in the pinned capture names this very label.
    const labels = parseName('\\000.no-such-name-9x7q.cloudflare.com.');
    expect(labels[0]).toEqual(Uint8Array.of(0));
    expect(labels).toHaveLength(4);
  });

  it('round-trips escaped octets through the printer', () => {
    for (const text of [
      '\\000.example.',
      'a\\.b.example.',
      '\\255\\000\\032.example.',
      'x.y.w.example.',
    ]) {
      expect(presentName(parseName(text))).toBe(text);
    }
  });

  it('rejects malformed escapes rather than guessing', () => {
    expect(() => parseName('\\12.example.')).toThrow(/three-digit/);
    expect(() => parseName('\\999.example.')).toThrow(/exceeds 255/);
    // An escaped final dot is a literal octet, not the root separator, so the
    // name is relative -- and this parser refuses to invent an origin.
    expect(() => parseName('ab\\.')).toThrow(/fully qualified/);
    expect(() => parseName('a\\\\.')).not.toThrow();
  });
});

describe('canonical form', () => {
  it('down-cases only US-ASCII A-Z', () => {
    expect(toHex(canonicalWire(parseName('ExAmPlE.CoM.')))).toBe(
      toHex(canonicalWire(parseName('example.com.')))
    );
  });

  it('encodes length-prefixed labels ending in a root octet', () => {
    expect(toHex(canonicalWire(parseName('a.example.')))).toBe('01610765 78616D70 6C6500'.replace(/\s/g, ''));
  });

  it('treats case-differing names as equal', () => {
    expect(nameEquals(parseName('WWW.Example.NET.'), parseName('www.example.net.'))).toBe(true);
  });
});

describe('canonical DNS name order (RFC 4034 section 6.1)', () => {
  // The ordering example printed in RFC 4034 section 6.1, verbatim.
  const rfcOrder = [
    'example.',
    'a.example.',
    'yljkjljk.a.example.',
    'Z.a.example.',
    'zABC.a.EXAMPLE.',
    'z.example.',
    '\\001.z.example.',
    '*.z.example.',
    '\\200.z.example.',
  ];

  it('sorts the RFC 4034 section 6.1 example into the printed order', () => {
    const shuffled = [...rfcOrder].reverse().map(parseName);
    const sorted = shuffled.sort(compareNames).map(presentName);
    expect(sorted).toEqual(rfcOrder.map((n) => presentName(parseName(n))));
  });

  it('compares right to left, so a subdomain follows its parent', () => {
    expect(compareNames(parseName('w.example.'), parseName('x.w.example.'))).toBeLessThan(0);
    expect(compareNames(parseName('x.w.example.'), parseName('y.example.'))).toBeLessThan(0);
  });

  it('sorts a shorter label before a longer one that shares its prefix', () => {
    expect(compareNames(parseName('a.example.'), parseName('aa.example.'))).toBeLessThan(0);
  });
});

describe('RRSIG label counting', () => {
  it('excludes the root label', () => {
    expect(rrsigLabelCount(parseName('www.example.net.'))).toBe(3);
    expect(rrsigLabelCount(parseName('.'))).toBe(0);
  });

  it('excludes a leading wildcard label', () => {
    expect(rrsigLabelCount(parseName('*.example.com.'))).toBe(2);
  });
});

describe('character-strings are octets, not text', () => {
  it('resolves a three-digit decimal escape to ONE octet', () => {
    // RFC 1035 section 5.1. Reading `\\065` as three characters would make the
    // character-string two octets longer than it should be -- and since TXT
    // RDATA is signed verbatim, those are the octets that would get signed.
    expect(toHex(parseRdata(RR_TYPE.TXT, '"a\\065b"'))).toBe('03614162');
    expect(presentRdata(RR_TYPE.TXT, parseRdata(RR_TYPE.TXT, '"a\\065b"'))).toBe('"aAb"');
  });

  it('round-trips an octet that has no printable spelling', () => {
    const wire = parseRdata(RR_TYPE.TXT, '"\\000\\255"');
    expect(toHex(wire)).toBe('0200FF');
    expect(presentRdata(RR_TYPE.TXT, wire)).toBe('"\\000\\255"');
  });

  it('still handles the literal escapes', () => {
    expect(toHex(parseRdata(RR_TYPE.TXT, '"a\\"b"'))).toBe('03612262');
    expect(toHex(parseRdata(RR_TYPE.TXT, '"a\\\\b"'))).toBe('03615C62');
  });

  it('refuses a character that does not fit in one octet', () => {
    // Accepting it would mean silently choosing an encoding for the caller,
    // which is how a signature comes to cover bytes nobody wrote.
    expect(() => parseRdata(RR_TYPE.TXT, '"caf\u00e9 \u2014 dash"')).toThrow(/non-octet/);
  });

  it('rejects a malformed decimal escape rather than guessing', () => {
    expect(() => parseRdata(RR_TYPE.TXT, '"\\12"')).toThrow(/three-digit/);
    expect(() => parseRdata(RR_TYPE.TXT, '"\\999"')).toThrow(/exceeds 255/);
  });
});

describe('ancestry', () => {
  it('recognises a name at or below a zone', () => {
    expect(isAtOrBelow(parseName('www.example.net.'), parseName('example.net.'))).toBe(true);
    expect(isAtOrBelow(parseName('example.net.'), parseName('example.net.'))).toBe(true);
    expect(isAtOrBelow(parseName('example.net.'), parseName('www.example.net.'))).toBe(false);
    expect(isAtOrBelow(parseName('example.org.'), parseName('example.net.'))).toBe(false);
  });
});
