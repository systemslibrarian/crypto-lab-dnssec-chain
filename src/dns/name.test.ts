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

describe('ancestry', () => {
  it('recognises a name at or below a zone', () => {
    expect(isAtOrBelow(parseName('www.example.net.'), parseName('example.net.'))).toBe(true);
    expect(isAtOrBelow(parseName('example.net.'), parseName('example.net.'))).toBe(true);
    expect(isAtOrBelow(parseName('example.net.'), parseName('www.example.net.'))).toBe(false);
    expect(isAtOrBelow(parseName('example.org.'), parseName('example.net.'))).toBe(false);
  });
});
