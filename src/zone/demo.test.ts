/**
 * The in-page hierarchy: signed here, verified here, broken here.
 *
 * Every assertion below runs against signatures this code made moments
 * earlier, with the same validator that judges the pinned real-world chain. A
 * green run means the signer and the verifier agree; the KAT suite is what
 * proves they agree with the RFCs rather than only with each other.
 */

import { describe, expect, it } from 'vitest';

import { parseName, presentName } from '../dns/name.ts';
import { RR_TYPE, toRRsets } from '../dns/types.ts';
import { validateChain } from '../dnssec/chain.ts';
import { nsec3Hash, proveNsec3Nxdomain, toNsec3Record } from '../dnssec/nsec3.ts';
import { fromBase32Hex } from '../dns/codec.ts';
import {
  buildDemoZone,
  buildHierarchy,
  DEMO_EXPIRATION,
  DEMO_INCEPTION,
  DEMO_NOW,
  GUESSABLE_LABELS,
  HIGH_ENTROPY_LABELS,
  RECOMMENDED_NSEC3,
  ZONE,
} from './demo.ts';
import { checkDenial, queryZone, resolveInDemo } from './resolve.ts';

const at = { now: DEMO_NOW } as const;

describe('a zone signed in the page', () => {
  it('validates from the configured anchor to a real answer', async () => {
    const hierarchy = await buildHierarchy();
    const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, at);
    expect(resolution.result.status).toBe('SECURE');
    expect(resolution.result.failure).toBeNull();
    expect(resolution.result.links.map((l) => l.title)).toEqual([
      'root zone',
      'example.',
      'demo.example.',
    ]);
  });

  it('uses Ed25519 for the child’s KSK and ECDSA P-256 for its ZSK', async () => {
    const hierarchy = await buildHierarchy();
    expect(hierarchy.keys.zoneKsk.key.algorithm).toBe(15);
    expect(hierarchy.keys.zoneZsk.key.algorithm).toBe(13);
    const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, at);
    // The DS points at the Ed25519 KSK; the answer is signed by the ECDSA ZSK.
    expect(resolution.result.links[2]?.vouchedKey?.algorithm).toBe(15);
    expect(resolution.result.answer?.verification.attempts[0]?.keyUsed?.algorithm).toBe(13);
  });

  it('re-verifies every RRset it signed', async () => {
    const zone = await buildDemoZone();
    for (const [, signed] of zone.signed) {
      expect(signed.rrsigs.length, presentName(signed.rrset.name)).toBeGreaterThan(0);
    }
    expect(zone.owners.length).toBe(GUESSABLE_LABELS.length + 1);
  });
});

describe('each link breaks with its own name', () => {
  it('DS_MISMATCH when the parent publishes a correctly signed but wrong digest', async () => {
    // Re-signed, not corrupted: the parent's signature over the DS is valid,
    // and the digest inside it simply does not match the child's key. This is
    // the failure a registrar causes by not updating the DS after a key roll.
    const hierarchy = await buildHierarchy({ corruptDs: true });
    const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, at);
    expect(resolution.result.status).toBe('BOGUS');
    expect(resolution.result.failure).toBe('DS_MISMATCH');
    expect(resolution.result.stoppedAt).toBe(2);
  });

  it('KEYTAG_MISMATCH when the DS names a key tag the child does not publish', async () => {
    const hierarchy = await buildHierarchy({ wrongKeyTag: true });
    const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, at);
    expect(resolution.result.failure).toBe('KEYTAG_MISMATCH');
    expect(resolution.result.status).toBe('BOGUS');
  });

  it('RRSIG_EXPIRED once the clock passes the window', async () => {
    const hierarchy = await buildHierarchy();
    const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, {
      now: DEMO_EXPIRATION + 60,
    });
    expect(resolution.result.failure).toBe('RRSIG_EXPIRED');
  });

  it('RRSIG_NOT_YET_VALID when the clock is behind the inception', async () => {
    const hierarchy = await buildHierarchy();
    const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, {
      now: DEMO_INCEPTION - 60,
    });
    expect(resolution.result.failure).toBe('RRSIG_NOT_YET_VALID');
  });

  it('KEYTAG_MISMATCH when the zone signs its keys with a key nobody vouched for', async () => {
    const hierarchy = await buildHierarchy({ rogueKsk: true });
    const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, at);
    expect(resolution.result.status).toBe('BOGUS');
    expect(resolution.result.failure).toBe('KEYTAG_MISMATCH');
  });

  it('SIGNATURE_INVALID when an answer’s bytes change after signing', async () => {
    // The whole chain still verifies; only the answer's own bytes moved. This
    // is a man-in-the-middle rewriting an address, and it is the one failure
    // that is genuinely an attack rather than an operational mistake.
    const hierarchy = await buildHierarchy();
    const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, at);
    const original = resolution.input.answer;
    expect(original).not.toBeNull();
    const rdatas = original!.rrset.rdatas.map((rdata) => {
      const copy = Uint8Array.from(rdata);
      const last = copy[copy.length - 1];
      if (last !== undefined) copy[copy.length - 1] = (last + 1) & 0xff;
      return copy;
    });
    const result = await validateChain({
      ...resolution.input,
      answer: { rrset: { ...original!.rrset, rdatas }, rrsigs: original!.rrsigs },
    });
    expect(result.failure).toBe('SIGNATURE_INVALID');
    expect(result.status).toBe('BOGUS');
    expect(result.links.every((l) => l.status === 'SECURE')).toBe(true);
  });
});

describe('INSECURE: an unsigned child under a signed parent', () => {
  it('ends the chain rather than breaking it', async () => {
    const hierarchy = await buildHierarchy();
    const resolution = await resolveInDemo(
      hierarchy,
      parseName('www.unsigned.example.'),
      RR_TYPE.A,
      { ...at, target: 'unsigned' }
    );
    expect(resolution.result.status).toBe('INSECURE');
    expect(resolution.result.failure).toBeNull();
  });

  it('rests on an NSEC that shows NS set and DS clear', async () => {
    const hierarchy = await buildHierarchy();
    const resolution = await resolveInDemo(
      hierarchy,
      parseName('www.unsigned.example.'),
      RR_TYPE.A,
      { ...at, target: 'unsigned' }
    );
    const link = resolution.result.links[2];
    const labels = link?.checks.map((c) => c.label) ?? [];
    expect(labels).toContain('NS present — this is a delegation');
    expect(labels).toContain('DS absent from the bit map');
    expect(labels).toContain('SOA absent — the parent is speaking');
    expect(link?.checks.every((c) => c.passed)).toBe(true);
  });

  it('is a different outcome from a missing DS with no proof', async () => {
    // Removing the DS *and* the proof is not INSECURE, it is a hole. The
    // distinction is the entire point of authenticated denial.
    const hierarchy = await buildHierarchy({ noDs: true });
    const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, at);
    expect(resolution.result.status).toBe('BOGUS');
  });
});

describe('denial of existence, in both flavours', () => {
  it('proves NXDOMAIN with a covering NSEC and a wildcard NSEC', async () => {
    const zone = await buildDemoZone();
    const response = queryZone(zone, parseName('nothing-here.demo.example.'), RR_TYPE.A);
    expect(response.rcode).toBe('NXDOMAIN');
    const proof = checkDenial(zone, response);
    expect(proof?.proven).toBe(true);
    expect(proof?.steps.map((s) => s.label)).toContain('No wildcard could have answered');
  });

  it('proves NODATA with the record that asserts the name', async () => {
    const zone = await buildDemoZone();
    const response = queryZone(zone, parseName('www.demo.example.'), RR_TYPE.MX);
    expect(response.rcode).toBe('NOERROR');
    expect(response.answer).toBeNull();
    expect(checkDenial(zone, response)?.proven).toBe(true);
  });

  it('proves NXDOMAIN under NSEC3 through a closest-encloser proof', async () => {
    const zone = await buildDemoZone({ denial: { kind: 'nsec3', params: RECOMMENDED_NSEC3 } });
    const response = queryZone(zone, parseName('nothing-here.demo.example.'), RR_TYPE.A);
    expect(response.rcode).toBe('NXDOMAIN');
    const proof = checkDenial(zone, response);
    expect(proof?.proven).toBe(true);
  });

  it('rejects an NSEC3 proof whose parameters do not match the zone’s', async () => {
    const zone = await buildDemoZone({ denial: { kind: 'nsec3', params: RECOMMENDED_NSEC3 } });
    const records = zone.denialRecords
      .filter((r) => r.rrset.type === RR_TYPE.NSEC3)
      .flatMap((r) =>
        r.rrset.rdatas.map((rdata) => {
          const first = r.rrset.name[0];
          if (!first) throw new Error('NSEC3 owner has no labels');
          return toNsec3Record(r.rrset.name, rdata, fromBase32Hex(new TextDecoder().decode(first)));
        })
      );
    const wrong = { ...RECOMMENDED_NSEC3, iterations: 5 };
    const proof = proveNsec3Nxdomain(records, parseName('nothing.demo.example.'), ZONE, wrong);
    expect(proof.proven).toBe(false);
    expect(proof.steps[0]?.label).toBe('NSEC3 parameters agree');
    expect(proof.steps[0]?.passed).toBe(false);
  });

  it('hashes each name to the owner label the zone published', async () => {
    const zone = await buildDemoZone({ denial: { kind: 'nsec3', params: RECOMMENDED_NSEC3 } });
    for (const [label, name] of zone.hashedOwners) {
      const { toBase32Hex } = await import('../dns/codec.ts');
      expect(toBase32Hex(nsec3Hash(name, RECOMMENDED_NSEC3)).toLowerCase()).toBe(label);
    }
  });
});

describe('ZSK rollover', () => {
  it('pre-publish adds the successor to the DNSKEY RRset without using it', async () => {
    const zone = await buildDemoZone({ rollover: 'pre-publish' });
    const rrset = toRRsets([])[0];
    void rrset;
    expect(zone.dnskey.rrset.rdatas).toHaveLength(3); // KSK + active ZSK + successor
    const answer = zone.signed.get('www.demo.example.|1|1');
    expect(answer?.rrsigs).toHaveLength(1); // still only the old ZSK signs
  });

  it('double-signature signs every RRset with both ZSKs at once', async () => {
    const zone = await buildDemoZone({ rollover: 'double-signature' });
    const answer = zone.signed.get('www.demo.example.|1|1');
    expect(answer?.rrsigs).toHaveLength(2);
    expect(new Set(answer?.signedBy).size).toBe(2);
  });

  it('validates in every rollover state, which is the point of doing it that way', async () => {
    for (const rollover of ['none', 'pre-publish', 'double-signature', 'complete'] as const) {
      const hierarchy = await buildHierarchy({ rollover });
      const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, at);
      expect(resolution.result.status, rollover).toBe('SECURE');
    }
  });
});

describe('the two label sets', () => {
  it('are the same size, so a recovery rate compares like with like', () => {
    expect(HIGH_ENTROPY_LABELS.length).toBe(GUESSABLE_LABELS.length);
  });

  it('produce zones that differ only in their names', async () => {
    const guessable = await buildDemoZone({ labels: GUESSABLE_LABELS });
    const random = await buildDemoZone({ labels: HIGH_ENTROPY_LABELS });
    expect(guessable.owners.length).toBe(random.owners.length);
    expect(guessable.spec.denial.kind).toBe(random.spec.denial.kind);
  });
});
