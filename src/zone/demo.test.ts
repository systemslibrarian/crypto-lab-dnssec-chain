/**
 * The in-page hierarchy: signed here, verified here, broken here.
 *
 * Every assertion below runs against signatures this code made moments
 * earlier, with the same validator that judges the pinned real-world chain. A
 * green run means the signer and the verifier agree; the KAT suite is what
 * proves they agree with the RFCs rather than only with each other.
 */

import { describe, expect, it } from 'vitest';

import { isWildcardExpansion, signedOwnerName } from '../dnssec/canonical.ts';
import { parseName, presentName, rrsigLabelCount } from '../dns/name.ts';
import { decodeRrsig, encodeRrsig, parseRdata } from '../dns/rdata.ts';
import { CLASS_IN, RR_TYPE, toRRsets, typeName } from '../dns/types.ts';
import { validateChain } from '../dnssec/chain.ts';
import { proveNsecNoDs, toNsecRecord } from '../dnssec/nsec.ts';
import { nsec3Hash, proveNsec3Nxdomain, toNsec3Record } from '../dnssec/nsec3.ts';
import { verifyRrset } from '../dnssec/verify.ts';
import { fromBase32Hex, toBase32Hex } from '../dns/codec.ts';
import {
  buildDemoZone,
  buildHierarchy,
  demoKeys,
  DEMO_EXPIRATION,
  DEMO_INCEPTION,
  DEMO_NOW,
  GUESSABLE_LABELS,
  HIGH_ENTROPY_LABELS,
  RECOMMENDED_NSEC3,
  TLD,
  ZONE,
} from './demo.ts';
import { checkDenial, queryZone, resolveInDemo } from './resolve.ts';
import { signRrsetAs } from './sign.ts';

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

  it('re-verifies every RRset it signed, cryptographically', async () => {
    // Not "an RRSIG exists" -- that would pass against a signer that emitted
    // 64 zero octets. Every signed RRset in the zone, including the NSEC
    // denial chain and the DNSKEY set itself, is run back through the same
    // verifier that judges the pinned real-world chain.
    const zone = await buildDemoZone();
    const keys = zone.dnskey.rrset.rdatas;
    let checked = 0;
    for (const [, signed] of zone.signed) {
      expect(signed.rrsigs.length, presentName(signed.rrset.name)).toBeGreaterThan(0);
      const result = await verifyRrset(signed.rrset, signed.rrsigs, keys, {
        zone: zone.spec.apex,
        now: DEMO_NOW,
      });
      expect(
        result.verified,
        `${presentName(signed.rrset.name)} ${typeName(signed.rrset.type)}: ${result.failure}`
      ).toBe(true);
      checked += 1;
    }
    // Guard the loop: a zone that produced nothing would otherwise pass here.
    expect(checked).toBeGreaterThan(GUESSABLE_LABELS.length);
    expect(zone.owners.length).toBe(GUESSABLE_LABELS.length + 1);

    // The denial chain specifically -- one signed NSEC per owner name.
    expect(zone.denialRecords).toHaveLength(zone.owners.length);
    for (const denial of zone.denialRecords) {
      const result = await verifyRrset(denial.rrset, denial.rrsigs, keys, {
        zone: zone.spec.apex,
        now: DEMO_NOW,
      });
      expect(result.verified, presentName(denial.rrset.name)).toBe(true);
    }
  });

  it('signs and verifies a wildcard answer through the Labels reconstruction', async () => {
    // A wildcard RRSIG counts FEWER labels than the name it answers for, and
    // the validator has to rebuild `*.<suffix>` to check it. Nothing else in
    // the suite reaches that branch: the demo zone has no wildcard, and no RFC
    // vector or pinned RRSIG is a wildcard expansion either.
    const keys = await demoKeys();
    const wildcard = parseName('*.demo.example.');
    const rrset = {
      name: wildcard,
      type: RR_TYPE.A,
      class: CLASS_IN,
      ttl: 3600,
      rdatas: [parseRdata(RR_TYPE.A, '203.0.113.200')],
    };
    expect(rrsigLabelCount(wildcard)).toBe(2);
    const rrsig = await signRrsetAs(rrset, keys.zoneZsk, {
      apex: ZONE,
      inception: DEMO_INCEPTION,
      expiration: DEMO_EXPIRATION,
    });

    // The synthesized answer: a name that does not literally exist, carrying
    // the wildcard's signature.
    const synthesized = { ...rrset, name: parseName('anything.demo.example.') };
    expect(isWildcardExpansion(synthesized.name, 2)).toBe(true);
    expect(presentName(signedOwnerName(synthesized.name, 2))).toBe('*.demo.example.');

    const dnskeys = [keys.zoneKsk.rdata, keys.zoneZsk.rdata];
    const ok = await verifyRrset(synthesized, [rrsig], dnskeys, { zone: ZONE, now: DEMO_NOW });
    expect(ok.verified).toBe(true);
    expect(ok.attempts[0]?.fromWildcard).toBe(true);

    // The reconstruction is LOAD-BEARING. Take the very same signature and
    // change only the Labels field to the literal name's count: the validator
    // then stops reconstructing the wildcard and hashes `anything.demo.
    // example.` instead, and the identical signature no longer verifies.
    const decoded = decodeRrsig(rrsig);
    const claimsLiteral = encodeRrsig({ ...decoded, labels: 3 });
    const wrong = await verifyRrset(synthesized, [claimsLiteral], dnskeys, {
      zone: ZONE,
      now: DEMO_NOW,
    });
    expect(wrong.verified).toBe(false);
    expect(wrong.failure).toBe('SIGNATURE_INVALID');
    expect(wrong.attempts[0]?.fromWildcard).toBe(false);

    // And a Labels field larger than the owner name has is not a wildcard at
    // all — it is unreconstructable, and says so.
    const impossible = encodeRrsig({ ...decoded, labels: 9 });
    const rejected = await verifyRrset(synthesized, [impossible], dnskeys, {
      zone: ZONE,
      now: DEMO_NOW,
    });
    expect(rejected.failure).toBe('LABELS_INVALID');
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

  it('KEYTAG_MISMATCH when the child rolled its KSK and the DS still names the old one', async () => {
    // The DS is the honest one, and the child now publishes a different
    // key-signing key. `matchDs` stops first, at "the DS points at a key tag
    // this child does not publish" -- which is the correct and most
    // informative diagnosis for this shape, and is exactly what a resolver
    // holding a stale cached DS sees.
    //
    // The DEEPER check -- that the key which signed the DNSKEY RRset is
    // byte-for-byte the key the DS vouched for, even when the tags agree -- is
    // not reachable from here, because the tags do not agree. It is pinned in
    // `src/dnssec/downgrade.test.ts` with a real tag collision instead.
    const hierarchy = await buildHierarchy({ rogueKsk: true });
    const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, at);
    expect(resolution.result.status).toBe('BOGUS');
    expect(resolution.result.failure).toBe('KEYTAG_MISMATCH');
    const link = resolution.result.links[2];
    expect(link?.checks.find((c) => c.id === 'binding')).toBeUndefined();
    expect(link?.checks.some((c) => c.label.includes('Referenced key') && !c.passed)).toBe(true);
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

  it('rejects an NSEC that came from the child side of the cut', async () => {
    // The all-passing case above proves the three steps are PRINTED. This one
    // proves the conjunction that computes `proven` actually depends on them:
    // a child's own apex NSEC carries SOA, NS and DNSKEY and never carries DS,
    // so checking only the DS bit would let a signed zone declare itself
    // unsigned.
    const delegation = parseName('unsigned.example.');
    const build = (types: number[]) =>
      toNsecRecord(
        delegation,
        parseRdata(RR_TYPE.NSEC, `next.example. ${types.map(typeName).join(' ')}`)
      );

    const fromChild = proveNsecNoDs([build([RR_TYPE.NS, RR_TYPE.SOA, RR_TYPE.RRSIG, RR_TYPE.DNSKEY])], delegation, TLD);
    expect(fromChild.proven).toBe(false);
    expect(fromChild.steps.find((x) => x.label.startsWith('SOA absent'))?.passed).toBe(false);

    const notADelegation = proveNsecNoDs([build([RR_TYPE.A, RR_TYPE.RRSIG])], delegation, TLD);
    expect(notADelegation.proven).toBe(false);
    expect(notADelegation.steps.find((x) => x.label.startsWith('NS present'))?.passed).toBe(false);

    const stillHasDs = proveNsecNoDs([build([RR_TYPE.NS, RR_TYPE.DS, RR_TYPE.RRSIG])], delegation, TLD);
    expect(stillHasDs.proven).toBe(false);

    const fromParent = proveNsecNoDs([build([RR_TYPE.NS, RR_TYPE.RRSIG])], delegation, TLD);
    expect(fromParent.proven).toBe(true);
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
    // Found by label rather than by index: the bailiwick check runs first.
    const params = proof.steps.find((step) => step.label === 'NSEC3 parameters agree');
    expect(params?.passed).toBe(false);
  });

  it('publishes an NSEC3 owner label for every name, and each one is that name’s hash', async () => {
    const zone = await buildDemoZone({ denial: { kind: 'nsec3', params: RECOMMENDED_NSEC3 } });

    // Read the labels the zone ACTUALLY PUBLISHES, off the NSEC3 owner names,
    // rather than re-reading the map the signer built while producing them.
    const published = zone.denialRecords
      .filter((r) => r.rrset.type === RR_TYPE.NSEC3)
      .map((r) => new TextDecoder().decode(r.rrset.name[0] ?? new Uint8Array()));
    expect(published).toHaveLength(zone.owners.length);
    expect(new Set(published).size).toBe(published.length);

    // Every owner in the zone must appear exactly once in that set, hashed.
    for (const owner of zone.owners) {
      const expected = toBase32Hex(nsec3Hash(owner, RECOMMENDED_NSEC3)).toLowerCase();
      expect(published, presentName(owner)).toContain(expected);
    }
    // ...and the ring is sorted by hash, which is the whole point of NSEC3.
    expect([...published].sort()).toEqual(published);
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
