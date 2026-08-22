/**
 * Downgrade attempts, and the checks that stop them.
 *
 * Every test here is an attack on the CLASSIFICATION rather than on the
 * cryptography. None of them forges a signature; each one tries to make a
 * validator reach a weaker verdict than the evidence supports — SECURE from a
 * substituted key, INSECURE from a zone that is actually signed, "proved" from
 * a denial that proves nothing. Those are the failures that matter in a
 * validator, because a wrong SECURE is invisible and a wrong INSECURE is
 * delivered to the client rather than refused.
 *
 * Six of these pin fixes for defects an adversarial review found in this
 * lab's own first implementation. They are here so the fixes cannot silently
 * regress.
 */

import { describe, expect, it } from 'vitest';

import { fromHex, toBase32Hex } from '../dns/codec.ts';
import { parseName, presentName } from '../dns/name.ts';
import { encodeDs, encodeNsec, encodeNsec3, encodeDnskey } from '../dns/rdata.ts';
import { CLASS_IN, DIGEST_TYPE, RR_TYPE, type RRset } from '../dns/types.ts';
import { COLLIDING_TAG_SEEDS } from '../vectors/demo-keys.ts';
import { buildDemoZone, buildHierarchy, DEMO_NOW, TLD, UNSIGNED_CHILD, ZONE } from '../zone/demo.ts';
import { checkDenial, queryZone, resolveInDemo } from '../zone/resolve.ts';
import { keyRole, signRrsetAs } from '../zone/sign.ts';
import { dsPreimage } from './canonical.ts';
import { validateChain } from './chain.ts';
import { digest, importPinnedEd25519Key } from './crypto.ts';
import { keyTag } from './keytag.ts';
import { proveNxdomain, toNsecRecord } from './nsec.ts';
import { nsec3Hash, proveNsec3NoDs, toNsec3Record } from './nsec3.ts';

const ROOT = parseName('.');
const WINDOW = { inception: DEMO_NOW - 86400, expiration: DEMO_NOW + 86400 } as const;

describe('a key tag is not an identity', () => {
  it('the two pinned keys really do collide', () => {
    const vouched = keyRole(importPinnedEd25519Key(fromHex(COLLIDING_TAG_SEEDS.vouched)), true);
    const impostor = keyRole(importPinnedEd25519Key(fromHex(COLLIDING_TAG_SEEDS.impostor)), true);
    expect(vouched.tag).toBe(COLLIDING_TAG_SEEDS.tag);
    expect(impostor.tag).toBe(COLLIDING_TAG_SEEDS.tag);
    // Same tag, different keys. That is the entire premise.
    expect(keyTag(vouched.rdata)).toBe(keyTag(impostor.rdata));
    expect(Array.from(vouched.rdata)).not.toEqual(Array.from(impostor.rdata));
  });

  it('rejects a zone that signs its key set with a DIFFERENT key of the same tag', async () => {
    // The attack: publish an impostor key beside the real one, get the tags to
    // collide, and sign the DNSKEY RRset with the impostor. A validator that
    // binds the parent's DS to the child's key by TAG sees a match and reports
    // SECURE, and every RRset below then validates under the impostor.
    const vouched = keyRole(importPinnedEd25519Key(fromHex(COLLIDING_TAG_SEEDS.vouched)), true);
    const impostor = keyRole(importPinnedEd25519Key(fromHex(COLLIDING_TAG_SEEDS.impostor)), true);

    const dnskeys: RRset = {
      name: ROOT,
      type: RR_TYPE.DNSKEY,
      class: CLASS_IN,
      ttl: 3600,
      rdatas: [vouched.rdata, impostor.rdata],
    };
    // Signed by the IMPOSTOR. The signature is genuine; the key is wrong.
    const rrsig = await signRrsetAs(dnskeys, impostor, { apex: ROOT, ...WINDOW });

    // The anchor vouches for the real key.
    const anchor = encodeDs({
      keyTag: vouched.tag,
      algorithm: vouched.key.algorithm,
      digestType: DIGEST_TYPE.SHA256,
      digest: digest(DIGEST_TYPE.SHA256, dsPreimage(ROOT, vouched.rdata)),
    });

    const result = await validateChain({
      anchors: [{ label: 'configured anchor', rdata: anchor }],
      zones: [
        { zone: ROOT, title: 'root zone', dnskeys, dnskeyRrsigs: [rrsig], ds: null, dsRrsigs: [] },
      ],
      answer: null,
      now: DEMO_NOW,
    });

    expect(result.status).toBe('BOGUS');
    expect(result.failure).toBe('KEYTAG_MISMATCH');
    // And the page must say WHY, so a reader is not left thinking the tags
    // disagreed when in fact they matched perfectly.
    const binding = result.links[0]?.checks.find((c) => c.id === 'binding');
    expect(binding?.passed).toBe(false);
    expect(binding?.detail).toContain('a tag is a checksum');
  });

  it('accepts the same set when the vouched key is the one that signed', async () => {
    // The control. Identical shape, identical colliding tags — only the
    // signing key changes — so the rejection above is about the key and not
    // about anything else in the construction.
    const vouched = keyRole(importPinnedEd25519Key(fromHex(COLLIDING_TAG_SEEDS.vouched)), true);
    const impostor = keyRole(importPinnedEd25519Key(fromHex(COLLIDING_TAG_SEEDS.impostor)), true);
    const dnskeys: RRset = {
      name: ROOT,
      type: RR_TYPE.DNSKEY,
      class: CLASS_IN,
      ttl: 3600,
      rdatas: [vouched.rdata, impostor.rdata],
    };
    const rrsig = await signRrsetAs(dnskeys, vouched, { apex: ROOT, ...WINDOW });
    const anchor = encodeDs({
      keyTag: vouched.tag,
      algorithm: vouched.key.algorithm,
      digestType: DIGEST_TYPE.SHA256,
      digest: digest(DIGEST_TYPE.SHA256, dsPreimage(ROOT, vouched.rdata)),
    });
    const result = await validateChain({
      anchors: [{ label: 'configured anchor', rdata: anchor }],
      zones: [
        { zone: ROOT, title: 'root zone', dnskeys, dnskeyRrsigs: [rrsig], ds: null, dsRrsigs: [] },
      ],
      answer: null,
      now: DEMO_NOW,
    });
    expect(result.status).toBe('SECURE');
    expect(result.failure).toBeNull();
  });
});

describe('a denial only speaks for its own zone', () => {
  it('refuses to prove NXDOMAIN for a name outside the zone', async () => {
    // The last NSEC in a chain wraps to the apex, so by construction it covers
    // every name sorting after the last owner -- including names in unrelated
    // zones. Without a bailiwick check, one zone's valid signed chain "proves"
    // that names in somebody else's zone do not exist.
    const zone = await buildDemoZone();
    const records = zone.denialRecords
      .filter((r) => r.rrset.type === RR_TYPE.NSEC)
      .flatMap((r) => r.rrset.rdatas.map((rdata) => toNsecRecord(r.rrset.name, rdata)));

    for (const outsider of ['www.google.com.', 'evil.attacker.net.', 'com.', 'zzz.']) {
      const proof = proveNxdomain(records, parseName(outsider), ZONE);
      expect(proof.proven, outsider).toBe(false);
      expect(proof.steps[0]?.label).toBe('Query is inside this zone');
      expect(proof.steps[0]?.passed).toBe(false);
    }

    // The same records still prove a real absence inside the zone.
    const inside = proveNxdomain(records, parseName('nothing-here.demo.example.'), ZONE);
    expect(inside.proven).toBe(true);
  });

  it('refuses an out-of-zone name through the server path too', async () => {
    const zone = await buildDemoZone();
    const response = queryZone(zone, parseName('www.google.com.'), RR_TYPE.A);
    expect(checkDenial(zone, response)?.proven).toBe(false);
  });
});

describe('a denial proves only what the ANSWER carried', () => {
  it('fails when the authority section is stripped', async () => {
    // A verdict computed from the zone file rather than from the response
    // would still say "proved" here, and would hide any bug in the server's
    // denial construction behind a permanent green tick.
    const zone = await buildDemoZone();
    const response = queryZone(zone, parseName('nope.demo.example.'), RR_TYPE.A);
    expect(checkDenial(zone, response)?.proven).toBe(true);
    expect(checkDenial(zone, { ...response, authority: [] })?.proven).toBe(false);
  });

  it('fails when only the wildcard half of the proof survives', async () => {
    const zone = await buildDemoZone();
    const response = queryZone(zone, parseName('nope.demo.example.'), RR_TYPE.A);
    const nsecOnly = response.authority.filter((r) => r.rrset.type === RR_TYPE.NSEC);
    expect(nsecOnly.length).toBeGreaterThan(0);
    // Keep just the LAST NSEC. An NXDOMAIN proof needs both halves.
    const half = { ...response, authority: nsecOnly.slice(-1) };
    const proof = checkDenial(zone, half);
    expect(proof?.proven).toBe(false);
  });

  it('fails a NODATA denial whose asserting record was removed', async () => {
    const zone = await buildDemoZone();
    const response = queryZone(zone, parseName('www.demo.example.'), RR_TYPE.MX);
    expect(response.denialKind).toBe('nodata');
    expect(checkDenial(zone, response)?.proven).toBe(true);
    expect(checkDenial(zone, { ...response, authority: [] })?.proven).toBe(false);
  });
});

describe('a child cannot declare its own delegation unsigned', () => {
  it('rejects an NSEC3 that carries SOA — it came from the wrong side of the cut', () => {
    // RFC 5155 section 8.9 requires NS set AND SOA clear as well as DS clear.
    // A child's own apex NSEC3 has SOA, NS and DNSKEY and never has DS, so
    // checking only the DS bit lets a signed zone downgrade itself.
    const params = { hashAlgorithm: 1, iterations: 0, salt: new Uint8Array(0) };
    const delegation = parseName('child.example.');
    const zone = parseName('example.');
    const hash = nsec3Hash(delegation, params);
    const owner = parseName(`${toBase32Hex(hash).toLowerCase()}.example.`);
    const build = (types: number[]): ReturnType<typeof toNsec3Record> =>
      toNsec3Record(
        owner,
        encodeNsec3({
          hashAlgorithm: 1,
          flags: 0,
          iterations: 0,
          salt: new Uint8Array(0),
          nextHashedOwner: new Uint8Array(20).fill(0xff),
          types,
        }),
        hash
      );

    const childApex = build([RR_TYPE.NS, RR_TYPE.SOA, RR_TYPE.RRSIG, RR_TYPE.DNSKEY]);
    const fromChild = proveNsec3NoDs([childApex], delegation, zone, params);
    expect(fromChild.proven).toBe(false);
    expect(fromChild.steps.find((s) => s.label.startsWith('SOA absent'))?.passed).toBe(false);

    const notADelegation = build([RR_TYPE.A, RR_TYPE.RRSIG]);
    const noNs = proveNsec3NoDs([notADelegation], delegation, zone, params);
    expect(noNs.proven).toBe(false);
    expect(noNs.steps.find((s) => s.label.startsWith('NS present'))?.passed).toBe(false);

    const fromParent = build([RR_TYPE.NS, RR_TYPE.RRSIG]);
    const good = proveNsec3NoDs([fromParent], delegation, zone, params);
    expect(good.proven).toBe(true);
  });
});

describe('an unauthenticated denial cannot end a chain', () => {
  it('reports BOGUS when the no-DS proof carries no signature', async () => {
    // INSECURE is delivered to the client rather than refused, so being able
    // to assert it without a signature is a better attack than forging one.
    const hierarchy = await buildHierarchy();
    const resolution = await resolveInDemo(
      hierarchy,
      parseName('www.unsigned.example.'),
      RR_TYPE.A,
      { now: DEMO_NOW, target: 'unsigned' }
    );
    expect(resolution.result.status).toBe('INSECURE');

    const stripped = resolution.input.zones.map((z) =>
      z.noDsProof ? { ...z, noDsProof: { ...z.noDsProof, rrsets: [] } } : z
    );
    const result = await validateChain({ ...resolution.input, zones: stripped });
    expect(result.status).toBe('BOGUS');
    expect(result.links[2]?.checks.find((c) => c.id === 'no-ds-signature')?.passed).toBe(false);
  });

  it('reports BOGUS when the no-DS proof is signed by the wrong zone', async () => {
    const hierarchy = await buildHierarchy();
    const resolution = await resolveInDemo(
      hierarchy,
      parseName('www.unsigned.example.'),
      RR_TYPE.A,
      { now: DEMO_NOW, target: 'unsigned' }
    );
    // Re-sign the denial under the CHILD zone's key rather than the parent's.
    const forged = await Promise.all(
      resolution.input.zones.map(async (z) => {
        if (!z.noDsProof) return z;
        const rrsets = await Promise.all(
          z.noDsProof.rrsets.map(async (e) => ({
            rrset: e.rrset,
            rrsigs: [await signRrsetAs(e.rrset, hierarchy.keys.zoneZsk, { apex: ZONE, ...WINDOW })],
          }))
        );
        return { ...z, noDsProof: { ...z.noDsProof, rrsets } };
      })
    );
    const result = await validateChain({ ...resolution.input, zones: forged });
    expect(result.status).toBe('BOGUS');
    expect(result.failure).toBe('SIGNER_NAME_MISMATCH');
  });
});

describe('an unsupported DS algorithm ends the chain, it does not break it', () => {
  it('reports INSECURE when every DS names an algorithm this validator lacks', async () => {
    // RFC 6840 section 5.2: "a validator disregards any authenticated DS
    // records that specify unknown or unsupported DNSKEY algorithms. If none
    // are left, the zone is treated as if it were unsigned."
    const hierarchy = await buildHierarchy({ unsupportedAlgorithm: true });
    const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, {
      now: DEMO_NOW,
    });
    expect(resolution.result.status).toBe('INSECURE');
    expect(resolution.result.failure).toBe('ALG_UNSUPPORTED');
    // Nothing on the failing link may read as a forgery accusation.
    expect(resolution.result.links[2]?.checks.map((c) => c.code)).not.toContain('DS_MISMATCH');
  });
});

describe('the parent must vouch for a key that may sign', () => {
  it('rejects a DS pointing at a key whose Zone Key flag is clear', async () => {
    const zsk = keyRole(importPinnedEd25519Key(fromHex(COLLIDING_TAG_SEEDS.vouched)), true);
    // Same key material, Zone Key bit cleared: flags 1 (SEP only).
    const notAZoneKey = encodeDnskey({
      flags: 0x0001,
      protocol: 3,
      algorithm: zsk.key.algorithm,
      publicKey: zsk.key.publicKey,
    });
    const dnskeys: RRset = {
      name: ROOT,
      type: RR_TYPE.DNSKEY,
      class: CLASS_IN,
      ttl: 3600,
      rdatas: [notAZoneKey],
    };
    const rrsig = await signRrsetAs(dnskeys, { ...zsk, rdata: notAZoneKey, tag: keyTag(notAZoneKey) }, {
      apex: ROOT,
      ...WINDOW,
    });
    const anchor = encodeDs({
      keyTag: keyTag(notAZoneKey),
      algorithm: zsk.key.algorithm,
      digestType: DIGEST_TYPE.SHA256,
      digest: digest(DIGEST_TYPE.SHA256, dsPreimage(ROOT, notAZoneKey)),
    });
    const result = await validateChain({
      anchors: [{ label: 'configured anchor', rdata: anchor }],
      zones: [
        { zone: ROOT, title: 'root zone', dnskeys, dnskeyRrsigs: [rrsig], ds: null, dsRrsigs: [] },
      ],
      answer: null,
      now: DEMO_NOW,
    });
    expect(result.status).toBe('BOGUS');
    expect(result.failure).toBe('NOT_A_ZONE_KEY');
  });
});

describe('the delegation names in the demo hierarchy are what they claim', () => {
  it('places the unsigned child under the signed top-level zone', () => {
    expect(presentName(UNSIGNED_CHILD).endsWith(presentName(TLD))).toBe(true);
    expect(presentName(ZONE).endsWith(presentName(TLD))).toBe(true);
  });

  it('builds an NSEC whose type bit map round-trips', () => {
    // A denial is only as good as its bit map, and the bit map is the one part
    // of NSEC that is easy to encode plausibly and wrongly.
    const rdata = encodeNsec({
      nextName: parseName('b.example.'),
      types: [RR_TYPE.A, RR_TYPE.RRSIG, RR_TYPE.NSEC, 64444],
    });
    const record = toNsecRecord(parseName('a.example.'), rdata);
    expect(record.rdata.types).toEqual([RR_TYPE.A, RR_TYPE.RRSIG, RR_TYPE.NSEC, 64444]);
  });
});
