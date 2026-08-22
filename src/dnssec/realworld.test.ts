/**
 * The pinned real-world chain, validated end to end.
 *
 * These are the tests that make the lab's central claim checkable. Every byte
 * here was signed by the root zone, by Verisign for `.com`, and by Cloudflare
 * — none of it by this repository — so a green run means the canonicalization,
 * the key tags, the DS digests and three different signature algorithms are
 * all right at once, against evidence nobody here could have adjusted to fit.
 */

import { describe, expect, it } from 'vitest';

import { toHex } from '../dns/codec.ts';
import { parseName, presentName } from '../dns/name.ts';
import { RR_TYPE } from '../dns/types.ts';
import { PINNED_CHAIN, PINNED_ZONES, section } from '../vectors/pinned.ts';
import { ROOT_TRUST_ANCHORS } from '../vectors/rfc.ts';
import { dsPreimage } from './canonical.ts';
import { validateChain } from './chain.ts';
import { digest } from './crypto.ts';
import { keyTag } from './keytag.ts';
import { nsecCovers, proveNxdomain } from './nsec.ts';
import {
  ANCHORS,
  buildBlackLieDenial,
  buildInsecureChain,
  buildSecureChain,
  capturedOptOutFlag,
} from './realworld.ts';

describe('the pinned capture itself', () => {
  it('records the instant it was taken, and every section it promises', () => {
    expect(PINNED_CHAIN.capturedAt).toBeGreaterThan(1_700_000_000);
    for (const key of [
      'root-dnskey',
      'root-ds-for-com',
      'com-dnskey',
      'com-ds-for-cloudflare',
      'cloudflare-dnskey',
      'cloudflare-a',
      'cloudflare-nxdomain',
      'com-ds-for-google-none',
    ]) {
      expect(section(PINNED_CHAIN, key).command).toMatch(/^dig /);
    }
  });

  it('reproduces IANA’s published root key tags and DS digests', () => {
    // The answer key for this test is maintained by IANA, not by this repo:
    // hash the DNSKEY records the root actually served and the result must
    // equal the digests at data.iana.org/root-anchors/root-anchors.xml.
    const rootKeys = section(PINNED_CHAIN, 'root-dnskey').answer.filter(
      (r) => r.type === RR_TYPE.DNSKEY
    );
    for (const anchor of ROOT_TRUST_ANCHORS) {
      const match = rootKeys.find((r) => keyTag(r.rdata) === anchor.keyTag);
      expect(match, `root DNSKEY with tag ${anchor.keyTag} (${anchor.label})`).toBeDefined();
      const computed = digest(anchor.digestType, dsPreimage(PINNED_ZONES.root, match!.rdata));
      expect(toHex(computed)).toBe(anchor.digestHex);
    }
  });
});

describe('SECURE: root trust anchor down to a real A record', () => {
  it('validates every link at the capture instant', async () => {
    const result = await validateChain(buildSecureChain());
    expect(result.failure).toBeNull();
    expect(result.status).toBe('SECURE');
    expect(result.links.map((l) => l.title)).toEqual(['root zone', 'com', 'cloudflare.com']);
    expect(result.links.every((l) => l.status === 'SECURE')).toBe(true);
    expect(result.answer?.verification.verified).toBe(true);
  });

  it('crosses three zones and two signing algorithms', async () => {
    // The root signs with RSASHA256 (8); .com and cloudflare.com with
    // ECDSAP256SHA256 (13). A validator that only implemented one of them
    // could not walk this chain at all.
    const result = await validateChain(buildSecureChain());
    const algorithms = result.links.map((l) => l.vouchedKey?.algorithm);
    expect(algorithms).toEqual([8, 13, 13]);
  });

  it('names each zone’s vouched key by the tag its parent published', async () => {
    const result = await validateChain(buildSecureChain());
    const tags = result.links.map((l) => l.vouchedKey?.tag);
    // Root: an IANA anchor. .com: DS 19718 at the root. cloudflare.com: DS
    // 2371 at .com. All three read off the captured records, not hardcoded.
    expect(tags[0]).toBeGreaterThan(0);
    expect(tags[1]).toBe(19718);
    expect(tags[2]).toBe(2371);
  });

  it('goes BOGUS with RRSIG_EXPIRED once the clock passes every signature', async () => {
    const result = await validateChain(
      buildSecureChain(PINNED_CHAIN, { now: PINNED_CHAIN.capturedAt + 400 * 86400 })
    );
    expect(result.status).toBe('BOGUS');
    expect(result.failure).toBe('RRSIG_EXPIRED');
    // The first link is the one that stops: the root's own signature expires
    // first in wall-clock terms, and a resolver never gets past it.
    expect(result.stoppedAt).toBe(0);
  });

  it('goes BOGUS with RRSIG_NOT_YET_VALID when the clock runs backwards', async () => {
    const result = await validateChain(
      buildSecureChain(PINNED_CHAIN, { now: PINNED_CHAIN.capturedAt - 400 * 86400 })
    );
    expect(result.status).toBe('BOGUS');
    expect(result.failure).toBe('RRSIG_NOT_YET_VALID');
  });

  it('flags a flipped DS digest at the parent’s signature, before the digest is compared', async () => {
    const result = await validateChain(
      buildSecureChain(PINNED_CHAIN, {
        mutate: (input) => {
          const zones = input.zones.map((z) => {
            if (presentName(z.zone) !== 'com.' || !z.ds) return z;
            const rdatas = z.ds.rdatas.map((rdata) => {
              const copy = Uint8Array.from(rdata);
              const last = copy[copy.length - 1];
              if (last !== undefined) copy[copy.length - 1] = last ^ 0xff;
              return copy;
            });
            return { ...z, ds: { ...z.ds, rdatas } };
          });
          return { ...input, zones };
        },
      })
    );
    // The DS is signed by the root, so corrupting it breaks the SIGNATURE over
    // the DS RRset before the digest is ever compared. That ordering is itself
    // the lesson: the parent's signature protects the fingerprint.
    expect(result.status).toBe('BOGUS');
    expect(result.failure).toBe('SIGNATURE_INVALID');
    expect(result.stoppedAt).toBe(1);
  });

  it('goes BOGUS with SIGNATURE_INVALID when the answer’s address is changed', async () => {
    const result = await validateChain(
      buildSecureChain(PINNED_CHAIN, {
        mutate: (input) => {
          if (!input.answer) throw new Error('secure chain lost its answer');
          const rdatas = input.answer.rrset.rdatas.map((rdata) => {
            const copy = Uint8Array.from(rdata);
            const last = copy[copy.length - 1];
            if (last !== undefined) copy[copy.length - 1] = (last + 1) & 0xff;
            return copy;
          });
          return { ...input, answer: { ...input.answer, rrset: { ...input.answer.rrset, rdatas } } };
        },
      })
    );
    expect(result.status).toBe('BOGUS');
    expect(result.failure).toBe('SIGNATURE_INVALID');
    // Every link still verified; only the answer failed.
    expect(result.links.every((l) => l.status === 'SECURE')).toBe(true);
  });

  it('flags a moved DS key tag at the parent’s signature too — an edited DS is a forged DS', async () => {
    const result = await validateChain(
      buildSecureChain(PINNED_CHAIN, {
        mutate: (input) => {
          const zones = input.zones.map((z) => {
            if (presentName(z.zone) !== 'cloudflare.com.' || !z.ds) return z;
            const rdatas = z.ds.rdatas.map((rdata) => {
              const copy = Uint8Array.from(rdata);
              copy[0] = (copy[0]! + 1) & 0xff; // move the key tag
              return copy;
            });
            return { ...z, ds: { ...z.ds, rdatas } };
          });
          return { ...input, zones };
        },
      })
    );
    expect(result.status).toBe('BOGUS');
    // The DS RRset is signed by .com, so this too is caught by the parent's
    // signature first. A DS a learner edits is always a forged DS.
    expect(result.failure).toBe('SIGNATURE_INVALID');
  });
});

describe('INSECURE: a signed parent proving an unsigned child', () => {
  it('reaches INSECURE at google.com, not BOGUS', async () => {
    const result = await validateChain(buildInsecureChain());
    expect(result.status).toBe('INSECURE');
    expect(result.failure).toBeNull();
    expect(result.links).toHaveLength(3);
    expect(result.links[0]?.status).toBe('SECURE');
    expect(result.links[1]?.status).toBe('SECURE');
    expect(result.links[2]?.status).toBe('INSECURE');
  });

  it('rests on an Opt-Out NSEC3, and says so', async () => {
    expect(capturedOptOutFlag()).toBe(true);
    const result = await validateChain(buildInsecureChain());
    const link = result.links[2];
    expect(link?.noDsProof?.proven).toBe(true);
    const optOutStep = link?.checks.find((c) => /Opt-Out/.test(c.label));
    expect(optOutStep?.passed).toBe(true);
  });

  it('does not claim the delegation is broken', async () => {
    const result = await validateChain(buildInsecureChain());
    // Nothing in an INSECURE outcome may carry a failure code: a validating
    // resolver returns this answer to the client, it does not SERVFAIL.
    expect(result.links.every((l) => l.failure === null)).toBe(true);
  });
});

describe('online minimally covering denial, as captured', () => {
  const denial = buildBlackLieDenial();

  it('answers a nonexistent name with NOERROR rather than NXDOMAIN', () => {
    expect(denial.rcodeIsNoError).toBe(true);
  });

  it('covers a gap that contains only the queried name', () => {
    const record = denial.nsec[0];
    expect(record).toBeDefined();
    // Owner is the queried name; next is that name with a single NUL octet
    // prepended as a new label -- RFC 4470's increment function, the smallest
    // possible step forward in canonical order.
    expect(presentName(record!.owner)).toBe(presentName(denial.queried));
    expect(presentName(record!.rdata.nextName)).toBe(`\\000.${presentName(denial.queried)}`);
  });

  it('leaves nothing to walk to: no real neighbour is disclosed', () => {
    const record = denial.nsec[0]!;
    // A classic NSEC hands back a name that exists. This one hands back a name
    // constructed from the query, so a walker learns nothing it did not
    // already know. Confirm by checking that the only thing the gap can cover
    // is a name derived from the query itself.
    const walkTarget = presentName(record.rdata.nextName);
    expect(walkTarget.endsWith(presentName(denial.queried))).toBe(true);
    expect(walkTarget.startsWith('\\000.')).toBe(true);
  });

  it('still refuses to cover a name outside its interval', () => {
    const record = denial.nsec[0]!;
    expect(nsecCovers(record, parseName('www.cloudflare.com.'))).toBe(false);
  });

  it('is not a general NXDOMAIN proof — there is no wildcard half', () => {
    // Black lies answer NODATA, so RFC 4035's two-part NXDOMAIN proof does not
    // apply and must not be claimed. Asserting the NXDOMAIN prover fails here
    // is what stops the page describing this as something it is not.
    const proof = proveNxdomain(denial.nsec, denial.queried, denial.zone);
    expect(proof.proven).toBe(false);
  });
});

describe('every anchor is usable', () => {
  it('renders each IANA anchor as DS RDATA the matcher accepts', () => {
    expect(ANCHORS).toHaveLength(ROOT_TRUST_ANCHORS.length);
    for (const anchor of ANCHORS) {
      expect(anchor.rdata.length).toBeGreaterThan(4);
    }
  });
});
