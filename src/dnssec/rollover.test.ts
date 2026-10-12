/** Real signatures over synthetic multi-key sets; not IANA root fixtures. */
import { describe, expect, it } from 'vitest';
import { parseName, type Labels } from '../dns/name.ts';
import { encodeDs } from '../dns/rdata.ts';
import { CLASS_IN, DIGEST_TYPE, RR_TYPE, type RRset } from '../dns/types.ts';
import { demoKeys, DEMO_NOW } from '../zone/demo.ts';
import { signRrsetAs, type KeyRole } from '../zone/sign.ts';
import { dsPreimage } from './canonical.ts';
import { validateChain, type AnchorDs, type ZoneEvidence } from './chain.ts';
import { digest } from './crypto.ts';

const root = parseName('.');
const child = parseName('example.');
const window = { inception: DEMO_NOW - 86400, expiration: DEMO_NOW + 86400 };
function anchor(key: KeyRole, zone = root): AnchorDs {
  return { label: `trusted ${key.tag}`, rdata: encodeDs({ keyTag: key.tag,
    algorithm: key.key.algorithm, digestType: DIGEST_TYPE.SHA256,
    digest: digest(DIGEST_TYPE.SHA256, dsPreimage(zone, key.rdata)) }) };
}
function keyset(zone: Labels, keys: KeyRole[]): RRset {
  return { name: zone, type: RR_TYPE.DNSKEY, class: CLASS_IN, ttl: 3600, rdatas: keys.map(k => k.rdata) };
}

describe('multi-key trust paths are existential, not order-dependent', () => {
  for (const signing of ['old', 'new', 'both'] as const) {
    for (const reverse of [false, true]) {
      it(`accepts ${signing} root signer(s), anchors ${reverse ? 'reversed' : 'normal'}`, async () => {
        const { rootKsk: oldKey, rootZsk: newKey, rogueKsk } = await demoKeys();
        const rrset = keyset(root, [oldKey, newKey, rogueKsk]);
        const signers = signing === 'both' ? [oldKey, newKey] : [signing === 'old' ? oldKey : newKey];
        const trusted = [anchor(oldKey), anchor(newKey)];
        const sigs = await Promise.all(signers.map(k => signRrsetAs(rrset, k, { apex: root, ...window })));
        // An unrelated, cryptographically valid signature comes first.
        sigs.unshift(await signRrsetAs(rrset, rogueKsk, { apex: root, ...window }));
        const result = await validateChain({ anchors: reverse ? trusted.reverse() : trusted,
          zones: [{ zone: root, title: 'synthetic root', dnskeys: rrset,
            dnskeyRrsigs: reverse ? sigs.reverse() : sigs, ds: null, dsRrsigs: [] }],
          answer: null, now: DEMO_NOW });
        expect(result.status).toBe('SECURE');
        expect(signers.map(k => k.tag)).toContain(result.links[0]?.vouchedKey?.tag);
      });
    }
  }
  for (const signing of ['old', 'new', 'both'] as const) {
    for (const reverseDs of [false, true]) {
      for (const reverseSigs of [false, true]) {
        it(`accepts child ${signing}, DS reverse=${reverseDs}, RRSIG reverse=${reverseSigs}`, async () => {
          const { rootKsk, tldKsk: oldKey, tldZsk: newKey, rogueKsk } = await demoKeys();
          const rootSet = keyset(root, [rootKsk]);
          const rrset = keyset(child, [oldKey, newKey, rogueKsk]);
          const signers = signing === 'both' ? [oldKey, newKey] : [signing === 'old' ? oldKey : newKey];
          const dsData = [anchor(oldKey, child).rdata, anchor(newKey, child).rdata];
          const ds: RRset = { name: child, type: RR_TYPE.DS, class: CLASS_IN,
            ttl: 3600, rdatas: reverseDs ? dsData.reverse() : dsData };
          const sigs = await Promise.all(signers.map(k => signRrsetAs(rrset, k, { apex: child, ...window })));
          sigs.unshift(await signRrsetAs(rrset, rogueKsk, { apex: child, ...window }));
          const zones: ZoneEvidence[] = [
            { zone: root, title: 'root', dnskeys: rootSet, dnskeyRrsigs: [await signRrsetAs(rootSet, rootKsk, { apex: root, ...window })], ds: null, dsRrsigs: [] },
            { zone: child, title: 'child', dnskeys: rrset, dnskeyRrsigs: reverseSigs ? sigs.reverse() : sigs,
              ds, dsRrsigs: [await signRrsetAs(ds, rootKsk, { apex: root, ...window })] },
          ];
          const result = await validateChain({ anchors: [anchor(rootKsk)], zones, answer: null, now: DEMO_NOW });
          expect(result.status).toBe('SECURE');
          expect(signers.map(k => k.tag)).toContain(result.links[1]?.vouchedKey?.tag);
        });
      }
    }
  }
  it('rejects multiple trusted keys when no valid trusted signature exists', async () => {
    const { rootKsk, rootZsk, rogueKsk } = await demoKeys();
    const rrset = keyset(root, [rootKsk, rootZsk, rogueKsk]);
    const untrusted = await signRrsetAs(rrset, rogueKsk, { apex: root, ...window });
    const bad = await signRrsetAs(rrset, rootKsk, { apex: root, ...window });
    bad[bad.length - 1] = bad[bad.length - 1]! ^ 1;
    const result = await validateChain({ anchors: [anchor(rootKsk), anchor(rootZsk)],
      zones: [{ zone: root, title: 'root', dnskeys: rrset, dnskeyRrsigs: [untrusted, bad], ds: null, dsRrsigs: [] }],
      answer: null, now: DEMO_NOW });
    expect(result.status).toBe('BOGUS');
    expect(result.failure).toBe('KEYTAG_MISMATCH');
  });
});
