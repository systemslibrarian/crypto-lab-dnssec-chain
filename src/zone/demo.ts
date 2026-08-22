/**
 * The in-page hierarchy: a root, a top-level zone, and a signed child, all
 * signed here with real keys.
 *
 * The pinned capture shows a real chain that cannot be altered. This one can:
 * it exists so a learner can move a byte, re-sign, and watch a genuine
 * validator produce a genuine, specifically-named failure. Both are real
 * cryptography; they answer different questions.
 *
 * `example.` is RFC 2606's reserved top-level name, so nothing built here can
 * collide with a real delegation.
 */

import { parseName, presentName, type Labels } from '../dns/name.ts';
import { parseRdata } from '../dns/rdata.ts';
import { CLASS_IN, DIGEST_TYPE, RR_TYPE, type ResourceRecord } from '../dns/types.ts';
import { importPinnedEcdsaKey, importPinnedEd25519Key } from '../dnssec/crypto.ts';
import type { Nsec3Params } from '../dnssec/nsec3.ts';
import { DEMO_EC_KEYS, DEMO_ED_SEEDS } from '../vectors/demo-keys.ts';
import { fromHex } from '../dns/codec.ts';
import { dsForZone, keyRole, signZone, type DenialStyle, type KeyRole, type SignedZone } from './sign.ts';

export const ROOT: Labels = parseName('.');
export const TLD: Labels = parseName('example.');
export const ZONE: Labels = parseName('demo.example.');
export const UNSIGNED_CHILD: Labels = parseName('unsigned.example.');

/**
 * A validity window fixed in absolute terms, so the demo zone's signatures do
 * not silently become the "expired" case the moment a build is a month old —
 * and so the clock control has a known window to move around.
 */
export const DEMO_INCEPTION = Date.UTC(2026, 0, 1) / 1000;
export const DEMO_EXPIRATION = Date.UTC(2027, 0, 1) / 1000;
export const DEMO_NOW = Date.UTC(2026, 5, 1) / 1000;

/**
 * Site-specific labels a generic wordlist does not carry.
 *
 * Real zones are mostly predictable names plus a handful of local ones, and
 * this is that handful. They are kept separate so the act can say WHICH names
 * survived rather than only how many — the survivors are always the ones
 * nobody outside the organisation would think to type.
 */
export const SITE_SPECIFIC_LABELS: readonly string[] = [
  'hr-portal-eu',
  'bugtracker7',
  'acme-billing',
  'lab-fixture-42',
];

/**
 * Ordinary, guessable labels — the shape of a real corporate zone.
 *
 * Every one of these is in `src/attack/wordlist.ts`, and that is not a rigged
 * result: they are in the wordlist because they are in every zone.
 */
export const COMMON_LABELS: readonly string[] = [
  'www',
  'mail',
  'ns1',
  'ns2',
  'vpn',
  'dev',
  'staging',
  'api',
  'admin',
  'git',
  'wiki',
  'blog',
  'shop',
  'test',
  'db',
  'smtp',
  'backup',
  'portal',
  'intranet',
  'jira',
];

/**
 * The zone the NSEC3 act attacks: mostly predictable, with a few local names.
 *
 * A zone made entirely of dictionary words would recover at 100% and look
 * rigged; a real one does not. The mix is the honest case, and it makes the
 * result say something a bare percentage cannot — the names that survive are
 * exactly the ones a stranger could not have guessed.
 */
export const GUESSABLE_LABELS: readonly string[] = [...COMMON_LABELS, ...SITE_SPECIFIC_LABELS];

/**
 * Twelve random characters each, drawn once from a CSPRNG and pinned.
 *
 * Not a defence anyone should deploy — nobody types `omhx7ttg06c2.example.com`
 * — but it is the honest other end of the experiment: the same zone, the same
 * NSEC3 parameters, the same wordlist, and a namespace the wordlist cannot
 * reach.
 */
export const HIGH_ENTROPY_LABELS: readonly string[] = [
  'omhx7ttg06c2',
  'v8zuayci43c9',
  'y57d3y02vmmn',
  'k6oyc8lv59gz',
  'focn27ckihbl',
  '81wgsz25kyoj',
  'umx97lyvcbbe',
  '9z3ju1d333g7',
  'khc6rlxs2vx3',
  '3n7yyp7dofuc',
  'b8ff1yf2zev7',
  'ait5z9zccoxm',
  'wceszbl59dsx',
  'prenrgxakjpw',
  't7707xn3lqud',
  'wmd7mfj8xzi5',
  '9z4c46qgdzee',
  '0k1euzlr1ve8',
  'qoaze4a3szxb',
  'of09dnctih01',
  'vaa96wuu5w57',
  'w6j94i6ntw5u',
  'ywwlvdxge80i',
  'ohrooxkemzcb',
];

/** RFC 9276's recommended NSEC3 parameters: SHA-1, no extra iterations, no salt. */
export const RECOMMENDED_NSEC3: Nsec3Params = {
  hashAlgorithm: 1,
  iterations: 0,
  salt: new Uint8Array(0),
};

export function nsec3WithIterations(iterations: number, saltHex: string): Nsec3Params {
  return { hashAlgorithm: 1, iterations, salt: saltHex === '' ? new Uint8Array(0) : fromHex(saltHex) };
}

let cachedKeys: DemoKeys | null = null;

export interface DemoKeys {
  readonly rootKsk: KeyRole;
  readonly rootZsk: KeyRole;
  readonly tldKsk: KeyRole;
  readonly tldZsk: KeyRole;
  readonly zoneKsk: KeyRole;
  readonly zoneZsk: KeyRole;
  readonly zoneZskNext: KeyRole;
  readonly rogueKsk: KeyRole;
  readonly rogueZsk: KeyRole;
}

/** Import the pinned keys once; every act reuses them. */
export async function demoKeys(): Promise<DemoKeys> {
  if (cachedKeys) return cachedKeys;
  const ec = async (jwk: JsonWebKey, sep: boolean): Promise<KeyRole> =>
    keyRole(await importPinnedEcdsaKey(jwk), sep);
  const ed = (hex: string, sep: boolean): KeyRole => keyRole(importPinnedEd25519Key(fromHex(hex)), sep);

  cachedKeys = {
    rootKsk: await ec(DEMO_EC_KEYS.rootKsk, true),
    rootZsk: await ec(DEMO_EC_KEYS.rootZsk, false),
    tldKsk: await ec(DEMO_EC_KEYS.tldKsk, true),
    tldZsk: await ec(DEMO_EC_KEYS.tldZsk, false),
    // The child's KSK is Ed25519 (algorithm 15) and its ZSK is ECDSA P-256
    // (algorithm 13), so the demo chain exercises both of the algorithms this
    // brief names, in the roles a zone actually uses them in.
    zoneKsk: ed(DEMO_ED_SEEDS.zoneKsk, true),
    zoneZsk: await ec(DEMO_EC_KEYS.zoneZsk, false),
    zoneZskNext: await ec(DEMO_EC_KEYS.zoneZskNext, false),
    rogueKsk: await ec(DEMO_EC_KEYS.rogueKsk, true),
    rogueZsk: ed(DEMO_ED_SEEDS.rogueZsk, false),
  };
  return cachedKeys;
}

function record(name: Labels, type: number, rdataText: string, ttl = 3600): ResourceRecord {
  return { name, type, class: CLASS_IN, ttl, rdata: parseRdata(type, rdataText) };
}

function addressFor(index: number): string {
  // 203.0.113.0/24 is TEST-NET-3 (RFC 5737): documentation addresses that can
  // never route anywhere, so no record here can point at a real host.
  return `203.0.113.${(index % 254) + 1}`;
}

export interface DemoZoneOptions {
  readonly labels?: readonly string[];
  readonly denial?: DenialStyle;
  readonly inception?: number;
  readonly expiration?: number;
  /** Roll the ZSK: sign with both, or pre-publish the successor unused. */
  readonly rollover?: 'none' | 'pre-publish' | 'double-signature' | 'complete';
}

/** Build and sign `demo.example.`. */
export async function buildDemoZone(options: DemoZoneOptions = {}): Promise<SignedZone> {
  const keys = await demoKeys();
  const labels = options.labels ?? GUESSABLE_LABELS;
  const records: ResourceRecord[] = [
    record(ZONE, RR_TYPE.SOA, 'ns1.demo.example. hostmaster.demo.example. 2026060101 7200 3600 1209600 3600'),
    record(ZONE, RR_TYPE.NS, 'ns1.demo.example.'),
    record(ZONE, RR_TYPE.NS, 'ns2.demo.example.'),
    record(ZONE, RR_TYPE.MX, '10 mail.demo.example.'),
    record(ZONE, RR_TYPE.TXT, '"a teaching zone — every address here is RFC 5737 documentation space"'),
  ];
  labels.forEach((label, index) => {
    records.push(record([new TextEncoder().encode(label), ...ZONE], RR_TYPE.A, addressFor(index)));
  });

  const rollover = options.rollover ?? 'none';
  const zsks: KeyRole[] =
    rollover === 'double-signature'
      ? [keys.zoneZsk, keys.zoneZskNext]
      : rollover === 'complete'
        ? [keys.zoneZskNext]
        : [keys.zoneZsk];
  const publishedOnly = rollover === 'pre-publish' ? [keys.zoneZskNext] : [];

  return signZone({
    apex: ZONE,
    title: 'demo.example.',
    ksk: keys.zoneKsk,
    zsks,
    publishedOnly,
    ttl: 3600,
    inception: options.inception ?? DEMO_INCEPTION,
    expiration: options.expiration ?? DEMO_EXPIRATION,
    denial: options.denial ?? { kind: 'nsec' },
    records,
  });
}

export interface DemoHierarchy {
  readonly root: SignedZone;
  readonly tld: SignedZone;
  readonly zone: SignedZone;
  /** The DS the root publishes for `example.`, and `example.` for the child. */
  readonly tldDs: Uint8Array;
  readonly zoneDs: Uint8Array;
  readonly anchorDs: Uint8Array;
  readonly keys: DemoKeys;
}

export interface HierarchyOptions extends DemoZoneOptions {
  /** Publish a DS at the parent that does not match the child's KSK. */
  readonly corruptDs?: boolean;
  /** Publish a DS whose key tag names a key the child does not have. */
  readonly wrongKeyTag?: boolean;
  /** Publish a DS for an algorithm this validator does not implement. */
  readonly unsupportedAlgorithm?: boolean;
  /** Sign the child's DNSKEY RRset with a key nobody vouched for. */
  readonly rogueKsk?: boolean;
  /** Delegate to the child with NO DS at all — the INSECURE case. */
  readonly noDs?: boolean;
}

/**
 * Build the whole hierarchy, with whichever break the learner asked for.
 *
 * The breaks are applied by CHANGING WHAT A ZONE PUBLISHES AND RE-SIGNING IT,
 * never by corrupting bytes after the fact. That distinction is the whole
 * teaching value: a re-signed wrong DS is `DS_MISMATCH`, a corrupted one is
 * just a broken signature, and a learner who only ever sees the second never
 * learns that DNSSEC can tell them apart.
 */
export async function buildHierarchy(options: HierarchyOptions = {}): Promise<DemoHierarchy> {
  const keys = await demoKeys();
  // The honest zone is built first and ALWAYS supplies the DS. That ordering
  // is what makes the `rogueKsk` act mean something: the parent keeps vouching
  // for the key it was given, and the child starts signing its DNSKEY RRset
  // with a different one -- which is exactly the shape of a key substituted
  // downstream of a delegation nobody re-checked.
  const zone = await buildDemoZone(options);
  const zoneDs = buildDs(zone, options);

  const effectiveZone = options.rogueKsk
    ? await signZone({ ...zone.spec, ksk: keys.rogueKsk })
    : zone;

  const tldRecords: ResourceRecord[] = [
    record(TLD, RR_TYPE.SOA, 'ns1.example. hostmaster.example. 2026060101 7200 3600 1209600 3600'),
    record(TLD, RR_TYPE.NS, 'ns1.example.'),
    record(ZONE, RR_TYPE.NS, 'ns1.demo.example.'),
    record(UNSIGNED_CHILD, RR_TYPE.NS, 'ns1.unsigned.example.'),
  ];
  if (!options.noDs) {
    tldRecords.push({ name: ZONE, type: RR_TYPE.DS, class: CLASS_IN, ttl: 3600, rdata: zoneDs });
  }
  const tld = await signZone({
    apex: TLD,
    title: 'example.',
    ksk: keys.tldKsk,
    zsks: [keys.tldZsk],
    ttl: 3600,
    inception: options.inception ?? DEMO_INCEPTION,
    expiration: options.expiration ?? DEMO_EXPIRATION,
    denial: { kind: 'nsec' },
    records: tldRecords,
  });

  const tldDs = dsForZone(tld, DIGEST_TYPE.SHA256);
  const root = await signZone({
    apex: ROOT,
    title: 'root zone',
    ksk: keys.rootKsk,
    zsks: [keys.rootZsk],
    ttl: 3600,
    inception: options.inception ?? DEMO_INCEPTION,
    expiration: options.expiration ?? DEMO_EXPIRATION,
    denial: { kind: 'nsec' },
    records: [
      record(ROOT, RR_TYPE.SOA, 'a.root.example. hostmaster.root.example. 2026060101 7200 3600 1209600 3600'),
      record(ROOT, RR_TYPE.NS, 'a.root.example.'),
      record(TLD, RR_TYPE.NS, 'ns1.example.'),
      { name: TLD, type: RR_TYPE.DS, class: CLASS_IN, ttl: 3600, rdata: tldDs },
    ],
  });

  return {
    root,
    tld,
    zone: effectiveZone,
    tldDs,
    zoneDs,
    anchorDs: dsForZone(root, DIGEST_TYPE.SHA256),
    keys,
  };
}

function buildDs(zone: SignedZone, options: HierarchyOptions): Uint8Array {
  const honest = dsForZone(zone, DIGEST_TYPE.SHA256);
  if (options.corruptDs) {
    // A digest that is signed by the parent and simply wrong — the shape a
    // real DS takes after a key roll the registrar was never told about.
    const copy = Uint8Array.from(honest);
    const last = copy[copy.length - 1];
    if (last !== undefined) copy[copy.length - 1] = last ^ 0x5a;
    return copy;
  }
  if (options.wrongKeyTag) {
    const copy = Uint8Array.from(honest);
    const high = copy[0];
    if (high !== undefined) copy[0] = (high + 1) & 0xff;
    return copy;
  }
  if (options.unsupportedAlgorithm) {
    // Algorithm 16 (Ed448) is real and unimplemented here. The digest still
    // matches nothing, but the algorithm is what a validator notices first.
    const copy = Uint8Array.from(honest);
    copy[2] = 16;
    return copy;
  }
  return honest;
}

/** Every name the demo zone contains, in the order the walk will find them. */
export function zoneNames(zone: SignedZone): string[] {
  return zone.owners.map(presentName);
}
