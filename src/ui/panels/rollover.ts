/**
 * Exhibit 7 — replacing a key without going dark.
 *
 * Rollover is where DNSSEC's operational failures actually live. The maths is
 * never the problem; the problem is that resolvers cache, so at any instant
 * different resolvers hold different generations of the same zone, and a
 * change that is atomic at the server is not atomic on the internet.
 *
 * The two standard shapes (RFC 6781 sections 4.1.1 and 4.1.2) exist to make
 * every intermediate state validate for every resolver, whichever generation
 * it happens to be holding. Each one is signed and validated here so the
 * "every state works" claim is watched rather than read.
 */

import { parseName, presentName } from '../../dns/name.ts';
import { algorithmName, RR_TYPE } from '../../dns/types.ts';
import { decodeRrsig } from '../../dns/rdata.ts';
import { buildHierarchy, DEMO_NOW } from '../../zone/demo.ts';
import { resolveInDemo } from '../../zone/resolve.ts';
import { describeKeys } from '../../dnssec/keytag.ts';
import { renderChain } from '../chainview.ts';
import { badge, button, controlGroup, disclosure, el, list, liveRegion, para, replace } from '../dom.ts';
import { recordBlock } from '../format.ts';

type Stage = 'none' | 'pre-publish' | 'double-signature' | 'complete';

interface StageSpec {
  readonly id: Stage;
  readonly label: string;
  readonly note: string;
}

const STAGES: readonly StageSpec[] = [
  {
    id: 'none',
    label: 'Before',
    note: 'One zone-signing key. Every RRset carries exactly one signature.',
  },
  {
    id: 'pre-publish',
    label: 'Pre-publish',
    note:
      'The successor key is added to the DNSKEY set but signs nothing yet. Nothing about the answers changes — the point is to get the new key into every resolver’s cache BEFORE it is needed, so that when it starts signing, no resolver is holding a key set that lacks it.',
  },
  {
    id: 'double-signature',
    label: 'Double-signature',
    note:
      'Both keys sign everything, so an answer validates under either generation. This costs twice the signatures and twice the response size, and it is the shape usually used for the key-signing key, where the parent’s DS has to change too.',
  },
  {
    id: 'complete',
    label: 'After',
    note: 'The old key is gone and the successor signs alone. The roll is finished.',
  },
];

async function renderStage(spec: StageSpec): Promise<HTMLElement> {
  const hierarchy = await buildHierarchy({ rollover: spec.id });
  const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, {
    now: DEMO_NOW,
  });
  const dnskeys = describeKeys(hierarchy.zone.dnskey.rrset.rdatas);
  const answer = hierarchy.zone.signed.get('www.demo.example.|1|1');
  const signers = (answer?.rrsigs ?? []).map((rdata) => decodeRrsig(rdata).keyTag);

  return el('div', {
    class: 'reveal',
    'data-stage': spec.id,
    'data-status': resolution.result.status,
    'data-keys': String(dnskeys.length),
    'data-signatures': String(signers.length),
  }, [
    para(spec.note),
    el('h4', { text: 'What the zone publishes' }),
    list(
      'ul',
      'chips',
      'Keys in the DNSKEY RRset',
      dnskeys.map((key) =>
        el('li', { class: 'chip', role: 'listitem' }, [
          `${key.isSep ? 'KSK' : 'ZSK'} tag ${key.tag} · ${algorithmName(key.algorithm)}` +
            (signers.includes(key.tag) ? ' · signing' : key.isSep ? ' · signs the key set' : ' · published, not signing'),
        ])
      ),
      'This zone publishes no keys.'
    ),
    el('h4', { text: 'What signs one answer' }),
    recordBlock(
      [
        `${presentName(answer?.rrset.name ?? [])} has ${signers.length} signature${signers.length === 1 ? '' : 's'}`,
        ...signers.map((tag) => `  RRSIG by key tag ${tag}`),
      ],
      'Signatures over the answer RRset'
    ),
    renderChain(resolution.result, DEMO_NOW),
  ]);
}

/**
 * The failure the brief singles out: a resolver's cached DS outliving the key
 * it points at.
 *
 * The parent still vouches for the old key-signing key, because that is what
 * the resolver has in its cache; the child has already rolled to a new one.
 * Both sides are internally consistent and correctly signed, and the
 * delegation is broken until the cached DS expires. This is the same mechanism
 * as the "signs with a key nobody vouched for" break — the difference is only
 * that here nobody did anything wrong except get the timing wrong.
 */
async function renderCachedDs(): Promise<HTMLElement> {
  const hierarchy = await buildHierarchy({ rogueKsk: true });
  const resolution = await resolveInDemo(hierarchy, parseName('www.demo.example.'), RR_TYPE.A, {
    now: DEMO_NOW,
  });
  return el('div', {
    class: 'reveal',
    'data-status': resolution.result.status,
    'data-failure': resolution.result.failure ?? 'none',
  }, [
    para(
      'The child rolled its key-signing key and the parent’s DS has not caught up — or, identically from the resolver’s point of view, it has caught up and this resolver is still holding the old DS in cache. The zone is correctly signed. The delegation still fails.'
    ),
    renderChain(resolution.result, DEMO_NOW),
    el('div', { class: 'callout callout-danger' }, [
      el('p', {}, [
        el('strong', { text: 'Why this is the classic outage. ' }),
        'The DS lives at the parent, which usually means a registrar’s web form and a TTL measured in days. A zone operator can roll a zone-signing key alone, on their own schedule — that is what the two shapes above are for. Rolling the KEY-SIGNING key means a change at the parent, and the window between "the child stopped using the old key" and "every cache has dropped the old DS" is exactly how long the domain is dark.',
      ]),
      el('p', {}, [
        'The rule that follows: never remove a key until every DS pointing at it has aged out of every cache. RFC 6781 sections 4.1.1 and 4.1.2 exist to make that waiting period safe rather than optional.',
      ]),
    ]),
  ]);
}

export function renderRolloverPanel(host: HTMLElement): void {
  const output = liveRegion('Rollover stage', 'rollover-out');
  const buttons: HTMLButtonElement[] = [];
  let current: StageSpec = STAGES[0]!;

  const run = async (): Promise<void> => {
    output.dataset.stage = 'pending';
    replace(output, para('Signing…'));
    const view = await renderStage(current);
    output.dataset.stage = view.dataset.stage ?? current.id;
    output.dataset.status = view.dataset.status ?? 'unknown';
    output.dataset.keys = view.dataset.keys ?? '0';
    output.dataset.signatures = view.dataset.signatures ?? '0';
    replace(output, view);
  };

  for (const spec of STAGES) {
    const node = button(
      spec.label,
      () => {
        current = spec;
        for (const other of buttons) other.setAttribute('aria-pressed', other === node ? 'true' : 'false');
        void run();
      },
      { 'aria-pressed': spec.id === current.id ? 'true' : 'false' }
    );
    buttons.push(node);
  }

  const failureOut = liveRegion('Cached DS failure', 'rollover-failure-out');

  host.append(
    el('h2', { text: 'Replacing a key without going dark' }),
    el('p', {
      class: 'lede',
      text:
        'Resolvers cache. At any moment, different resolvers hold different generations of the same zone — so a key change has to be arranged so that every generation still validates. Step through the stages and watch every one of them stay SECURE.',
    }),
    controlGroup('Rollover stage', ...buttons),
    output,

    el('h3', { text: 'And the failure that is actually common' }),
    controlGroup('Break it', button('A cached DS outlives its key', () => {
        failureOut.dataset.status = 'pending';
      void renderCachedDs().then((view) => {
        failureOut.dataset.status = view.dataset.status ?? 'unknown';
        failureOut.dataset.failure = view.dataset.failure ?? 'none';
        replace(failureOut, view);
      });
    })),
    failureOut,

    disclosure(
      'Why there are two keys in the first place',
      para(
        'Nothing in DNSSEC requires a zone to have two keys. Zones do it because the two jobs have different costs. The key-signing key is the one the parent’s DS points at, so replacing it means a change at the parent and a wait for caches — expensive and slow. The zone-signing key signs the actual records, so replacing it is entirely internal.'
      ),
      para(
        'Splitting them lets the frequently-rotated key be the cheap one. It also lets the expensive key be larger and kept further offline, since it signs one small RRset a few times a year rather than everything.'
      ),
      el('p', { class: 'prose' }, [
        badge('info', 'in this lab'),
        ' the child zone’s key-signing key is Ed25519 (algorithm 15) and its zone-signing key is ECDSA P-256 (algorithm 13), which is legal and occasionally done — the DS points at one algorithm, the answers are signed with another, and a validator has to handle both.',
      ])
    )
  );

  void run();
}
