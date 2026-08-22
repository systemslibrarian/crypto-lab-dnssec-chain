/**
 * Exhibit 4 — the headline mechanism, walked.
 *
 * This panel exists to SHOW one thing: an NSEC record proves a name does not
 * exist by naming the next name that does, so following those names enumerates
 * the zone. It is not asserted anywhere on this page. The learner presses a
 * button, one ordinary query goes to the in-page authoritative server, a real
 * signed denial comes back, and the next name is read out of it. Repeat until
 * the chain wraps around to the apex, at which point the whole zone is on
 * screen and the ring visibly closes.
 *
 * Nothing about it is an attack on the cryptography. Every proof along the way
 * verifies. That is the uncomfortable part, and it is the point: NSEC permits
 * traditional walking by construction, and no amount of correct implementation
 * changes that.
 */

import { presentName, type Labels } from '../../dns/name.ts';
import { presentRdata } from '../../dns/rdata.ts';
import { RR_TYPE, typeName } from '../../dns/types.ts';
import { proveNxdomain, toNsecRecord } from '../../dnssec/nsec.ts';
import { describeStep, PROBE_TYPE, startWalk, walkOnce, type WalkState } from '../../attack/walk.ts';
import { buildDemoZone, GUESSABLE_LABELS, HIGH_ENTROPY_LABELS } from '../../zone/demo.ts';
import { checkDenial } from '../../zone/resolve.ts';
import type { SignedZone } from '../../zone/sign.ts';
import { badge, button, checkList, checkRow, controlGroup, disclosure, el, list, liveRegion, para, replace } from '../dom.ts';
import { recordBlock } from '../format.ts';

const CENTER = 160;
const RADIUS = 118;

/**
 * The ring, drawn from what the walk has actually learned.
 *
 * Nodes are the names discovered so far, spread evenly around the circle in
 * the order they were found; an arc is drawn for every `next` pointer that has
 * been read out of a real record. The closing arc — the one back to the apex —
 * appears only when a record actually said so, which is what makes the closed
 * ring a result rather than a decoration.
 */
function ring(state: WalkState): SVGSVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 320 320');
  svg.setAttribute('class', 'ring');
  svg.setAttribute('role', 'img');
  const found = state.steps.length;
  svg.setAttribute(
    'aria-label',
    found === 0
      ? 'Zone ring: no names discovered yet.'
      : `Zone ring: ${found} name${found === 1 ? '' : 's'} discovered so far, ${state.complete ? 'and the chain has closed back to the zone apex' : 'the chain has not closed yet'}.`
  );

  const make = (tag: string, attrs: Record<string, string | number>): SVGElement => {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
    return node;
  };

  const count = Math.max(found, 1);
  const pos = (index: number): { x: number; y: number } => {
    const angle = (index / count) * Math.PI * 2 - Math.PI / 2;
    return { x: CENTER + RADIUS * Math.cos(angle), y: CENTER + RADIUS * Math.sin(angle) };
  };

  svg.append(
    make('circle', {
      cx: CENTER,
      cy: CENTER,
      r: RADIUS,
      class: 'ring-edge',
      'stroke-dasharray': '3 5',
    })
  );

  for (let i = 0; i < found; i += 1) {
    const isLast = i === found - 1;
    if (!isLast || state.complete) {
      const a = pos(i);
      const b = pos((i + 1) % count);
      svg.append(
        make('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: 'ring-edge ring-edge-found' })
      );
    }
  }
  for (let i = 0; i < found; i += 1) {
    const p = pos(i);
    const isCurrent = i === found - 1;
    svg.append(
      make('circle', {
        cx: p.x,
        cy: p.y,
        r: isCurrent ? 8 : 6,
        class: `ring-slot ${isCurrent ? 'ring-slot-current' : 'ring-slot-found'}`,
      })
    );
  }

  const label = make('text', {
    x: CENTER,
    y: CENTER - 4,
    class: 'ring-caption',
    'text-anchor': 'middle',
    'font-size': 15,
  });
  label.textContent = String(found);
  const sub = make('text', {
    x: CENTER,
    y: CENTER + 14,
    class: 'ring-caption',
    'text-anchor': 'middle',
  });
  sub.textContent = found === 1 ? 'name found' : 'names found';
  svg.append(label, sub);
  return svg as SVGSVGElement;
}

function walkLog(state: WalkState): HTMLElement {
  return list(
    'ul',
    'walk-log',
    'Names learned, in the order the walk found them',
    state.steps.map((step) =>
      el('li', { class: 'walk-row', role: 'listitem' }, [
        el('span', { class: 'walk-index', text: `${step.index + 1}.` }),
        el('span', { class: 'walk-name', text: presentName(step.discovered) }),
        el('span', { class: 'walk-next', text: `→ next is ${presentName(step.next)}` }),
      ])
    ),
    'No names learned yet — press “Ask one question” to send the first query.'
  );
}

function evidenceFor(zone: SignedZone, state: WalkState): HTMLElement {
  const step = state.steps[state.steps.length - 1];
  if (!step) {
    return para('Press “Ask one question” to send the first query.');
  }
  const lines = step.response.authority.flatMap((signed) =>
    signed.rrset.rdatas.map(
      (rdata) =>
        `${presentName(signed.rrset.name)} ${signed.rrset.ttl} IN ${typeName(signed.rrset.type)} ${presentRdata(signed.rrset.type, rdata)}`
    )
  );
  const proof = checkDenial(zone, step.response);
  return el('div', {}, [
    para(
      `Query ${step.index + 1} asked for ${presentName(step.queried)} type ${PROBE_TYPE}, a type nothing in this zone has. The server answered with the record that asserts the name exists — and that record carries the next one.`
    ),
    recordBlock(lines, `Authority section for query ${step.index + 1}`),
    checkList(
      (proof?.steps ?? []).map((s) => checkRow(s.passed, s.label, s.detail)),
      'Denial proof checks',
      'This answer carried no denial proof.'
    ),
    el('p', { class: 'prose' }, [
      badge(proof?.proven ? 'ok' : 'bad', proof?.proven ? 'proof valid' : 'proof invalid'),
      ` ${describeStep(step)}`,
    ]),
  ]);
}

export function renderWalkPanel(host: HTMLElement): void {
  const output = liveRegion('Zone walk progress', 'walk-out');
  const evidence = el('div', { class: 'walk-evidence' });
  let zone: SignedZone | null = null;
  let state: WalkState | null = null;
  let labels: readonly string[] = GUESSABLE_LABELS;

  const draw = (): void => {
    if (!zone || !state) return;
    const done = state.complete;
    output.dataset.found = String(state.steps.length);
    output.dataset.total = String(zone.owners.length);
    output.dataset.complete = done ? 'true' : 'false';
    replace(
      output,
      el('div', { class: 'ring-wrap reveal' }, [
        ring(state),
        el('div', {}, [
          el('p', { class: 'prose' }, [
            badge(done ? 'bad' : 'info', done ? 'zone recovered' : 'walking'),
            done
              ? ` ${state.steps.length} of ${zone.owners.length} names recovered in ${state.steps.length} ordinary queries. The chain closed back on the apex, which is the proof that nothing was missed.`
              : ` ${state.steps.length} name${state.steps.length === 1 ? '' : 's'} so far. Each one came out of a signed denial.`,
          ]),
          walkLog(state),
        ]),
      ])
    );
    replace(evidence, evidenceFor(zone, state));
  };

  const reset = async (): Promise<void> => {
    // Signing takes a moment, and every control below is inert until it
    // finishes. Say so rather than letting a press do nothing silently.
    output.dataset.complete = 'pending';
    replace(output, el('p', { class: 'prose', text: 'Signing the zone…' }));
    try {
      zone = await buildDemoZone({ labels });
    } catch (error) {
      output.dataset.complete = 'error';
      replace(
        output,
        el('div', { class: 'callout callout-danger' }, [
          el('p', { text: `Could not sign the zone: ${(error as Error).message}` }),
        ])
      );
      return;
    }
    state = startWalk(zone);
    draw();
  };

  const step = (): void => {
    if (!state) return;
    state = walkOnce(state);
    draw();
  };

  const all = (): void => {
    if (!state) return;
    for (let i = 0; i < 512 && !state.complete; i += 1) state = walkOnce(state);
    draw();
  };

  const labelButtons: HTMLButtonElement[] = [];
  const chooseLabels = (set: readonly string[], node: HTMLButtonElement): void => {
    labels = set;
    for (const other of labelButtons) {
      other.setAttribute('aria-pressed', other === node ? 'true' : 'false');
    }
    void reset();
  };
  const ordinaryBtn = button('Ordinary names', () => chooseLabels(GUESSABLE_LABELS, ordinaryBtn), {
    'aria-pressed': 'true',
  });
  const randomBtn = button('Unguessable names', () => chooseLabels(HIGH_ENTROPY_LABELS, randomBtn), {
    'aria-pressed': 'false',
  });
  labelButtons.push(ordinaryBtn, randomBtn);

  host.append(
    el('h2', { text: 'The proof that a name is absent tells you which names are present' }),
    el('p', {
      class: 'lede',
      text:
        'A signed zone cannot make up a “no” on demand, so it signs the gaps between the names it has. Ask about a name in a gap and you are handed the two names on either side of it. Do that repeatedly and the zone falls out.',
    }),

    controlGroup(
      'Walk the zone',
      button('Ask one question', () => step(), { class: 'btn btn-primary' }),
      button('Walk the whole zone', () => all()),
      button('Start over', () => void reset())
    ),
    controlGroup('Zone contents', ordinaryBtn, randomBtn),
    el('p', { class: 'prose' }, [
      badge('warn', 'unconditional'),
      ' Unguessable names are no defence here. Try the second button: the record NAMES the next owner, so a random twelve-character label is recovered exactly as easily as ',
      el('code', { text: 'www' }),
      '.',
    ]),

    output,

    el('h3', { text: 'The evidence for the last step' }),
    evidence,

    disclosure(
      'Why does this work at all? — the offline-signing constraint',
      para(
        'A zone is signed in advance, usually on a machine that is nowhere near the internet, and the private key never touches a nameserver. That is a deliberate and valuable property: compromising a nameserver does not compromise the zone’s signatures.'
      ),
      para(
        'But it means the signer must anticipate every answer, including every negative one — and there are infinitely many names that do not exist. Signing the gaps is the only finite way to cover them, and a gap is defined by its endpoints. The enumeration is not a leak bolted onto the design; it is what the design is made of.'
      ),
      para(
        'The next two tabs are the two ways out: hash the names so the walk yields hashes instead of names (which converts the problem rather than removing it), or give up offline signing and synthesize a minimal denial per query.'
      )
    ),

    forgeSection(() => zone)
  );

  void reset();
}

/**
 * A denial that does not cover what it claims to.
 *
 * The walk shows a valid proof doing something uncomfortable. This shows the
 * other half: a proof that looks the same and is rejected, so that "the
 * validator is actually checking" is a thing observed rather than assumed.
 */
function forgeSection(getZone: () => SignedZone | null): HTMLElement {
  const out = liveRegion('Forged denial result', 'walk-forge-out');
  const host = el('div', {}, [
    el('h3', { text: 'Try to forge a denial' }),
    para(
      'Take a perfectly valid NSEC record from elsewhere in the ring and offer it as proof that some other name does not exist. It is correctly signed, it is genuinely part of the zone, and it covers the wrong interval.'
    ),
    controlGroup(
      'Forge',
      button('Offer a non-covering NSEC', () => {
        const zone = getZone();
        if (!zone) return;
        const records = zone.denialRecords.filter((r) => r.rrset.type === RR_TYPE.NSEC);
        const first = records[0];
        const rdata = first?.rrset.rdatas[0];
        if (!first || !rdata) return;
        const record = toNsecRecord(first.rrset.name, rdata);
        // A name deliberately outside this record's interval.
        const target: Labels = [new TextEncoder().encode('zzzz-not-covered'), ...zone.spec.apex];
        const proof = proveNxdomain([record], target, zone.spec.apex);
        replace(
          out,
          el('div', { class: 'reveal' }, [
            recordBlock(
              [
                `${presentName(first.rrset.name)} ${first.rrset.ttl} IN NSEC ${presentRdata(RR_TYPE.NSEC, rdata)}`,
              ],
              'The record offered as proof'
            ),
            para(`Offered as proof that ${presentName(target)} does not exist.`),
            checkList(
              proof.steps.map((s) => checkRow(s.passed, s.label, s.detail)),
              'Forged denial checks'
            ),
            el('p', { class: 'prose' }, [
              badge(proof.proven ? 'bad' : 'ok', proof.proven ? 'accepted' : 'rejected'),
              proof.proven
                ? ' The forgery was accepted, which would be a bug in this validator.'
                : ' Rejected as NSEC_PROOF_INVALID. A denial is only as good as the interval it names, and this one names the wrong one.',
            ]),
          ])
        );
      })
    ),
    out,
  ]);
  return host;
}
