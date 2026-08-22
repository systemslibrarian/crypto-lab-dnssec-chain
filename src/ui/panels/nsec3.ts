/**
 * Exhibit 5 — NSEC3, run twice on the same construction.
 *
 * The claim this panel exists to test is stated in the direction that is
 * actually true: NSEC3 REPLACES TRIVIAL WALKING WITH AN OFFLINE GUESSING
 * PROBLEM. It does not eliminate enumeration, and predictable labels remain
 * recoverable despite any number of added iterations.
 *
 * So the experiment holds the cryptography fixed — same SHA-1, same salt, same
 * iteration count, same candidate list — and varies only whether the names
 * were guessable. It reports a RECOVERY RATE against a stated candidate list,
 * because a rate against an unstated list means nothing, and because "NSEC3 is
 * broken" and "NSEC3 is fine" are both wrong.
 */

import { toBase32Hex, toHex } from '../../dns/codec.ts';
import { presentName, type Labels } from '../../dns/name.ts';
import { nsec3HashTrace, type Nsec3Params } from '../../dnssec/nsec3.ts';
import { RR_TYPE } from '../../dns/types.ts';
import {
  collectHashes,
  runDictionary,
  type DictionaryOutcome,
  type DictionaryProgress,
  type DictionaryTarget,
} from '../../attack/dictionary.ts';
import { CANDIDATES } from '../../attack/wordlist.ts';
import {
  buildDemoZone,
  COMMON_LABELS,
  GUESSABLE_LABELS,
  HIGH_ENTROPY_LABELS,
  nsec3WithIterations,
  SITE_SPECIFIC_LABELS,
  ZONE,
} from '../../zone/demo.ts';
import type { SignedZone } from '../../zone/sign.ts';
import { badge, button, controlGroup, disclosure, el, list, liveRegion, para, replace } from '../dom.ts';
import { recordBlock } from '../format.ts';

const ITERATION_CHOICES = [0, 10, 50, 150];
const SALT_CHOICES: { label: string; hex: string }[] = [
  { label: 'no salt (RFC 9276)', hex: '' },
  { label: '8-byte salt', hex: 'deadbeefcafe0123' },
];

function targetFor(zone: SignedZone): DictionaryTarget {
  if (zone.spec.denial.kind !== 'nsec3') throw new Error('expected an NSEC3 zone');
  const labels = zone.denialRecords
    .filter((r) => r.rrset.type === RR_TYPE.NSEC3)
    .map((r) => new TextDecoder().decode(r.rrset.name[0] ?? new Uint8Array()));
  return {
    hashes: collectHashes(labels),
    apex: zone.spec.apex,
    params: zone.spec.denial.params,
    truth: zone.owners.map(presentName),
  };
}

function meter(fraction: number, label: string, none: boolean): HTMLElement {
  const pct = Math.round(fraction * 1000) / 10;
  return el('div', { class: 'meter' }, [
    el(
      'div',
      {
        class: 'meter-track',
        role: 'meter',
        'aria-valuenow': String(pct),
        'aria-valuemin': '0',
        'aria-valuemax': '100',
        'aria-label': label,
      },
      [el('div', { class: `meter-fill ${none ? 'meter-fill-none' : ''}`, style: `width:${pct}%` })]
    ),
    el('span', { class: 'meter-label', text: `${label}: ${pct}%` }),
  ]);
}

function chips(labelsFound: readonly string[], labelsMissed: readonly string[]): HTMLElement {
  return list(
    'ul',
    'chips',
    'Names recovered and names missed',
    [
      ...labelsFound.map((name) => el('li', { class: 'chip chip-found', role: 'listitem', text: name })),
      ...labelsMissed.map((name) => el('li', { class: 'chip chip-safe', role: 'listitem', text: name })),
    ],
    'No names in the zone.'
  );
}

/** The iterated hash, shown one round at a time. */
function hashTracePanel(params: Nsec3Params): HTMLElement {
  const name: Labels = [new TextEncoder().encode('www'), ...ZONE];
  const trace = nsec3HashTrace(name, params);
  const shown = trace.rounds.slice(0, 4);
  return el('div', {}, [
    para(
      `Hashing ${presentName(name)} with ${params.iterations} extra iteration${params.iterations === 1 ? '' : 's'} and ${params.salt.length === 0 ? 'no salt' : `a ${params.salt.length}-octet salt`}. The input is the name in wire form — length-prefixed labels, down-cased — not the text you just read.`
    ),
    recordBlock(
      [
        `input (wire form) = ${toHex(trace.input)}`,
        ...shown.map((round, i) => `IH(salt, name, ${i}) = ${toHex(round)}`),
        trace.rounds.length > shown.length ? `… ${trace.rounds.length - shown.length} more rounds …` : '',
        `owner label = ${toBase32Hex(trace.rounds[trace.rounds.length - 1] ?? new Uint8Array()).toLowerCase()}`,
      ].filter(Boolean),
      'Iterated hash trace'
    ),
    para(
      'Each round costs the attacker exactly one hash and costs the server exactly one hash. Raising the count multiplies both sides equally, which is why RFC 9276 (BCP 236) sets the recommendation at zero iterations and no salt.'
    ),
  ]);
}

export function renderNsec3Panel(host: HTMLElement): void {
  const output = liveRegion('Dictionary attack progress', 'nsec3-out');
  const traceHost = el('div', {});
  let iterations = 0;
  let saltHex = '';
  let labels: readonly string[] = GUESSABLE_LABELS;
  let running = false;

  const params = (): Nsec3Params => nsec3WithIterations(iterations, saltHex);

  const drawTrace = (): void => {
    replace(traceHost, hashTracePanel(params()));
  };

  const render = (progress: DictionaryProgress, outcome: DictionaryOutcome | null, zone: SignedZone): void => {
    const truth = zone.owners.map(presentName).filter((n) => n !== presentName(ZONE));
    const found = progress.recovered.map((r) => r.name);
    const missed = truth.filter((n) => !found.includes(n));
    const rate = truth.length === 0 ? 0 : found.length / truth.length;
    output.dataset.state = outcome ? 'complete' : 'running';
    output.dataset.rate = String(Math.round(rate * 1000) / 10);
    output.dataset.recovered = String(found.length);
    output.dataset.zonenames = String(truth.length);
    output.dataset.candidates = String(progress.total);
    output.dataset.hashops = String(progress.hashOperations);
    output.dataset.iterations = String(iterations);
    replace(
      output,
      el('div', { class: 'reveal' }, [
        el('p', { class: 'prose' }, [
          badge(outcome ? (rate > 0 ? 'bad' : 'ok') : 'info', outcome ? 'run complete' : 'running'),
          ` ${progress.tried.toLocaleString()} of ${progress.total.toLocaleString()} candidates tried, ` +
            `${progress.hashOperations.toLocaleString()} SHA-1 operations, ` +
            `${found.length} of ${truth.length} zone names recovered.`,
        ]),
        meter(rate, 'Recovery rate against this candidate list', rate === 0),
        chips(found, missed),
        outcome ? conclusion(rate, missed) : el('span', {}),
      ])
    );
  };

  const conclusion = (rate: number, missed: readonly string[]): HTMLElement => {
    if (rate === 0) {
      return el('div', { class: 'callout callout-note' }, [
        el('p', {}, [
          el('strong', { text: 'Nothing recovered — from this list. ' }),
          'Twelve random characters per label are outside a wordlist’s reach, so the offline stage finds nothing. That is a statement about the names, not about NSEC3: the hashes were still handed out, the salt and iteration count came with them, and a list that contained these labels would have recovered them instantly.',
        ]),
      ]);
    }
    return el('div', { class: 'callout callout-danger' }, [
      el('p', {}, [
        el('strong', { text: 'Most of the zone fell out. ' }),
        `The names that survived are ${missed.length === 0 ? 'none' : missed.map((m) => m.split('.')[0]).join(', ')} — the site-specific ones. Predictability decided the outcome; the hash parameters did not.`,
      ]),
      el('p', {}, [
        'RFC 5155 section 12.1.1 names this exactly: NSEC3 records "are still susceptible to dictionary attacks". RFC 9276 adds that an adversary willing to run one "will likely be able to find most of the ‘guessable’ names despite any level of additional hashing iterations".',
      ]),
    ]);
  };

  const run = async (): Promise<void> => {
    if (running) return;
    running = true;
    output.dataset.state = 'pending';
    const zone = await buildDemoZone({ labels, denial: { kind: 'nsec3', params: params() } });
    const target = targetFor(zone);
    const iterator = runDictionary(target, CANDIDATES, 250);
    const pump = (): void => {
      const next = iterator.next();
      if (next.done) {
        render(next.value, next.value, zone);
        running = false;
        return;
      }
      render(next.value, null, zone);
      requestAnimationFrame(pump);
    };
    pump();
  };

  const pressGroup = <T,>(
    values: readonly T[],
    labelFor: (value: T) => string,
    isCurrent: (value: T) => boolean,
    onPick: (value: T) => void
  ): HTMLButtonElement[] => {
    const nodes: HTMLButtonElement[] = [];
    for (const value of values) {
      const node = button(
        labelFor(value),
        () => {
          onPick(value);
          for (const other of nodes) other.setAttribute('aria-pressed', other === node ? 'true' : 'false');
          drawTrace();
          void run();
        },
        { 'aria-pressed': isCurrent(value) ? 'true' : 'false' }
      );
      nodes.push(node);
    }
    return nodes;
  };

  host.append(
    el('h2', { text: 'NSEC3 turns the walk into an offline guessing problem' }),
    el('p', {
      class: 'lede',
      text:
        'Hash every name and sort the hashes instead. The chain still hands back neighbours, but they are now 20-byte digests — so the online walk collects hashes and the work moves offline, to a list of guesses. Whether that helps depends entirely on the names.',
    }),

    el('h3', { text: 'What the hashing actually does' }),
    traceHost,

    el('h3', { text: 'Run the same attack on two zones' }),
    controlGroup(
      'Zone contents',
      ...pressGroup(
        [GUESSABLE_LABELS, HIGH_ENTROPY_LABELS] as const,
        (set) => (set === GUESSABLE_LABELS ? `Ordinary names (${COMMON_LABELS.length} common + ${SITE_SPECIFIC_LABELS.length} site-specific)` : 'Unguessable names (12 random characters each)'),
        (set) => set === labels,
        (set) => {
          labels = set;
        }
      )
    ),
    controlGroup(
      'Extra hash iterations',
      ...pressGroup(
        ITERATION_CHOICES,
        (n) => `${n}`,
        (n) => n === iterations,
        (n) => {
          iterations = n;
        }
      )
    ),
    controlGroup(
      'Salt',
      ...pressGroup(
        SALT_CHOICES,
        (choice) => choice.label,
        (choice) => choice.hex === saltHex,
        (choice) => {
          saltHex = choice.hex;
        }
      )
    ),
    el('p', { class: 'prose' }, [
      'The candidate list is ',
      el('strong', { text: `${CANDIDATES.length.toLocaleString()} labels` }),
      ' of the kind any zone contains — it is committed in the repository and contains nothing derived from the target zone. Every rate below is a rate against that list.',
    ]),
    output,

    disclosure(
      'Why iterations and salt do not change the answer',
      para(
        'Iterations multiply the attacker’s cost per candidate by exactly the factor they multiply the server’s cost per query. There is no asymmetry to exploit: a defender paying 150× for every ordinary answer has made a guessing attack 150× more expensive and has not made any name less guessable. Try it above — the recovered set is identical at 0 and at 150.'
      ),
      para(
        'The salt is subtler. It defeats a rainbow table computed in ADVANCE — but a fully qualified name is already implicitly salted by the zone it sits in, so no cross-zone table works anyway, and the salt is published in the same records that carry the hashes. RFC 9276 concludes that re-salting often enough to matter would mean rebuilding the whole NSEC3 chain, which "renders the additional salt field functionally useless".'
      ),
      para(
        'What does change the answer is the namespace. That is the variable this panel lets you move, and it is the only one that moved the result.'
      )
    ),

    disclosure(
      'The honest summary, stated in the direction that is true',
      el('div', { class: 'callout callout-warn' }, [
        el('p', {}, [
          el('strong', { text: 'NSEC3 replaces trivial walking with an offline guessing problem. ' }),
          'Predictable labels remain recoverable despite added iterations; sufficiently unpredictable labels do not. It is not a fix for enumeration and it was never claimed to be one — RFC 5155 says so in its own security considerations.',
        ]),
        el('p', {}, [
          'Said the other way round it becomes false, and that is the version most people carry around: it leads operators to publish internal hostnames in a signed zone believing the hashing conceals them. It does not conceal them; it prices them.',
        ]),
      ])
    )
  );

  drawTrace();
  void run();
}
