/**
 * The offline guessing problem NSEC3 leaves behind.
 *
 * Collect a zone's NSEC3 records — every one of them is handed out on request,
 * along with the salt and iteration count needed to reproduce the hashing —
 * and the online part of the attack is over. What remains is a purely local
 * exercise: hash candidate names, compare against the hashes you collected,
 * keep the hits.
 *
 * RFC 5155 says this plainly in section 12.1.1 ("Dictionary Attacks"), and RFC
 * 9276 (BCP 236) is sharper about what the parameters do and do not buy: an
 * adversary "will likely be able to find most of the 'guessable' names despite
 * any level of additional hashing iterations", and because a name is already
 * implicitly salted by being fully qualified, the salt field is "functionally
 * useless" unless it changes mid-attack, which rebuilding the whole chain
 * makes impractical.
 *
 * So this runs the same attack twice against the same construction, and
 * REPORTS A RECOVERY RATE rather than a verdict. The variable is not the
 * cryptography — SHA-1, the salt, the iteration count are identical — it is
 * whether the names were guessable. That is the finding.
 */

import { toBase32Hex } from '../dns/codec.ts';
import { presentName, type Labels } from '../dns/name.ts';
import { nsec3Hash, type Nsec3Params } from '../dnssec/nsec3.ts';

export interface DictionaryTarget {
  /** Every hashed owner the zone published, base32hex, lowercased. */
  readonly hashes: ReadonlySet<string>;
  readonly apex: Labels;
  readonly params: Nsec3Params;
  /** The names actually in the zone, used only to score the result. */
  readonly truth: readonly string[];
}

export interface Recovery {
  readonly label: string;
  readonly name: string;
  readonly hash: string;
}

export interface DictionaryProgress {
  readonly tried: number;
  readonly total: number;
  /** Hash invocations performed, which is `tried * (iterations + 1)`. */
  readonly hashOperations: number;
  readonly recovered: readonly Recovery[];
  readonly done: boolean;
}

export interface DictionaryOutcome extends DictionaryProgress {
  /** Fraction of the zone's non-apex names this run recovered, 0..1. */
  readonly recoveryRate: number;
  /** Names in the zone the candidate list never reached. */
  readonly missed: readonly string[];
}

/**
 * Run the attack in slices, so a long run cannot freeze the page.
 *
 * A generator rather than a callback because the UI needs to render progress
 * between slices and the honest thing to show while a run is going is how far
 * it has actually got, not a spinner.
 */
export function* runDictionary(
  target: DictionaryTarget,
  candidates: readonly string[],
  sliceSize = 400
): Generator<DictionaryProgress, DictionaryOutcome, void> {
  const recovered: Recovery[] = [];
  const perCandidate = target.params.iterations + 1;
  let tried = 0;

  while (tried < candidates.length) {
    const end = Math.min(tried + sliceSize, candidates.length);
    for (; tried < end; tried += 1) {
      const label = candidates[tried]!;
      const name: Labels = [new TextEncoder().encode(label), ...target.apex];
      const hash = toBase32Hex(nsec3Hash(name, target.params)).toLowerCase();
      if (target.hashes.has(hash)) {
        recovered.push({ label, name: presentName(name), hash });
      }
    }
    yield {
      tried,
      total: candidates.length,
      hashOperations: tried * perCandidate,
      recovered: [...recovered],
      done: tried >= candidates.length,
    };
  }

  const apex = presentName(target.apex);
  const zoneNames = target.truth.filter((n) => n !== apex);
  const found = new Set(recovered.map((r) => r.name));
  const missed = zoneNames.filter((n) => !found.has(n));
  return {
    tried,
    total: candidates.length,
    hashOperations: candidates.length * perCandidate,
    recovered,
    done: true,
    recoveryRate: zoneNames.length === 0 ? 0 : (zoneNames.length - missed.length) / zoneNames.length,
    missed,
  };
}

/** Run to completion in one go. Used by the tests; the UI slices instead. */
export function runDictionaryToEnd(
  target: DictionaryTarget,
  candidates: readonly string[]
): DictionaryOutcome {
  const iterator = runDictionary(target, candidates, candidates.length);
  let step = iterator.next();
  while (!step.done) step = iterator.next();
  return step.value;
}

/**
 * What a zone hands an attacker: the hashed owner names, straight off the
 * records it publishes.
 *
 * Note what is NOT needed — no zone transfer, no privileged access, no
 * cryptographic weakness. A dozen queries for names that do not exist collects
 * the whole chain, because each denial hands back its neighbours.
 */
export function collectHashes(hashedOwnerLabels: Iterable<string>): Set<string> {
  return new Set([...hashedOwnerLabels].map((h) => h.toLowerCase()));
}
