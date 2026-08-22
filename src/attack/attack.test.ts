/**
 * The two enumeration acts, measured.
 *
 * The NSEC walk is unconditional: it recovers the whole zone every time,
 * because the construction hands out the next name. The NSEC3 dictionary
 * attack is conditional: it recovers what the candidate list can reach, which
 * for ordinary labels is most of the zone and for high-entropy labels is
 * nothing. Both results are computed, not asserted — the tests below pin the
 * numbers the page reports.
 */

import { describe, expect, it } from 'vitest';

import { presentName } from '../dns/name.ts';
import { RR_TYPE } from '../dns/types.ts';
import {
  buildDemoZone,
  COMMON_LABELS,
  GUESSABLE_LABELS,
  HIGH_ENTROPY_LABELS,
  SITE_SPECIFIC_LABELS,
  nsec3WithIterations,
  RECOMMENDED_NSEC3,
  ZONE,
} from '../zone/demo.ts';
import type { SignedZone } from '../zone/sign.ts';
import { checkDenial, queryZone } from '../zone/resolve.ts';
import { collectHashes, runDictionaryToEnd, type DictionaryTarget } from './dictionary.ts';
import { CANDIDATES } from './wordlist.ts';
import { discovered, PROBE_TYPE, walkAll, walkOnce, startWalk } from './walk.ts';

describe('NSEC zone walking — unconditional', () => {
  it('recovers every name in the zone', async () => {
    const zone = await buildDemoZone();
    const state = walkAll(zone);
    expect(state.complete).toBe(true);
    const names = new Set(discovered(state));
    for (const label of GUESSABLE_LABELS) {
      expect(names, label).toContain(`${label}.demo.example.`);
    }
    expect(names).toContain('demo.example.');
    expect(names.size).toBe(zone.owners.length);
  });

  it('finishes in one query per name, and closes the ring', async () => {
    const zone = await buildDemoZone();
    const state = walkAll(zone);
    expect(state.steps).toHaveLength(zone.owners.length);
    expect(state.steps[state.steps.length - 1]?.closesRing).toBe(true);
  });

  it('learns each name from a signed proof, not from the zone file', async () => {
    // Every step's evidence is an answer the server produced, and every one of
    // those answers verifies. The walk is not an attack on the cryptography;
    // it is the cryptography working.
    const zone = await buildDemoZone();
    let state = startWalk(zone);
    for (let i = 0; i < 5; i += 1) {
      state = walkOnce(state);
      const step = state.steps[state.steps.length - 1];
      expect(step).toBeDefined();
      expect(checkDenial(zone, step!.response)?.proven).toBe(true);
    }
  });

  it('recovers the high-entropy zone just as completely', async () => {
    // Unguessable names are no defence against NSEC: the record NAMES them.
    const zone = await buildDemoZone({ labels: HIGH_ENTROPY_LABELS });
    const state = walkAll(zone);
    const names = new Set(discovered(state));
    for (const label of HIGH_ENTROPY_LABELS) {
      expect(names, label).toContain(`${label}.demo.example.`);
    }
  });

  it('the probe type really is absent, so every step gets a denial', async () => {
    const zone = await buildDemoZone();
    const response = queryZone(zone, ZONE, PROBE_TYPE);
    expect(response.answer).toBeNull();
    expect(response.denialKind).toBe('nodata');
  });

  it('walks a zone whose transfers would be refused — there is nothing to refuse', async () => {
    const zone = await buildDemoZone();
    const state = walkAll(zone);
    // The walker only ever issued ordinary queries for a type nothing has.
    expect(state.steps.every((s) => s.response.qtype === PROBE_TYPE)).toBe(true);
  });
});

const targetFor = (zone: SignedZone): DictionaryTarget => {
  if (zone.spec.denial.kind !== 'nsec3') throw new Error('expected an NSEC3 zone');
  // The attacker sees only what the zone published: hashed owner labels.
  const labels = zone.denialRecords
    .filter((r) => r.rrset.type === RR_TYPE.NSEC3)
    .map((r) => {
      const first = r.rrset.name[0];
      if (!first) throw new Error('NSEC3 owner has no labels');
      return new TextDecoder().decode(first);
    });
  return {
    hashes: collectHashes(labels),
    apex: zone.spec.apex,
    params: zone.spec.denial.params,
    truth: zone.owners.map(presentName),
  };
};

describe('NSEC3 offline dictionary — conditional', () => {
  it('recovers most of a zone of ordinary labels', async () => {
    const zone = await buildDemoZone({
      labels: GUESSABLE_LABELS,
      denial: { kind: 'nsec3', params: RECOMMENDED_NSEC3 },
    });
    const outcome = runDictionaryToEnd(targetFor(zone), CANDIDATES);
    expect(outcome.recoveryRate).toBeGreaterThan(0.7);
    expect(outcome.recoveryRate).toBeLessThan(1);
    // The names that survive are exactly the site-specific ones. That is the
    // finding, and it is sharper than the percentage: predictability, not key
    // length or iteration count, is what decided which names stayed hidden.
    expect([...outcome.missed].sort()).toEqual(
      SITE_SPECIFIC_LABELS.map((l) => `${l}.demo.example.`).sort()
    );
    for (const label of COMMON_LABELS) {
      expect(outcome.recovered.map((r) => r.label)).toContain(label);
    }
  });

  it('recovers nothing from the same zone with high-entropy labels', async () => {
    const zone = await buildDemoZone({
      labels: HIGH_ENTROPY_LABELS,
      denial: { kind: 'nsec3', params: RECOMMENDED_NSEC3 },
    });
    const outcome = runDictionaryToEnd(targetFor(zone), CANDIDATES);
    expect(outcome.recoveryRate).toBe(0);
    expect(outcome.recovered).toHaveLength(0);
  });

  it('adding iterations changes the COST and not the outcome', async () => {
    // RFC 9276's claim, run as an experiment rather than quoted: the same
    // candidate list against the same names, with 150 extra iterations, finds
    // exactly the same names for 151 times the work.
    const cheap = await buildDemoZone({
      labels: GUESSABLE_LABELS,
      denial: { kind: 'nsec3', params: nsec3WithIterations(0, '') },
    });
    const expensive = await buildDemoZone({
      labels: GUESSABLE_LABELS,
      denial: { kind: 'nsec3', params: nsec3WithIterations(150, '') },
    });
    const a = runDictionaryToEnd(targetFor(cheap), CANDIDATES);
    const b = runDictionaryToEnd(targetFor(expensive), CANDIDATES);
    expect(b.recoveryRate).toBe(a.recoveryRate);
    expect(b.recovered.map((r) => r.label).sort()).toEqual(a.recovered.map((r) => r.label).sort());
    expect(b.hashOperations).toBe(a.hashOperations * 151);
  });

  it('adding a salt changes the COST and not the outcome either', async () => {
    const unsalted = await buildDemoZone({
      labels: GUESSABLE_LABELS,
      denial: { kind: 'nsec3', params: nsec3WithIterations(0, '') },
    });
    const salted = await buildDemoZone({
      labels: GUESSABLE_LABELS,
      denial: { kind: 'nsec3', params: nsec3WithIterations(0, 'deadbeefcafe0123') },
    });
    const a = runDictionaryToEnd(targetFor(unsalted), CANDIDATES);
    const b = runDictionaryToEnd(targetFor(salted), CANDIDATES);
    // The salt defeats a dictionary computed in ADVANCE. It does nothing at all
    // against one computed after the salt is published -- and the salt arrives
    // in the same response as the hashes.
    expect(b.recoveryRate).toBe(a.recoveryRate);
  });

  it('reports a rate against a stated candidate list, not a verdict', async () => {
    const zone = await buildDemoZone({
      labels: GUESSABLE_LABELS,
      denial: { kind: 'nsec3', params: RECOMMENDED_NSEC3 },
    });
    const outcome = runDictionaryToEnd(targetFor(zone), CANDIDATES);
    expect(outcome.total).toBe(CANDIDATES.length);
    expect(outcome.recoveryRate).toBeGreaterThan(0);
    expect(outcome.recoveryRate).toBeLessThanOrEqual(1);
    // Every recovered name must actually be in the zone -- a "recovery" that
    // is not a real name would be a false positive, and the rate would lie.
    const real = new Set(zone.owners.map(presentName));
    for (const hit of outcome.recovered) expect(real).toContain(hit.name);
  });

  it('does not need a zone transfer: the hashes come from ordinary denials', async () => {
    const zone = await buildDemoZone({
      labels: GUESSABLE_LABELS,
      denial: { kind: 'nsec3', params: RECOMMENDED_NSEC3 },
    });
    // Collect hashes the way an outsider does -- ask for names that do not
    // exist and keep the NSEC3 records that come back.
    const seen = new Set<string>();
    for (let i = 0; i < 200 && seen.size < zone.owners.length; i += 1) {
      const probe = queryZone(
        zone,
        [new TextEncoder().encode(`probe-${i}`), ...ZONE],
        RR_TYPE.A
      );
      for (const record of probe.authority) {
        if (record.rrset.type !== RR_TYPE.NSEC3) continue;
        const first = record.rrset.name[0];
        if (first) seen.add(new TextDecoder().decode(first));
      }
    }
    // A handful of queries is enough to reach most of the ring; the point is
    // that no privileged access was involved at any stage.
    expect(seen.size).toBeGreaterThan(3);
    const outcome = runDictionaryToEnd(
      { ...targetFor(zone), hashes: collectHashes(seen) },
      CANDIDATES
    );
    expect(outcome.recovered.length).toBeGreaterThan(0);
  });
});

describe('the candidate list', () => {
  it('is large enough to be a real attempt and small enough to state', () => {
    expect(CANDIDATES.length).toBeGreaterThan(1000);
    expect(new Set(CANDIDATES).size).toBe(CANDIDATES.length);
  });
});
