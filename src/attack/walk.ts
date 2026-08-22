/**
 * Walking an NSEC-signed zone.
 *
 * There is no cleverness here and no cryptography is broken. Each step asks
 * the server a perfectly ordinary question, the server answers with a
 * perfectly valid signed denial, and the denial names the next name that
 * exists. Reading that field is the walk.
 *
 * The question used at each step is for a type nothing in the zone has. A name
 * that exists but lacks the type produces a NODATA answer, whose proof is the
 * NSEC record sitting AT that name — and that record carries two things: the
 * next name in canonical order, and a type bit map listing everything the
 * current name does have. So one query yields both the next stop and a full
 * inventory of this one.
 *
 * The walk ends when the next name is the apex again: the chain is a ring, and
 * closing it means every name has been seen. That is a complete, signed
 * enumeration of a zone whose transfers are blocked — which is precisely the
 * property NSEC3 and online minimally covering denial were invented to remove.
 */

import { nameEquals, presentName, type Labels } from '../dns/name.ts';
import { typeName } from '../dns/types.ts';
import { interestingTypes } from '../dnssec/nsec.ts';
import type { SignedZone } from '../zone/sign.ts';
import { nextNameFrom, queryZone, typesFrom, type ZoneResponse } from '../zone/resolve.ts';

/**
 * A type number nothing in the demo zone carries.
 *
 * 64444 is inside the private-use range, so asking for it is a legal query
 * that no name can answer — which is exactly what a walker wants, because
 * every existing name then produces the NSEC record that names its successor.
 */
export const PROBE_TYPE = 64444;

export interface WalkStep {
  readonly index: number;
  /** The name asked about. */
  readonly queried: Labels;
  /** The NSEC record's owner, which is the name proved to exist. */
  readonly discovered: Labels;
  /** The next existing name, read straight out of the record. */
  readonly next: Labels;
  /** Everything the discovered name has, from the type bit map. */
  readonly types: readonly number[];
  readonly response: ZoneResponse;
  /** True once the chain has wrapped back to the apex. */
  readonly closesRing: boolean;
}

export interface WalkState {
  readonly zone: SignedZone;
  readonly steps: readonly WalkStep[];
  /** The name to query next, or null once the ring has closed. */
  readonly cursor: Labels | null;
  readonly complete: boolean;
}

export function startWalk(zone: SignedZone): WalkState {
  return { zone, steps: [], cursor: zone.spec.apex, complete: false };
}

/** Take one step: one query, one signed denial, one name learned. */
export function walkOnce(state: WalkState): WalkState {
  if (state.complete || !state.cursor) return state;
  const response = queryZone(state.zone, state.cursor, PROBE_TYPE);
  const next = nextNameFrom(response);
  const inventory = typesFrom(response);
  if (!next || !inventory) {
    // The zone declined to prove anything about this name. Stop rather than
    // guess -- a walker that invents a next name is not reading a proof.
    return { ...state, cursor: null, complete: true };
  }
  const closesRing = nameEquals(next, state.zone.spec.apex);
  const step: WalkStep = {
    index: state.steps.length,
    queried: state.cursor,
    discovered: inventory.owner,
    next,
    types: inventory.types,
    response,
    closesRing,
  };
  return {
    zone: state.zone,
    steps: [...state.steps, step],
    cursor: closesRing ? null : next,
    complete: closesRing,
  };
}

/** Run the walk to completion, bounded so a malformed chain cannot loop. */
export function walkAll(zone: SignedZone, maxSteps = 512): WalkState {
  let state = startWalk(zone);
  for (let i = 0; i < maxSteps && !state.complete; i += 1) state = walkOnce(state);
  return state;
}

/** Names learned so far, in the order the walk found them. */
export function discovered(state: WalkState): string[] {
  return state.steps.map((s) => presentName(s.discovered));
}

/** A one-line summary of what a step revealed, for the transcript. */
export function describeStep(step: WalkStep): string {
  const types = interestingTypes(step.types).map(typeName);
  return (
    `${presentName(step.discovered)} exists${types.length ? ` (${types.join(', ')})` : ''}` +
    ` — next is ${presentName(step.next)}`
  );
}
