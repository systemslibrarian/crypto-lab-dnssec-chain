/**
 * A scoped master-file reader: `dig` output and RFC example zones in,
 * `ResourceRecord`s out.
 *
 * This exists so the vectors in `src/vectors/` can be committed as the exact
 * text the source printed — `dig`'s answer sections, the example zones in RFC
 * 4034, 5155, 6605 and 8080 — rather than as hex someone transcribed by hand.
 * A transcription is a place for an error to hide; a parser is a thing that
 * can be tested.
 *
 * It handles what those sources actually use and nothing more: comments,
 * parenthesised continuations, blank owner names meaning "same as the previous
 * record", and TTL/class in either order. Origin-relative names, `$ORIGIN`,
 * `$TTL` and `$INCLUDE` are deliberately unimplemented — every name here ends
 * up inside a hash, so a name this parser had to guess at would be a name the
 * validator could authenticate wrongly.
 */

import { parseName, type Labels } from './name.ts';
import { parseRdata } from './rdata.ts';
import { CLASS_IN, typeNumber, type ResourceRecord } from './types.ts';

export class ZoneFileError extends Error {
  constructor(
    message: string,
    readonly line: string
  ) {
    super(`${message} — in: ${line.trim()}`);
    this.name = 'ZoneFileError';
  }
}

/** Strip a `;` comment, but not a `;` inside a quoted string. */
function stripComment(line: string): string {
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '\\') {
      i += 1;
      continue;
    }
    if (ch === '"') inQuotes = !inQuotes;
    else if (ch === ';' && !inQuotes) return line.slice(0, i);
  }
  return line;
}

/**
 * Fold physical lines into logical records.
 *
 * A record may be wrapped across lines inside parentheses, and the RFCs use
 * that for every base64 key and signature. RFC 5155's Appendix A even opens
 * the parenthesis AFTER the first chunk of base64, so the fold cannot assume
 * the `(` starts a line.
 */
function logicalLines(text: string): string[] {
  const out: string[] = [];
  let current = '';
  let depth = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = stripComment(raw);
    if (depth === 0 && line.trim() === '') continue;
    let inQuotes = false;
    for (let i = 0; i < line.length; i += 1) {
      const ch = line[i];
      if (ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === '"') inQuotes = !inQuotes;
      else if (!inQuotes && ch === '(') depth += 1;
      else if (!inQuotes && ch === ')') depth -= 1;
    }
    // The parentheses are pure line-continuation syntax; they carry no data.
    current += (current === '' ? '' : ' ') + line.replace(/[()]/g, ' ');
    if (depth <= 0) {
      if (current.trim() !== '') out.push(current);
      current = '';
      depth = 0;
    }
  }
  if (current.trim() !== '') out.push(current);
  return out;
}

const CLASS_NAMES: Readonly<Record<string, number>> = { IN: CLASS_IN, CH: 3, HS: 4 };

export interface ParseOptions {
  /** Used when a record omits its TTL. */
  readonly defaultTtl?: number;
}

/**
 * Parse master-file text into records.
 *
 * A leading run of whitespace means "same owner as the previous record", which
 * is how RFC example zones are printed. The first record in a file must
 * therefore name its owner.
 */
export function parseRecords(text: string, options: ParseOptions = {}): ResourceRecord[] {
  const records: ResourceRecord[] = [];
  let previousOwner: Labels | null = null;
  let previousTtl = options.defaultTtl ?? 3600;

  for (const logical of logicalLines(text)) {
    const ownerOmitted = /^[ \t]/.test(logical);
    const fields = logical.trim().split(/[ \t]+/);
    let index = 0;

    let owner: Labels;
    if (ownerOmitted) {
      if (!previousOwner) throw new ZoneFileError('record omits its owner and there is no previous one', logical);
      owner = previousOwner;
    } else {
      const token = fields[index];
      if (token === undefined) throw new ZoneFileError('empty record', logical);
      try {
        owner = parseName(token);
      } catch (error) {
        throw new ZoneFileError(`bad owner name: ${(error as Error).message}`, logical);
      }
      index += 1;
    }

    // TTL and class may appear in either order, and either may be absent.
    let ttl: number | null = null;
    let klass: number | null = null;
    for (let seen = 0; seen < 2; seen += 1) {
      const token = fields[index];
      if (token === undefined) break;
      if (/^\d+$/.test(token) && ttl === null) {
        ttl = Number(token);
        index += 1;
        continue;
      }
      const asClass = CLASS_NAMES[token.toUpperCase()];
      if (asClass !== undefined && klass === null) {
        klass = asClass;
        index += 1;
        continue;
      }
      break;
    }

    const typeToken = fields[index];
    if (typeToken === undefined) throw new ZoneFileError('record has no type', logical);
    index += 1;
    let type: number;
    try {
      type = typeNumber(typeToken);
    } catch (error) {
      throw new ZoneFileError((error as Error).message, logical);
    }

    const rdataText = fields.slice(index).join(' ');
    let rdata: Uint8Array;
    try {
      rdata = parseRdata(type, rdataText);
    } catch (error) {
      throw new ZoneFileError(`bad ${typeToken} RDATA: ${(error as Error).message}`, logical);
    }

    const effectiveTtl = ttl ?? (ownerOmitted ? previousTtl : (options.defaultTtl ?? previousTtl));
    records.push({ name: owner, type, class: klass ?? CLASS_IN, ttl: effectiveTtl, rdata });
    previousOwner = owner;
    previousTtl = effectiveTtl;
  }
  return records;
}
