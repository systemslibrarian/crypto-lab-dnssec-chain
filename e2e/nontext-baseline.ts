/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * IT IS EMPTY, AND THAT IS THE POINT — this is the terminal state of the
 * ratchet, not an unrun check. Two decisions in `src/style.css` are what keep
 * it empty rather than an allowlist. First, the stylesheet separates its two
 * boundary tokens: `--border` (#2e3856, ~1.7:1) is used ONLY for decorative
 * dividers between blocks of text, and `--control-border` (#7d89b3, 5.6:1 on
 * `--bg` and 4.5:1 on the lightest surface a control sits on) is used for
 * every interactive edge. Most of this fleet's baselined entries are a control
 * that inherited the decorative token; there is no such control here. Second,
 * every tinted fill is a resolved literal hex value rather than a
 * `color-mix()`, so nothing this lab paints lands in axe's `incomplete`
 * bucket in the first place.
 *
 * The shared top bar's `.cl-btn` — baselined in older labs at ~1.49:1 because
 * it drew its edge from a low-percentage `color-mix()` toward the accent —
 * takes its border from `--cl-ink` here, which resolves to #bdb8fc against the
 * bar's #0b1512 and clears 3:1 by a wide margin. That is why the two entries
 * most of this fleet carries are absent too.
 *
 * A run with `NT_BASELINE_CAPTURE=1` set prints every finding through this
 * same path and asserts nothing, which is how this file is regenerated.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};
