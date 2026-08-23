import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };
/**
 * A HEADROOM probe, deliberately narrower than the 320 CSS px WCAG 1.4.10 asks
 * for. Scanning AT 320 does not work: a sibling lab in this batch shipped a
 * defect whose min-content floor was 318px, so it fit at 320 and failed at 380
 * only once Linux font metrics in CI inflated it — a single-width check cannot
 * see a floor sitting just under that width. 280 asserts the floor is low
 * enough that no font-metric delta can push it back over 320.
 */
export const REFLOW = { width: 280, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the gate
 * this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the one rendering a reduced-motion reader actually gets — `.panel` and
 *     `.reveal` with their animations cancelled by the stylesheet's own rule —
 *     was never once the rendering that got scanned. This gate sets the
 *     preference through `emulateMedia`, asserts from inside the page that it
 *     took effect (`test.use({ reducedMotion })` silently does nothing on
 *     Playwright 1.61.1), and injects nothing.
 *
 *  2. IT FORCED EVERY PANEL VISIBLE FROM SCRIPT. The old drive stripped every
 *     `[hidden]` attribute and set every `<details>.open` by JS before its only
 *     scan. Stripping `hidden` puts all seven tabpanels on screen AT ONCE — a
 *     rendering no reader can reach and axe then scans instead of the real one
 *     — and script-opening the disclosures means the SHUT state, which is what
 *     every reader arrives at, was never scanned at all. This gate switches
 *     tabs by clicking them and opens each disclosure through its `<summary>`,
 *     which is the route a reader has, and scans before and after.
 *
 *  3. IT DROVE BLIND AND THEN THREW THE STATES AWAY. The old drive clicked
 *     every button whose label matched a regex, swallowed every failure with
 *     `.catch(() => {})`, waited a fixed 120ms per tab, and scanned ONCE at the
 *     end — so every failure verdict, every rejected proof, every intermediate
 *     rollover stage and every step of the zone walk were overwritten before
 *     anything measured them, and a click that silently did nothing looked
 *     identical to one that worked. This drive names every control it touches,
 *     asserts a real completion signal after each, and scans after every step,
 *     at 1280px and again at 380px.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. This lab's stylesheet
 *     resolves every tint to a literal hex value precisely so axe can judge
 *     them, but the shared top bar still paints its ink with `color-mix()`,
 *     and an `aria-label` on a role-less element lands in `incomplete` no
 *     matter what the colours are. Both are asserted rather than skimmed.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE. The old
 *     spec hand-rolled one luminance check over two input selectors, reading
 *     the DECLARED `border-top-color` and `background-color` — blind to
 *     composited backdrops, to every `.btn` and `.tab-btn`, and to all states
 *     past first paint. `nontext.ts` replaces it with a measured oracle over
 *     every control at every driven state, and `expectNoHorizontalOverflow`
 *     adds the 1.4.10 check axe has no rule for.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, `style.css`'s reduced-motion
 * block cancels `.panel` / `.reveal` animations and every transition, so
 * `getAnimations()` is normally empty and this returns on the sixth frame. It
 * stays because the shared top bar's `.cl-btn` transitions are declared
 * OUTSIDE the lab's `@media` block — `* { transition: none !important }` wins
 * today, but that is a property of the current stylesheet, not of the page.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * has exactly that shape in miniature: `@keyframes reveal` starts at
 * `opacity: 0.35`, and every result that appears after a click rides it. The
 * reduced-motion block cancels it with `animation: none` AND restates
 * `opacity: 1` explicitly rather than relying on the cancellation — correct
 * today, and this assertion is what makes that a measurement rather than a
 * reading.
 *
 * `aria-hidden` subtrees are excluded; what this lab hides is the decorative
 * check and badge glyphs sitting beside their own words — see `contrast.ts`.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. Six of the seven panels render synchronously at first activation
 * and every one of them then does real cryptography, so a renderer or a
 * verifier that throws leaves that tabpanel EMPTY — and an empty region is
 * exactly what a scan reports as perfectly accessible. Attach before `boot`,
 * assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`. This lab's own
 * hero is a `<div class="cl-hero">`, not a `<header>`, so nothing here implies
 * a second banner today — but the shared bar's `dedupeBanner()` exists because
 * other labs in this fleet DID ship one, and the hero markup is the part of
 * this page most likely to be re-templated from a lab that uses `<header>`.
 * The scripture footer is a `<footer>`, whose implicit role is contentinfo and
 * never banner. Asserting the OUTCOME rather than the markup is what catches
 * an edit that changes either.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * List semantics survive their styling.
 *
 * Every list on this page — the chain of links, each link's checklist, the walk
 * transcript, the key chips, the recovered-name chips — is styled
 * `list-style: none`, which is exactly the declaration that makes Safari and
 * VoiceOver DROP the list's implicit role. `dom.ts` compensates the documented
 * way: an explicit `role="list"` on the container and `role="listitem"` on
 * every child. So here, unlike most of this fleet, an explicit role on a list
 * is the fix rather than the defect. What is asserted is therefore the SHAPE
 * of that fix: any explicit role on a `ul`/`ol` must be `list` (any other
 * value orphans every `<li>` under it), and a `role="list"` must never sit on
 * an empty element, because axe applies `aria-required-children` to the
 * explicit role and fails it the day a walk renders with no steps. Roles are
 * assigned in an element-creation helper, so ask the DOM rather than grepping
 * the source.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
      )
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children'
  ).toEqual([]);
}

/**
 * Load the page with reduced motion actually in effect, and assert the content
 * every scan relies on is really on the page — including the lab's DEFAULTS,
 * which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.x, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. Nothing in this lab's JS branches on
 * `matchMedia`, but the stylesheet's reduced-motion block is the only thing
 * standing between a scan and the mid-flight `reveal` opacity, so the
 * assertion is the difference between scanning the reduced-motion rendering
 * and merely believing we did.
 *
 * `index.html` pins `data-theme="dark"` before first paint and writes the
 * `theme` key; dark is the only theme and there is no toggle anywhere. The
 * boot asserts both the attribute and the absence of any toggle, so the day
 * one is added it fails here rather than being silently hidden by the shared
 * bar's `display:none` rule.
 *
 * The defaults are asserted at length because `app.ts` renders each tabpanel
 * lazily on first activation, and the chain panel validates a real captured
 * chain at mount. A navigation that resolves proves nothing: a renderer that
 * threw would leave `#panel-chain` half-empty, and an empty region is exactly
 * what a scan reports as perfectly accessible.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(page.locator('.tab-btn')).toHaveCount(7);

  // The shared skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run
  // says nothing about.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);

  // Dark is the only theme, so the page must carry no theme control at all —
  // not the shared bar's, which was removed fleet-wide, and not a lab-local
  // one. The shared CSS hides any lab toggle with `display:none !important`,
  // which would leave a dead-but-known element; asserting the count at zero
  // catches the day one is added without going through that list.
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]')
  ).toHaveCount(0);
  await expect(page.locator('#cl-theme-toggle')).toHaveCount(0);

  // ── The arrival state: the chain panel active and ALREADY VALIDATED ─────
  // `renderChainPanel` validates the pinned root-to-Cloudflare capture at
  // mount, so first paint includes three links, their checklists and a verdict.
  // The other six panels are lazily rendered: hidden AND EMPTY until their tab
  // is first activated — asserted, because "empty" is this lab's tell that a
  // renderer threw (see `watchPageErrors`).
  await expect(page.locator('#chain-out')).toHaveAttribute('data-status', 'SECURE');
  await expect(page.locator('#panel-chain .link')).toHaveCount(4); // three zones + the answer
  await expect(page.locator('#panel-chain .check')).not.toHaveCount(0);
  for (const id of ['break', 'insecure', 'walk', 'nsec3', 'online', 'rollover']) {
    await expect(page.locator(`#panel-${id}`)).toBeHidden();
    await expect(page.locator(`#panel-${id}`)).toBeEmpty();
  }

  // ── Every shipped control default ───────────────────────────────────────
  // The clock starts at the capture instant, which is the only instant the
  // captured signatures were all valid at.
  await expect(
    page.locator('#panel-chain .btn[aria-pressed="true"]')
  ).toHaveText('The capture instant');
  await expect(page.getByRole('tab', { name: 'Build the chain' })).toHaveAttribute(
    'aria-selected',
    'true'
  );

  // ── Disclosures ship shut ───────────────────────────────────────────────
  // The gate this replaces opened every <details> from script before its only
  // scan, so the state every reader arrives at was never once measured.
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all. This lab's long
 * values are unbroken hex and base64 runs — a 2048-bit RSA key, a signed-data
 * dump of several hundred octets, and the entire raw `dig` capture — and every
 * one of them relies on `overflow-wrap: anywhere` plus `white-space: pre-wrap`
 * rather than on a scroll region. The shape at risk is a new `<code>` or
 * `<pre>` run that forgets one of those, or a grid item whose automatic
 * minimum size is the min-content of a 512-character line. At 380px that is
 * precisely what this check exists to catch.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab wraps its long values rather than scrolling them, so the assertion
 * is usually vacuous here — but the stylesheet does carry a `.scroller` rule
 * (`overflow: auto`, `max-height: 22rem`) and `dom.ts`'s `scroller()` helper
 * exists to build one WITH `tabindex="0"`, a role and a label already
 * attached. This check is what keeps that helper honest: reach for
 * `overflow: auto` anywhere else and a scroller born without a keyboard route
 * appears, which axe has no rule for at all.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden`
 * DO remove an element from the tab order, so those are skipped rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair. The
 * `hidden` tabpanels here take the `display: none` route, which is why five
 * panels' worth of buttons are legitimately absent from the tab order.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks at `top:-3rem` with
 * full opacity and slides in on focus. The drive scans it focused.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding as it happens and then fails at the end, so
 * a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it here means it runs at
 * every driven state, including `:hover`, and this repo's baseline was
 * captured by that live path.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which still matters because the shared top bar
 *    paints its ink with `color-mix()` even though this lab resolved all of
 *    its own tints to literal hex for exactly this reason. Everything else in
 *    that bucket is a real result axe simply could not finish — including
 *    `aria-prohibited-attr`, which is where an `aria-label` on a role-less
 *    element hides. This page leans on getting that right: every
 *    `.control-group`, every `.check-list`, every `.chips` row and the
 *    `.scroller` helper pair their labels with an explicit role. Drop any of
 *    those roles and the label is silently discarded.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted —
 *    SC 1.4.3 is about what a reader SEES; see `contrast.ts` for what this
 *    lab hides and why it is measured anyway.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the shape they catch: a sticky `<header role="banner">` above a
  // `<div id="app">` holding an `<aside class="cl-hero-why">`, two `<nav>`s
  // (the shared actions and the tablist wrapper), one `<main>` and a footer.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // The aria-hidden walk, exemption lifted — axe skips this text entirely and
  // the default walk honours the same boundary, so this second call is the
  // ONLY thing that ever measures it. See `contrast.ts` for the inventory.
  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)
      )
    )
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}
// ── The drive ───────────────────────────────────────────────────────────────

/** Switch to a tab by clicking it, and prove the switch happened. */
async function openTab(page: Page, name: RegExp, panelId: string): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator(panelId)).toBeVisible();
  await expect(page.locator(panelId)).not.toBeEmpty();
}

/** Wait for an asynchronous panel to finish; every one marks itself pending. */
async function settled(page: Page, selector: string, attribute: string): Promise<void> {
  await expect(page.locator(selector)).not.toHaveAttribute(attribute, 'pending');
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, exactly as a reader gets it: the
 *    chain panel active and already validated against the pinned capture, the
 *    other six tabpanels hidden and UNRENDERED, every disclosure shut.
 *
 *  - EVERY PANEL IS RENDERED LAZILY, so a tab that is never clicked is a panel
 *    that is never in the DOM at all. Each of the seven is activated through
 *    its real tab button and then driven through its own states.
 *
 *  - EVERY FAILURE STATE. Eight of the nine breaks on the second tab paint a
 *    red verdict with its own failure code, and none of them is reachable
 *    without pressing something on purpose. The same goes for the forged
 *    denial on the walk tab and the cached-DS outage on the rollover tab.
 *
 *  - HOVER IS A STATE AND IT PERSISTS AFTER A CLICK. `:hover` stays on the
 *    element under the pointer after `page.click()` resolves, so it is the
 *    state a reader occupies the instant after pressing a button — and
 *    `.tab-btn:hover`, `.btn:hover` and the shared bar's `.cl-btn:hover` all
 *    repaint their fill. Each is scanned explicitly.
 *
 *  - NO FIXED TIMEOUTS. Every wait is on a real completion signal: a
 *    `data-status` leaving `pending`, a `data-complete` flipping to `true`, a
 *    tab's `aria-selected`, a disclosure's `open`.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('arrival: the pinned chain validated, six panels unrendered, disclosures shut');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused, slid in from top:-3rem');

  // ── 1. Build the chain ──────────────────────────────────────────────────
  // Every clock preset, including `+1 day`: its note paragraph and its
  // validation timestamp appear in no other state, so skipping it would leave
  // that rendering unscanned.
  for (const [label, expected] of [
    ['+1 day', 'SECURE'],
    ['+400 days', 'BOGUS'],
    ['−400 days', 'BOGUS'],
    ['The capture instant', 'SECURE'],
  ] as const) {
    await page.locator('#panel-chain').getByRole('button', { name: label }).click();
    await settled(page, '#chain-out', 'data-status');
    await expect(page.locator('#chain-out')).toHaveAttribute('data-status', expected);
    await scanAt(`Chain: clock at ${label} — ${expected}`);
  }

  // The two disclosures a link carries, opened the way a reader opens them.
  const digestSummary = page
    .locator('#panel-chain .disclose-summary', { hasText: 'digest that was compared' })
    .first();
  await digestSummary.click();
  await expect(page.locator('#panel-chain details[open]')).not.toHaveCount(0);
  await scanAt('Chain: the DS digest comparison open, both values printed');

  const octetSummary = page
    .locator('#panel-chain .disclose-summary', { hasText: 'octets this signature covers' })
    .first();
  await octetSummary.click();
  await expect(page.locator('#panel-chain .sd')).not.toHaveCount(0);
  await scanAt('Chain: the signed-octet runs open');

  const rawSummary = page
    .locator('#panel-chain .disclose-summary', { hasText: 'raw dig output' })
    .first();
  await rawSummary.click();
  await expect(page.locator('#panel-chain pre.records')).not.toHaveCount(0);
  await scanAt('Chain: the raw capture disclosed — the widest text on the page');

  // ── 2. Break each link ──────────────────────────────────────────────────
  await openTab(page, /Break each link/, '#panel-break');
  await settled(page, '#break-out', 'data-failure');
  await expect(page.locator('#break-out')).toHaveAttribute('data-failure', 'none');
  await scanAt('Break: nothing broken — every link SECURE');

  for (const [label, expected] of [
    ['Stale fingerprint at the parent', 'DS_MISMATCH'],
    ['DS points at a key that is not there', 'KEYTAG_MISMATCH'],
    ['Signatures expired', 'RRSIG_EXPIRED'],
    ['Clock behind the inception', 'RRSIG_NOT_YET_VALID'],
    ['Zone signs its keys with a key nobody vouched for', 'KEYTAG_MISMATCH'],
    ['Answer rewritten in flight', 'SIGNATURE_INVALID'],
    ['A neighbouring zone signs your records', 'SIGNER_NAME_MISMATCH'],
    ['An algorithm this validator does not implement', 'ALG_UNSUPPORTED'],
  ] as const) {
    await page.locator('#panel-break').getByRole('button', { name: label }).click();
    await settled(page, '#break-out', 'data-failure');
    await expect(page.locator('#break-out')).toHaveAttribute('data-failure', expected);
    await scanAt(`Break: ${label} — ${expected}`);
  }

  // ── 3. No DS: insecure ──────────────────────────────────────────────────
  await openTab(page, /No DS: insecure/, '#panel-insecure');
  await settled(page, '#insecure-out', 'data-status');
  await expect(page.locator('#insecure-out')).toHaveAttribute('data-status', 'INSECURE');
  await scanAt('Insecure: the real .com proof for google.com — INSECURE, not an alarm');

  for (const [label, expected] of [
    ['In-page: an unsigned child', 'INSECURE'],
    ['For contrast: no DS and no proof', 'BOGUS'],
  ] as const) {
    await page.locator('#panel-insecure').getByRole('button', { name: label }).click();
    await settled(page, '#insecure-out', 'data-status');
    await expect(page.locator('#insecure-out')).toHaveAttribute('data-status', expected);
    await scanAt(`Insecure: ${label} — ${expected}`);
  }

  await page
    .locator('#panel-insecure .disclose-summary', { hasText: 'what .com actually sent' })
    .click();
  await expect(page.locator('#panel-insecure details[open]')).toHaveCount(1);
  await scanAt('Insecure: the captured NSEC3 records disclosed');

  // ── 4. Walk the zone ────────────────────────────────────────────────────
  await openTab(page, /Walk the zone/, '#panel-walk');
  await expect(page.locator('#walk-out')).toHaveAttribute('data-found', '0');
  await scanAt('Walk: the arrival state — an empty ring, nothing discovered');

  await page.locator('#panel-walk').getByRole('button', { name: 'Ask one question' }).click();
  await expect(page.locator('#walk-out')).toHaveAttribute('data-found', '1');
  await scanAt('Walk: one query, one name, the evidence panel populated');

  await page.locator('#panel-walk').getByRole('button', { name: 'Walk the whole zone' }).click();
  await expect(page.locator('#walk-out')).toHaveAttribute('data-complete', 'true');
  await scanAt('Walk: the ring closed — every name recovered');

  await page.locator('#panel-walk').getByRole('button', { name: 'Unguessable names' }).click();
  await expect(page.locator('#walk-out')).toHaveAttribute('data-found', '0');
  await page.locator('#panel-walk').getByRole('button', { name: 'Walk the whole zone' }).click();
  await expect(page.locator('#walk-out')).toHaveAttribute('data-complete', 'true');
  await scanAt('Walk: high-entropy labels recovered just as completely');

  // Back to the ordinary zone and reset, so both of the remaining controls are
  // driven and the emptied ring is scanned again with a rendered panel.
  await page.locator('#panel-walk').getByRole('button', { name: 'Ordinary names' }).click();
  await expect(page.locator('#walk-out')).toHaveAttribute('data-found', '0');
  await page.locator('#panel-walk').getByRole('button', { name: 'Ask one question' }).click();
  await expect(page.locator('#walk-out')).toHaveAttribute('data-found', '1');
  await page.locator('#panel-walk').getByRole('button', { name: 'Start over' }).click();
  await expect(page.locator('#walk-out')).toHaveAttribute('data-found', '0');
  await scanAt('Walk: reset to an empty ring with the panel already rendered');

  await page.locator('#panel-walk').getByRole('button', { name: 'Offer a non-covering NSEC' }).click();
  await expect(page.locator('#panel-walk .check-bad')).not.toHaveCount(0);
  await scanAt('Walk: a forged denial rejected — the failed-check styling');

  await page
    .locator('#panel-walk .disclose-summary', { hasText: 'Why does this work at all' })
    .click();
  await expect(page.locator('#panel-walk details[open]')).toHaveCount(1);
  await scanAt('Walk: the offline-signing explanation disclosed');

  // ── 5. NSEC3 guessing ───────────────────────────────────────────────────
  await openTab(page, /NSEC3 guessing/, '#panel-nsec3');
  await settled(page, '#nsec3-out', 'data-state');
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-state', 'complete');
  await scanAt('NSEC3: ordinary labels — most of the zone recovered, the meter filled');

  await page.locator('#panel-nsec3').getByRole('button', { name: /Unguessable names/ }).click();
  await settled(page, '#nsec3-out', 'data-state');
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-state', 'complete');
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-rate', '0');
  await scanAt('NSEC3: high-entropy labels — nothing recovered, the empty meter');

  await page.locator('#panel-nsec3').getByRole('button', { name: /^Ordinary names/ }).click();
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-state', 'complete');
  await page.locator('#panel-nsec3').getByRole('button', { name: '150', exact: true }).click();
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-state', 'complete');
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-iterations', '150');
  await scanAt('NSEC3: 150 extra iterations — same recovery, 151x the work');

  await page.locator('#panel-nsec3').getByRole('button', { name: '8-byte salt' }).click();
  // `data-state` passes through `running`, so wait for `complete` rather than
  // merely for "not pending" -- a scan taken mid-run measures a half-drawn
  // chip list and a meter that is still moving.
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-state', 'complete');
  await scanAt('NSEC3: salted — the trace and the rate both re-rendered');

  // One intermediate iteration count and the no-salt control, so every button
  // in this panel is driven. The 10 and 50 presets render the same shape as
  // 150 with different numbers, so only one of the three is scanned; that is a
  // deliberate cap and it is stated here rather than left silent.
  await page.locator('#panel-nsec3').getByRole('button', { name: '10', exact: true }).click();
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-state', 'complete');
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-iterations', '10');
  await page.locator('#panel-nsec3').getByRole('button', { name: /no salt/ }).click();
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-state', 'complete');
  await scanAt('NSEC3: 10 iterations, salt removed again — every control in this panel driven');

  for (const summary of ['iterations and salt do not change', 'stated in the direction that is true']) {
    await page.locator('#panel-nsec3 .disclose-summary', { hasText: summary }).click();
  }
  await expect(page.locator('#panel-nsec3 details[open]')).toHaveCount(2);
  await scanAt('NSEC3: both explanatory disclosures open, including the warning callout');

  // ── 6. Denial on demand ─────────────────────────────────────────────────
  await openTab(page, /Denial on demand/, '#panel-online');
  await expect(page.locator('#online-out')).toHaveAttribute('data-style', 'synthesized');
  await scanAt('Online: the captured black lie — NOERROR and a synthesized interval');

  await page.locator('#panel-online').getByRole('button', { name: 'Pre-computed chain' }).click();
  await settled(page, '#online-out', 'data-style');
  await expect(page.locator('#online-out')).toHaveAttribute('data-style', 'precomputed');
  await scanAt('Online: the pre-computed chain, which names real neighbours');

  await page
    .locator('#panel-online .disclose-summary', { hasText: 'Citations' })
    .click();
  await expect(page.locator('#panel-online .check-bad')).not.toHaveCount(0);
  await scanAt('Online: the citation list open, with its two struck-through entries');

  await page.locator('#panel-online .disclose-summary', { hasText: 'Where this capture came from' }).click();
  await expect(page.locator('#panel-online details[open]')).toHaveCount(2);
  await scanAt('Online: the raw captured denial disclosed');

  // ── 7. Key rollover ─────────────────────────────────────────────────────
  await openTab(page, /Key rollover/, '#panel-rollover');
  await settled(page, '#rollover-out', 'data-stage');
  await expect(page.locator('#rollover-out')).toHaveAttribute('data-status', 'SECURE');
  await scanAt('Rollover: before the roll — one zone-signing key');

  for (const [label, keys, signatures] of [
    ['Pre-publish', '3', '1'],
    ['Double-signature', '3', '2'],
    ['After', '2', '1'],
  ] as const) {
    await page.locator('#panel-rollover').getByRole('button', { name: label, exact: true }).click();
    await settled(page, '#rollover-out', 'data-stage');
    await expect(page.locator('#rollover-out')).toHaveAttribute('data-keys', keys);
    await expect(page.locator('#rollover-out')).toHaveAttribute(
      'data-signatures',
      signatures
    );
    await scanAt(`Rollover: ${label} — ${keys} keys, ${signatures} signature(s), still SECURE`);
  }

  await page
    .locator('#panel-rollover')
    .getByRole('button', { name: 'A cached DS outlives its key' })
    .click();
  await settled(page, '#rollover-failure-out', 'data-status');
  await expect(page.locator('#rollover-failure-out')).toHaveAttribute('data-status', 'BOGUS');
  await scanAt('Rollover: the cached-DS outage — the danger callout');

  await page.locator('#panel-rollover .disclose-summary', { hasText: 'two keys in the first place' }).click();
  await expect(page.locator('#panel-rollover details[open]')).toHaveCount(1);
  await scanAt('Rollover: the two-key explanation disclosed');

  // ── Hover, which persists after a click ─────────────────────────────────
  await page.locator('#panel-rollover').getByRole('button', { name: 'Before', exact: true }).hover();
  await scanAt('an in-panel button hovered — its surface-3 fill repainted');

  await page.getByRole('tab', { name: /Build the chain/ }).hover();
  await scanAt('an inactive tab hovered');

  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered');

  // ── Focus rings on the controls that take them ──────────────────────────
  await page.getByRole('tab', { name: /Key rollover/ }).focus();
  await scanAt('the active tab focused');

  await page.locator('#panel-rollover .disclose-summary').first().focus();
  await scanAt('a disclosure summary focused');

  // ── Narrow-width regression: every panel rendered at once ───────────────
  // Only reached because every tab above has now been activated, so the whole
  // document exists. Switching back to the first tab and scanning proves the
  // page still reflows with every panel's DOM present.
  await openTab(page, /Build the chain/, '#panel-chain');
  await scanAt('back on the chain tab with every other panel rendered but hidden');
}
