import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  REFLOW,
  reportCollected,
  watchPageErrors,
} from './gate.ts';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where the
 * pinned root-to-Cloudflare chain has already validated and the other six
 * tabpanels are hidden and UNRENDERED; the shared skip link focused; the
 * validation clock moved past every expiration and back before every
 * inception; the DS-digest and signed-octet disclosures opened through their
 * summaries; the entire raw `dig` capture disclosed, which is the widest text
 * on the page; all eight named breaks, each painting its own failure code;
 * the real `.com` proof that `google.com` has no DS, the in-page NSEC version
 * of the same, and the contrasting case where the proof is missing too; the
 * zone walk at zero names, at one, walked to completion on ordinary labels and
 * again on high-entropy ones, and a forged denial rejected; the NSEC3
 * dictionary run on both label sets, at 150 iterations and with a salt; the
 * captured black lie and the pre-computed chain beside it; every rollover
 * stage and the cached-DS outage; three hover states; two focus rings; and
 * finally the first tab again with every other panel rendered but hidden.
 * Every one of those states is scanned, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page (the old gate's
 * `addStyleTag` motion kill bypassed the stylesheet's own reduced-motion
 * block, so the rendering reduced-motion readers get was never the one
 * scanned), why no panel is revealed from script (the old gate stripped every
 * `[hidden]` and opened every `<details>` by JS before its only scan), why the
 * lab's defaults are asserted rather than assumed, and why `violations` is not
 * the whole oracle.
 *
 * Dark is the only theme this lab ships, so the loop below has one iteration.
 * It stays a loop because the gate's helpers take the theme by name and the
 * scan labels carry it, and because a lab that grew a second theme should get
 * both scanned rather than silently only the first.
 */
for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 280px — reflow headroom below the 320px threshold`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(REFLOW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @280px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
