import { expect, test, type Page } from '@playwright/test';

/**
 * The claims suite: does the page tell the truth?
 *
 * The rule that makes these tests worth anything is that they compare two
 * values the PAGE ITSELF printed, or re-derive a claim from what is on screen
 * by a different route than the source takes. A test that recomputes the same
 * expression the source uses will happily agree with a bug — and internal
 * consistency alone is not enough either, because a page can be consistently
 * wrong. So the mix here is deliberate:
 *
 *  - CROSS-CHECKS between two surfaces that must agree, each rendered from a
 *    different source. The strongest is the root DS digest: the page COMPUTES
 *    one by hashing the DNSKEY records the root actually served, and
 *    separately PRINTS the digest IANA publishes. Those are different inputs
 *    through different code paths, and they have to come out identical.
 *  - INDEPENDENT RE-DERIVATIONS. The zone walk's transcript is re-linked here
 *    from the rendered text alone: every row's discovered name must equal the
 *    previous row's printed `next`. Nothing in the source is consulted.
 *  - PARTS-SUM-TO-WHOLE. The per-run octet counts in the signed-data panel
 *    must add up to the total the signature check reports, and the recovered
 *    chips must add up to the recovery rate the meter shows.
 *
 * Plus every failure path, the retirement of a stale verdict, a no-op guard,
 * the `[hidden]` cascade probe, and the two negative claims this lab makes in
 * prose — that DNSSEC never provides confidentiality, and that ECH does not
 * depend on it — each checked against evidence the page itself supplies.
 */

async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(30_000);
  await page.goto('.');
  await expect(page.locator('#chain-out')).toHaveAttribute('data-status', 'SECURE');
}

async function openTab(page: Page, name: string): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
}

async function settled(page: Page, selector: string, attribute: string): Promise<void> {
  await expect(page.locator(selector)).not.toHaveAttribute(attribute, 'pending');
}

/**
 * The dictionary run passes through `running` on its way to `complete`, so
 * "not pending" is NOT the same as "finished" — reading the counters at that
 * moment gets a mid-run snapshot, which is how a comparison between two runs
 * comes to compare one finished run against half of another.
 */
async function dictionaryFinished(page: Page): Promise<void> {
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-state', 'complete');
}

// ── The headline claim, re-derived from the rendered transcript ────────────

test('the walk transcript links up: every row starts where the previous one pointed', async ({
  page,
}) => {
  await boot(page);
  await openTab(page, 'Walk the zone');
  await page.locator('#panel-walk').getByRole('button', { name: 'Walk the whole zone' }).click();
  await expect(page.locator('#walk-out')).toHaveAttribute('data-complete', 'true');

  // Read the transcript as a reader would, and re-link it here. The source is
  // never consulted: the chain is reconstructed from the printed text.
  const rows = await page.locator('#walk-out .walk-row').all();
  expect(rows.length).toBeGreaterThan(5);
  const parsed: { discovered: string; next: string }[] = [];
  for (const row of rows) {
    const discovered = (await row.locator('.walk-name').textContent())?.trim() ?? '';
    const nextText = (await row.locator('.walk-next').textContent())?.trim() ?? '';
    const next = nextText.replace(/^→\s*next is\s*/, '').trim();
    parsed.push({ discovered, next });
  }

  for (let i = 1; i < parsed.length; i += 1) {
    expect(parsed[i]?.discovered, `row ${i + 1} must start where row ${i} pointed`).toBe(
      parsed[i - 1]?.next
    );
  }
  // The ring closes: the last row points back at the first name found, which
  // is the zone apex. That is what makes the enumeration provably complete.
  expect(parsed[parsed.length - 1]?.next).toBe(parsed[0]?.discovered);
  expect(parsed[0]?.discovered).toBe('demo.example.');

  // Every name is distinct, so a walk of N rows really did find N names.
  const names = parsed.map((p) => p.discovered);
  expect(new Set(names).size).toBe(names.length);

  // The counter the page prints agrees with the transcript it printed.
  const found = await page.locator('#walk-out').getAttribute('data-found');
  const total = await page.locator('#walk-out').getAttribute('data-total');
  expect(Number(found)).toBe(parsed.length);
  expect(Number(total)).toBe(parsed.length);

  // And the ring's own accessible description agrees with both.
  const ringLabel = (await page.locator('#walk-out .ring').getAttribute('aria-label')) ?? '';
  expect(ringLabel).toContain(`${parsed.length} names discovered`);
  expect(ringLabel).toContain('closed back to the zone apex');
});

test('unguessable names are recovered by the walk exactly as completely', async ({ page }) => {
  await boot(page);
  await openTab(page, 'Walk the zone');
  await page.locator('#panel-walk').getByRole('button', { name: 'Unguessable names' }).click();
  await expect(page.locator('#walk-out')).toHaveAttribute('data-found', '0');
  await page.locator('#panel-walk').getByRole('button', { name: 'Walk the whole zone' }).click();
  await expect(page.locator('#walk-out')).toHaveAttribute('data-complete', 'true');

  const names = await page.locator('#walk-out .walk-name').allTextContents();
  // Twelve random characters per label, and every one is on screen.
  const random = names.filter((n) => /^[a-z0-9]{12}\.demo\.example\.$/.test(n));
  expect(random.length).toBeGreaterThan(15);
});

// ── Cross-check: the computed digest against IANA's published one ──────────

test('the digest the page computes equals the digest IANA publishes', async ({ page }) => {
  await boot(page);
  // Surface one: the trust-anchor table, rendered from the transcribed
  // root-anchors.xml.
  const published = await page.locator('#panel-chain table.data tbody td.mono').allTextContents();
  const publishedDigests = published
    .map((t) => t.trim().toUpperCase())
    .filter((t) => /^[0-9A-F]{64}$/.test(t));
  expect(publishedDigests.length).toBeGreaterThan(0);

  // Surface two: the comparison panel, rendered by hashing the DNSKEY records
  // the root actually served in the pinned capture.
  await page
    .locator('#panel-chain .disclose-summary', { hasText: 'digest that was compared' })
    .first()
    .click();
  const rootLink = page.locator('#panel-chain .link').first();
  const rows = await rootLink.locator('.cmp-row .cmp-hex').allTextContents();
  expect(rows).toHaveLength(2);
  const computed = rows[0]?.trim().toUpperCase() ?? '';
  const parentPublished = rows[1]?.trim().toUpperCase() ?? '';

  // The two sides of the comparison agree with each other...
  expect(computed).toBe(parentPublished);
  // ...and with the anchor table, which was rendered from a different source.
  expect(publishedDigests).toContain(computed);
  await expect(rootLink.locator('.cmp-equal')).toHaveCount(1);
});

// ── Parts sum to whole: the signed octets ──────────────────────────────────

test('the per-run octet counts add up to the total the signature check reports', async ({
  page,
}) => {
  await boot(page);
  await page
    .locator('#panel-chain .disclose-summary', { hasText: 'octets this signature covers' })
    .first()
    .click();
  const link = page.locator('#panel-chain .link').filter({ has: page.locator('.sd') }).first();

  const lengths = await link.locator('.sd .sd-len').allTextContents();
  expect(lengths.length).toBeGreaterThan(1);
  const sum = lengths.reduce((n, text) => n + Number(/(\d+)/.exec(text)?.[1] ?? 0), 0);

  // The signature check line states the total independently. Found by its own
  // wording rather than by position: several checks in the same list carry the
  // word "signature" in their label.
  const details = await link.locator('.check .check-detail').allTextContents();
  const signatureDetail = details.find((t) => /verified over \d+ octets/.test(t)) ?? '';
  const stated = Number(/verified over (\d+) octets/.exec(signatureDetail)?.[1] ?? -1);
  expect(stated).toBeGreaterThan(0);
  expect(sum).toBe(stated);

  // And the record count in that same sentence matches the number of runs
  // drawn, minus the RRSIG prefix run.
  const statedRecords = Number(/followed by (\d+) canonicalized record/.exec(signatureDetail)?.[1] ?? -1);
  expect(statedRecords).toBe(lengths.length - 1);
});

// ── Every failure path names its actual cause ──────────────────────────────

test('each break produces the failure the page said it would', async ({ page }) => {
  await boot(page);
  await openTab(page, 'Break each link');
  await settled(page, '#break-out', 'data-failure');

  const buttons = await page.locator('#panel-break .control-group button').all();
  expect(buttons.length).toBeGreaterThanOrEqual(9);

  for (const control of buttons) {
    await control.click();
    await settled(page, '#break-out', 'data-failure');
    const out = page.locator('#break-out');
    // `data-expected` comes from the hand-authored break table; `data-failure`
    // comes from the validator. They are produced by different code and must
    // agree — a break that stopped producing its failure fails here.
    const expected = await out.getAttribute('data-expected');
    const actual = await out.getAttribute('data-failure');
    const label = (await control.textContent())?.trim() ?? '(unnamed)';
    expect(actual, `break "${label}"`).toBe(expected);

    if (expected === 'none') {
      await expect(out.locator('.failure-code')).toHaveCount(0);
      await expect(out).toHaveAttribute('data-status', 'SECURE');
    } else {
      // The code the page PRINTS in its failure note must be the code the
      // validator returned, not a generic message.
      const printed = (await out.locator('.failure-code').first().textContent())?.trim();
      expect(printed, `break "${label}" must name its cause`).toBe(expected);
      // And the note must carry a real specification reference, not a
      // hand-waved one.
      const reference = (await out.locator('.failure-ref').first().textContent()) ?? '';
      expect(reference, `break "${label}"`).toMatch(/RFC \d{4}/);
    }
  }
});

test('an unsupported algorithm is INDETERMINATE, never a forgery', async ({ page }) => {
  await boot(page);
  await openTab(page, 'Break each link');
  await page
    .locator('#panel-break')
    .getByRole('button', { name: 'An algorithm this validator does not implement' })
    .click();
  await settled(page, '#break-out', 'data-failure');
  await expect(page.locator('#break-out')).toHaveAttribute('data-failure', 'ALG_UNSUPPORTED');
  await expect(page.locator('#break-out')).toHaveAttribute('data-status', 'INDETERMINATE');
  // The distinction has to be visible, not just internal.
  await expect(page.locator('#break-out')).not.toContainText('SIGNATURE_INVALID');
});

// ── INSECURE is not a failure ──────────────────────────────────────────────

test('INSECURE carries no failure code; the same delegation without a proof is BOGUS', async ({
  page,
}) => {
  await boot(page);
  await openTab(page, 'No DS: insecure');
  await settled(page, '#insecure-out', 'data-status');

  // The real captured .com proof for google.com.
  await expect(page.locator('#insecure-out')).toHaveAttribute('data-status', 'INSECURE');
  await expect(page.locator('#insecure-out .failure-code')).toHaveCount(0);
  await expect(page.locator('#insecure-out .check-bad')).toHaveCount(0);

  // The in-page NSEC version reaches the same conclusion by a different route.
  await page.locator('#panel-insecure').getByRole('button', { name: 'In-page: an unsigned child' }).click();
  await settled(page, '#insecure-out', 'data-status');
  await expect(page.locator('#insecure-out')).toHaveAttribute('data-status', 'INSECURE');
  await expect(page.locator('#insecure-out .failure-code')).toHaveCount(0);

  // Remove the proof as well and the same missing DS becomes a hole.
  await page
    .locator('#panel-insecure')
    .getByRole('button', { name: 'For contrast: no DS and no proof' })
    .click();
  await settled(page, '#insecure-out', 'data-status');
  await expect(page.locator('#insecure-out')).toHaveAttribute('data-status', 'BOGUS');
  await expect(page.locator('#insecure-out .failure-code')).not.toHaveCount(0);
});

// ── The NSEC3 result is a measured rate, and its parts agree ───────────────

test('the recovery rate, the chips and the hash count all agree', async ({ page }) => {
  await boot(page);
  await openTab(page, 'NSEC3 guessing');
  await dictionaryFinished(page);

  const read = async (key: string): Promise<number> =>
    Number(await page.locator('#nsec3-out').getAttribute(`data-${key}`));

  const recovered = await read('recovered');
  const zoneNames = await read('zonenames');
  const rate = await read('rate');
  const candidates = await read('candidates');
  const hashOps = await read('hashops');
  const iterations = await read('iterations');

  // Re-derive the percentage from the two counts, rather than trusting it.
  expect(Math.round((recovered / zoneNames) * 1000) / 10).toBe(rate);
  // The meter's accessible value is a third surface and must match.
  const meterValue = Number(
    await page.locator('#nsec3-out [role="meter"]').getAttribute('aria-valuenow')
  );
  expect(meterValue).toBe(rate);
  // The chips are the fourth: one per recovered name, one per missed name.
  // Scoped to `ul.chips` because the legend above the list uses the same two
  // classes to show what each colour means — counting it would be an off-by-one
  // in both directions.
  await expect(page.locator('#nsec3-out ul.chips .chip-found')).toHaveCount(recovered);
  await expect(page.locator('#nsec3-out ul.chips .chip-safe')).toHaveCount(zoneNames - recovered);

  // Every hash is accounted for: one per candidate, times iterations + 1.
  expect(hashOps).toBe(candidates * (iterations + 1));

  // The headline finding: most of a guessable zone falls out, but not all of
  // it, and what survives is named on screen rather than merely counted.
  expect(rate).toBeGreaterThan(70);
  expect(rate).toBeLessThan(100);
  const survivors = await page
    .locator('#nsec3-out ul.chips .chip-safe .chip-name')
    .allTextContents();
  expect(survivors.length).toBeGreaterThan(0);
  for (const survivor of survivors) expect(survivor).toMatch(/\.demo\.example\.$/);
});

test('adding 150 iterations changes the cost and not the recovered set', async ({ page }) => {
  await boot(page);
  await openTab(page, 'NSEC3 guessing');
  await dictionaryFinished(page);
  const before = await page.locator('#nsec3-out ul.chips .chip-found .chip-name').allTextContents();
  const hashesBefore = Number(await page.locator('#nsec3-out').getAttribute('data-hashops'));

  await page.locator('#panel-nsec3').getByRole('button', { name: '150', exact: true }).click();
  await dictionaryFinished(page);
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-iterations', '150');
  const after = await page.locator('#nsec3-out ul.chips .chip-found .chip-name').allTextContents();
  const hashesAfter = Number(await page.locator('#nsec3-out').getAttribute('data-hashops'));

  // Identical outcome...
  expect([...after].sort()).toEqual([...before].sort());
  // ...for 151 times the work. That ratio is the whole argument.
  expect(hashesAfter).toBe(hashesBefore * 151);
});

test('high-entropy labels recover nothing, and the page says why', async ({ page }) => {
  await boot(page);
  await openTab(page, 'NSEC3 guessing');
  await dictionaryFinished(page);
  await page.locator('#panel-nsec3').getByRole('button', { name: /Unguessable names/ }).click();
  await dictionaryFinished(page);
  await expect(page.locator('#nsec3-out')).toHaveAttribute('data-rate', '0');
  await expect(page.locator('#nsec3-out ul.chips .chip-found')).toHaveCount(0);
  // The conclusion must be about the NAMES, not a verdict on NSEC3.
  await expect(page.locator('#nsec3-out')).toContainText('a statement about the names, not about NSEC3');
});

test('the page states the NSEC3 claim in the direction that is true', async ({ page }) => {
  await boot(page);
  await openTab(page, 'NSEC3 guessing');
  await page
    .locator('#panel-nsec3 .disclose-summary', { hasText: 'stated in the direction that is true' })
    .click();
  const panel = page.locator('#panel-nsec3');
  await expect(panel).toContainText('replaces trivial walking with an offline guessing problem');
  await expect(panel).toContainText('Predictable labels remain recoverable despite added iterations');
  // The inverted claim must not appear anywhere on the page, in any casing.
  const text = ((await page.locator('#app').textContent()) ?? '').toLowerCase();
  expect(text).not.toContain('nsec3 prevents enumeration');
  expect(text).not.toContain('nsec3 eliminates enumeration');
});

// ── Retirement, and the no-op guard ────────────────────────────────────────

test('changing the clock retires the previous verdict and names the new instant', async ({
  page,
}) => {
  await boot(page);
  const stamp = async (): Promise<string> =>
    (await page.locator('#chain-out .prose', { hasText: 'Validating at' }).first().textContent()) ?? '';

  const firstStamp = await stamp();
  expect(firstStamp).toContain('Validating at');
  await expect(page.locator('#chain-out')).toHaveAttribute('data-status', 'SECURE');
  await expect(page.locator('#chain-out .failure-code')).toHaveCount(0);

  await page.locator('#panel-chain').getByRole('button', { name: '+400 days' }).click();
  await settled(page, '#chain-out', 'data-status');

  // The stale verdict is gone...
  await expect(page.locator('#chain-out')).toHaveAttribute('data-status', 'BOGUS');
  await expect(page.locator('#chain-out .status-note-ok')).toHaveCount(0);
  // ...and the page states which instant the new one belongs to.
  const secondStamp = await stamp();
  expect(secondStamp).not.toBe(firstStamp);
  expect(secondStamp).toContain('Validating at');
  await expect(page.locator('#chain-out .failure-code')).toContainText('RRSIG_EXPIRED');
});

test('re-selecting the same clock does not change a fresh verdict', async ({ page }) => {
  await boot(page);
  const before = await page.locator('#chain-out').getAttribute('data-now');
  await page.locator('#panel-chain').getByRole('button', { name: 'The capture instant' }).click();
  await settled(page, '#chain-out', 'data-status');
  const after = await page.locator('#chain-out').getAttribute('data-now');
  expect(after).toBe(before);
  await expect(page.locator('#chain-out')).toHaveAttribute('data-status', 'SECURE');
  await expect(page.locator('#chain-out .failure-code')).toHaveCount(0);
});

// ── The [hidden] cascade probe (section 4.1) ───────────────────────────────

test('a hidden tabpanel really is hidden, and really is empty', async ({ page }) => {
  await boot(page);
  // The trap this catches: a class rule setting `display` outranks the UA's
  // `[hidden]` rule, so the element paints while the code believes it is
  // hidden. Ask the browser what it actually renders.
  const leaking = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('[hidden]'))
      .filter((el) => el.checkVisibility?.({ checkVisibilityCSS: true }))
      .map((el) => el.id || el.className)
  );
  expect(leaking).toEqual([]);

  // And lazily-rendered panels are empty until their tab is used, so a scan
  // that reported them accessible would be reporting nothing.
  for (const id of ['break', 'insecure', 'walk', 'nsec3', 'online', 'rollover']) {
    await expect(page.locator(`#panel-${id}`)).toBeEmpty();
  }
});

// ── The negative claims, each with evidence on the page ────────────────────

test('NEG-1: the page claims no confidentiality, and its own capture is the evidence', async ({
  page,
}) => {
  await boot(page);

  // The claim, in the page's own scoping section.
  const scope = page.locator('.scope-note');
  await expect(scope).toContainText('never confidentiality');
  await expect(scope).toContainText('travel in the clear');

  // The evidence fixture: the disclosed capture is the actual bytes those
  // servers returned, and it is plain readable text. Nothing had to be
  // decrypted to read a hostname or an address out of it — which is the whole
  // content of the claim.
  await page
    .locator('#panel-chain .disclose-summary', { hasText: 'raw dig output' })
    .click();
  const capture = (await page.locator('#panel-chain pre.records code').textContent()) ?? '';
  expect(capture.length).toBeGreaterThan(2000);
  expect(capture).toContain('cloudflare.com.');
  // A routable address, in the clear, inside a chain that validates.
  expect(capture).toMatch(/\bIN\s+A\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
  // The signatures are there too — integrity and origin, and nothing else.
  expect(capture).toContain('RRSIG');

  // And the page never claims the opposite.
  const text = ((await page.locator('#app').textContent()) ?? '').toLowerCase();
  expect(text).not.toContain('dnssec encrypts');
  expect(text).not.toContain('encrypts your queries');
});

test('the ECH cross-link is stated as a protection, not as a dependency', async ({ page }) => {
  await boot(page);
  const note = page.locator('#ech-note');
  await expect(note).toContainText('It is not.');
  await expect(note).toContainText('without requiring any verifiable authenticity or provenance');
  await expect(note).toContainText('an available protection for the ECHConfig, not the source of its authenticity');

  const text = ((await page.locator('#app').textContent()) ?? '').toLowerCase();
  expect(text).not.toContain('ech depends on dnssec');
  expect(text).not.toContain('ech requires dnssec');
});

// ── Rollover: every intermediate state validates ───────────────────────────

test('every rollover stage stays SECURE, and the key counts are what the stage means', async ({
  page,
}) => {
  await boot(page);
  await openTab(page, 'Key rollover');
  await settled(page, '#rollover-out', 'data-stage');

  for (const [label, keys, signatures] of [
    ['Before', '2', '1'],
    ['Pre-publish', '3', '1'],
    ['Double-signature', '3', '2'],
    ['After', '2', '1'],
  ] as const) {
    await page.locator('#panel-rollover').getByRole('button', { name: label, exact: true }).click();
    await settled(page, '#rollover-out', 'data-stage');
    const out = page.locator('#rollover-out');
    await expect(out, label).toHaveAttribute('data-status', 'SECURE');
    await expect(out, label).toHaveAttribute('data-keys', keys);
    await expect(out, label).toHaveAttribute('data-signatures', signatures);
    // The chip list is a second surface for the same counts. `.first()` picks
    // the stage's own key list rather than the per-link chips the chain view
    // renders below it.
    const keyChips = out.locator('.chips').first();
    await expect(keyChips.locator('li'), label).toHaveCount(Number(keys));
    // Pre-publish means published and NOT signing; the page must say so.
    if (label === 'Pre-publish') {
      await expect(keyChips.locator('li', { hasText: 'published, not signing' })).toHaveCount(1);
    }
  }

  // And the failure that is actually common is still a failure.
  await page
    .locator('#panel-rollover')
    .getByRole('button', { name: 'A cached DS outlives its key' })
    .click();
  await settled(page, '#rollover-failure-out', 'data-status');
  await expect(page.locator('#rollover-failure-out')).toHaveAttribute('data-status', 'BOGUS');
});

// ── The online-denial panel says what it costs ─────────────────────────────

test('the synthesized denial is shown as a trade, with its citations checked', async ({ page }) => {
  await boot(page);
  await openTab(page, 'Denial on demand');
  await expect(page.locator('#online-out')).toHaveAttribute('data-style', 'synthesized');
  // NOERROR, not NXDOMAIN: black lies answer NODATA.
  await expect(page.locator('#online-out')).toHaveAttribute('data-rcode', 'NOERROR');
  // And the page does not claim it as an NXDOMAIN proof.
  await expect(page.locator('#online-out')).toHaveAttribute('data-nxproof', 'false');

  // The cost is stated, not glossed.
  await expect(page.locator('#panel-online')).toContainText('private key lives on a machine that answers the internet');

  // The citation that is commonly wrong is named as wrong rather than repeated.
  await page.locator('#panel-online .disclose-summary', { hasText: 'Citations' }).click();
  await expect(page.locator('#panel-online .check-bad', { hasText: 'RFC 8901' })).toHaveCount(1);
  await expect(page.locator('#panel-online .check-bad', { hasText: 'has no RFC' })).toHaveCount(1);
  // Matched on the label, not on the row text: RFC 7129's entry mentions RFC
  // 4470 in its own description.
  await expect(
    page.locator('#panel-online .check-ok .check-label', { hasText: 'RFC 4470 — Standards Track' })
  ).toHaveCount(1);
});

// ── Scoping honesty ────────────────────────────────────────────────────────

test('the page says what it is not', async ({ page }) => {
  await boot(page);
  const scope = page.locator('.scope-note');
  await expect(scope).toContainText('Not production crypto');
  await expect(scope).toContainText('teaching demo');
  await expect(scope).toContainText('pinned capture');
  await expect(scope).toContainText('What it does NOT prove');
  // The private keys being public is stated, because it matters.
  await expect(scope).toContainText('private keys are published in the repository on purpose');
});
