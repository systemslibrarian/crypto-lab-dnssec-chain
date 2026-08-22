/**
 * Teaching keys for the in-page hierarchy, pinned so the demo zone is
 * reproducible across reloads, across browsers, and in CI.
 *
 * THESE PRIVATE KEYS ARE PUBLISHED ON PURPOSE AND PROTECT NOTHING. They exist
 * so a learner can watch a real signature be made and then be verified, and so
 * the page's own tests can assert exact key tags. Nothing on this page is
 * production key material, and nothing here is a secret; the lab has no
 * backend and stores nothing.
 *
 * Generated once with WebCrypto (P-256) and `@noble/curves` (Ed25519). The
 * hierarchy mirrors the real one the pinned capture shows: a root, a top-level
 * zone, and a signed child, plus a spare ZSK for the rollover act and a rogue
 * pair for the acts where a learner signs with the wrong key.
 *
 * `example.` is RFC 2606's reserved top-level name, so nothing in this
 * hierarchy can ever collide with a real delegation.
 */

/** P-256 (algorithm 13) private keys, in JWK form for WebCrypto import. */
export const DEMO_EC_KEYS = {
  rootKsk: { kty: 'EC', crv: 'P-256', d: '0Y-_x4o9NjrKRZbZhpbqr7aFgsJnAKwoA9xhBBniPoc', x: 'ZihV4b5d-UKN8_XaqrnIAmHDXcDojk2MUEcN3Tr6uvo', y: 'KIgQpWmtsRPnJeXSBguLG5XyY5LMH-ljuuFzBDDR8ys', ext: true },
  rootZsk: { kty: 'EC', crv: 'P-256', d: 'q5JVFLyGQv0Hu-PdyrBGmlfFzw9-oZM5NIE67YbLcns', x: 'gdTo5QUs8mUvZpaqjUBPpdoyETMeDSuYYGHEN6KrHH4', y: '7nVH0TdZfzZ5LUMv_RYWMOqNZryUWaAIDNflAh7Q1pE', ext: true },
  tldKsk: { kty: 'EC', crv: 'P-256', d: '8xgzf2DHM8lrhekytzYhjQQW7J66iCcAP1jKHQwi0bE', x: '4u6g5pLKESPU57jAI4N-b1iK_y5LR3hEERDEg7mzq08', y: 'yTxCjZDw0fEUkcvIX-wBytDm_cKhWW8N8VnLyi-K870', ext: true },
  tldZsk: { kty: 'EC', crv: 'P-256', d: '9WvdlYEwF9Mi8Bl_qmV40J388ikVoP-ehCLCgV0t3gc', x: '7pn4mK-ZdrEADQBHD5FBhKtb1aF529B7Q8cIiG8cqf8', y: '2uqTym5u4j1DVcQXBmwmA6OPUTVuIAaXVTvFPdVctLU', ext: true },
  zoneZsk: { kty: 'EC', crv: 'P-256', d: 'jvhol_U47QOVNpFDIvI23dBh0ja02TGS0_3yqGqYOPY', x: 'H-aIQ-Oek1VVKPLxvEiVl5oHwCUWDMQPw6hhU_kyCO8', y: 'arhAzyjNImEN6LUwa9n2Gfki5U4vCjnTRy70T-RBatQ', ext: true },
  /** The successor ZSK the rollover act pre-publishes and then activates. */
  zoneZskNext: { kty: 'EC', crv: 'P-256', d: 'Ruz80VJJfDYeHastt7vVEbpFWXPoetjAOeZ8sRnUYFY', x: 'sytMr7Pt85JDLfB4StolpljxUtZPkgc31aueuFN-UGU', y: 'Y02DgCDJKf8DSlnZ7GWeTYWBnLjH8ieW2md0ZOKT-Js', ext: true },
  /** Not in any zone: the key a learner signs with to forge an answer. */
  rogueKsk: { kty: 'EC', crv: 'P-256', d: 'mBmrcPWayyoj8fgrijB3BuWyPMjE74f4veGbSHRgJN0', x: 'GmVq3yQlVrR7fzWfRgLzwoiVffeFvP2rpSEIu69XV_8', y: '2RWMJp7mgcAmqup4KUAu132mE-xem8U1K5CvbfE4n30', ext: true },
} as const satisfies Record<string, JsonWebKey>;

/** Ed25519 (algorithm 15) seeds, hex. The child zone's KSK is Ed25519. */
export const DEMO_ED_SEEDS = {
  zoneKsk: '8139671b5198c5f861f852950ec8dea549f7a0a3ece5722032e76b84b51b22a2',
  rogueZsk: '96af9e694bfdee988ba87fea2709f69316289c38c5b19cec4bb664a6b724b5d5',
} as const;
