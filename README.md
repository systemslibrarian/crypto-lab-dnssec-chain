# DNSSEC Chain

Authenticated denial of existence, and the trust hierarchy it hangs off — in the browser, with real cryptography and a real captured chain.

**Live demo:** https://systemslibrarian.github.io/crypto-lab-dnssec-chain/

---

## What It Is

A browser demo of DNSSEC validation, built around the mechanism that makes DNSSEC unlike any other PKI: **it has to sign statements about names that do not exist.**

DNS is a second trust hierarchy, entirely separate from the X.509 world your browser uses for TLS. It shares no keys, no certificate authorities and no revocation machinery with it. Its root of trust is a small set of key fingerprints published by IANA and compiled into resolvers, and from there every zone vouches for its child by publishing a hash of the child's key. This lab validates that hierarchy for real, and then shows what its denial proofs give away.

**The exact primitives.**

| Piece | What it is | Where it is specified |
| --- | --- | --- |
| `DNSKEY` | A zone's public key, with a flags field distinguishing key-signing from zone-signing keys | RFC 4034 §2 |
| Key tag | A 16-bit checksum over the DNSKEY RDATA — a lookup hint, never an authenticator | RFC 4034 Appendix B, as corrected by [Errata 4552](https://www.rfc-editor.org/errata/eid4552) |
| `DS` | The parent's fingerprint of the child's key: `H(child apex ‖ DNSKEY RDATA)` | RFC 4034 §5.1.4 |
| `RRSIG` | A signature over `RRSIG_RDATA ‖ RR(1) ‖ RR(2) …` in canonical form | RFC 4034 §3.1.8.1, §6 |
| Canonical form | Down-cased owner names and the ORIGINAL TTL (§6.2, as corrected by RFC 6840 §5.1); RDATA sorted as unsigned octets (§6.3) | RFC 4034 §6.2, §6.3 |
| `NSEC` | Proof a name is absent, by naming the next name that is present | RFC 4034 §4, RFC 4035 §5.4 |
| `NSEC3` | The same chain over SHA-1 hashes of the names, with a salt and an iteration count | RFC 5155 |
| Opt-Out | An NSEC3 flag letting a signer skip unsigned delegations entirely | RFC 5155 §6 |
| Minimally covering NSEC | Denial synthesized per query, with an online signing key | RFC 4470 (Standards Track) |
| Validator outcomes | Secure · Insecure · Bogus · Indeterminate | RFC 4033 §5, RFC 4035 §5 |
| Rollover | Pre-publish and double-signature key replacement | RFC 6781 §4.1.1.1, §4.1.1.2 |

**The algorithms.** RSASHA256 (8) and ECDSAP256SHA256 (13) are verified with WebCrypto; ED25519 (15) with [`@noble/curves`](https://github.com/paulmillr/noble-curves). Algorithm 8 is implemented because **the DNS root signs with it** — without it, the pinned real-world chain could not be validated from its own trust anchor, and the lab would be teaching against a chain it had quietly replaced. Every other real DNSSEC algorithm is reported as `ALG_UNSUPPORTED` — a statement about this validator, never a forgery accusation. Ed25519 comes from a library rather than WebCrypto because WebCrypto's Ed25519 support arrived late and is still not present in every browser a learner might open this page in.

**The security model.** DNSSEC gives you **origin authentication and data integrity** for DNS records, and nothing else. It does not encrypt anything, it does not tell you whether an answer is the one you wanted, and it does not vouch for the honesty of the zone operator. A `SECURE` verdict here means exactly: *these records verified under these keys at this instant, along an unbroken chain from a configured anchor.*

**Not production crypto — a teaching demo.** The cryptography is genuine and the known-answer tests are the specifications' own, but nothing here is a resolver. There is no caching, no network, no transport security, no query minimisation, and no attempt at the operational hardening a real validator needs.

**Prior art and correct citations.** Three of the citations most often attached to this subject are wrong, and this lab names them rather than repeating them:

- **RFC 8901 is not a reference for enumeration defences.** It specifies multi-signer DNSSEC models — running one zone across several DNS providers — and touches enumeration only in two passing sentences that point elsewhere for the definitions. The correct anchors are **RFC 5155** (NSEC3, normative; §12.1.1 is its own account of dictionary attacks), **RFC 4470** (minimally covering NSEC and on-line signing, Standards Track, April 2006), **RFC 7129** (authenticated denial of existence; Informational, Independent Submission, February 2014 — its Appendix B is where "NSEC3 white lies" is defined) and **RFC 9276** (BCP 236, August 2022, the NSEC3 parameter guidance).
- **"NSEC black lies" has no RFC.** The NODATA-style synthesized denial the sixth exhibit captures is specified only in an Internet-Draft, `draft-valsorda-dnsop-black-lies`. The published anchor for the technique it derives from is RFC 4470.
- **RFC 8080's published Section 6 does not verify.** Its Ed25519 examples print `RRSIG MX 3 3600 …` with the algorithm field missing, and the accompanying signatures do not check out. This repository uses the text from **Verified Errata 4935** (Tom Thorogood, verified 2017-02-16) instead; the correction is flagged at the top of `src/vectors/rfc.ts`. Taking the published text at face value would have produced a test that "proved" the Ed25519 path by failing to parse it.

---

## Exhibits

1. **Build the chain** — the pinned real-world chain, root zone → `.com` → `cloudflare.com` → an A record, each link checked on its own. The trust anchors are IANA's published root KSK fingerprints; the digest the page computes from the DNSKEY records the root actually served is shown beside the digest IANA publishes. A clock control moves the validation instant forward and backward, because DNSSEC validity is wall-clock and a bad clock is a real outage.
2. **Break each link** — nine states against a hierarchy signed in the page, with real keys. Each break is made by **signing something wrong and re-signing the zone**, not by corrupting bytes, so a stale DS fingerprint reports `DS_MISMATCH` rather than a generic signature failure. The unsupported-algorithm case is not synthesized at all: it runs RFC 6605's own ECDSA P-384 example, a real and valid signature this lab does not implement.
3. **No DS: insecure** — `.com`'s real answer for `google.com`, an unsigned domain, resting on an Opt-Out NSEC3. The chain reaches `.com`, verifies, and correctly **ends**. Beside it, the same delegation with the proof removed as well, which is `BOGUS`. The distinction is routinely got backwards and it is not a nuance: `INSECURE` is a normal answer a resolver returns, `BOGUS` is a `SERVFAIL`.
4. **Walk the zone** — the headline mechanism. Each button press sends one ordinary query for a type nothing in the zone has, gets back one genuinely valid signed denial, and reads the next existing name out of it. Repeat and the zone falls out; the ring closes when the chain wraps back to the apex, which is the proof nothing was missed. Switch the zone to twelve-random-character labels and the walk recovers them exactly as completely — the record *names* them. A second control offers a valid NSEC as proof for a name it does not cover, and watches the validator reject it.
5. **NSEC3 guessing** — the same attack run twice on the same construction, varying only whether the names are guessable. Reports a **recovery rate against a stated candidate list** rather than a verdict. Controls for iterations (0–150) and salt let you check RFC 9276's claim yourself: the recovered set is identical at 150 iterations, for 151× the work.
6. **Denial on demand** — the captured Cloudflare answer for a name that does not exist, which is `NOERROR` with an NSEC whose next owner is the queried name with a single NUL octet prepended: RFC 4470's increment function applied to the query. Nothing to walk to — at the price of a signing key on an internet-facing server.
7. **Key rollover** — pre-publish and double-signature, every intermediate state validated, plus the failure that actually takes domains offline: a resolver's cached DS outliving the key it points at.

---

## When to Use It

**Use DNSSEC when** you need the *origin* of DNS data authenticated: to make DANE/TLSA records meaningful, to stop cache-poisoning and off-path spoofing, to let a resolver reject forged answers rather than trust whoever replied first, or to publish anything (SSHFP, OPENPGPKEY, a DS for a child) whose whole value depends on it not having been substituted.

**Use NSEC3 when** you are signing offline and can tolerate an offline guessing problem in place of a trivial walk — and follow RFC 9276: `1 0 0 -`, meaning SHA-1, no extra iterations, no salt. Anything more costs your own servers far more than it costs an attacker.

**Use minimally covering denial (RFC 4470) when** enumeration genuinely matters and you can accept an online signing key and a signature per denial.

**Do NOT use DNSSEC for confidentiality.** It provides none. Queries and answers travel in the clear whether or not they validate — that is what DNS-over-HTTPS, DNS-over-TLS and DNS-over-QUIC are for, and they are orthogonal mechanisms solving a different problem.

**Do NOT rely on NSEC3 to hide internal hostnames.** Publishing `vpn-admin.internal.example.com` in a signed zone and assuming the hashing conceals it is the mistake this lab's fifth exhibit exists to make concrete. Hashes are handed out on request, the parameters come with them, and predictable labels fall to an ordinary wordlist.

**Do NOT read `INSECURE` as an attack.** Most of the DNS is unsigned. Treating a correctly-proved unsigned delegation as a failure trains people to ignore the real ones.

---

## Live Demo

https://systemslibrarian.github.io/crypto-lab-dnssec-chain/

Everything runs in your browser. There is no backend, nothing is sent anywhere, and no DNS query is made at run time — the real-world chain is a capture committed to this repository. Things you can do:

- Validate the real root → `.com` → `cloudflare.com` chain and open each link's actual compared bytes.
- Move the validation clock past every expiration and watch the chain go `BOGUS` with a named cause.
- Break a delegation eight different ways and watch the validator name each cause specifically — seven distinct codes, because two of the eight are genuinely the same failure arrived at from opposite ends (a DS pointing at a key the child never had, and a child that stopped using the key the DS points at).
- Enumerate a signed zone one query at a time, from its denial proofs alone.
- Run a dictionary attack against the same zone's NSEC3 hashes, twice, and compare the recovery rates.

---

## What Can Go Wrong

The failure modes this lab reproduces, and what each one actually is in the wild:

| Failure | What happened | Real-world cause |
| --- | --- | --- |
| `DS_MISMATCH` | The parent's fingerprint does not hash to the key the child served | A key was rolled and the DS at the registrar was not updated. The most common way a real domain goes dark. |
| `RRSIG_EXPIRED` | The signature's expiration is behind the validator's clock | A re-signing job stopped running, or a zone was frozen. Nothing is wrong with the maths. |
| `RRSIG_NOT_YET_VALID` | The inception is ahead of the validator's clock | Usually the *validator's* clock, not the zone's. A device with no working time source cannot validate DNSSEC at all. |
| `KEYTAG_MISMATCH` | No key in the zone claims to be the signer | A DS pointing at a removed key, or a resolver holding a cached DS from before a KSK roll. |
| `SIGNER_NAME_MISMATCH` | A neighbouring zone signed these records | Rejecting this is what stops any zone speaking for any other. |
| `SIGNATURE_INVALID` | The bytes offered are not the bytes signed | An on-path attacker rewriting an answer — the only entry here that is genuinely an attack rather than an operational mistake. |
| `NSEC_PROOF_INVALID` | The denial does not span the name it claims to deny | A validator that skipped the interval check would accept a forged NXDOMAIN built from any valid NSEC in the zone. |
| `ALG_UNSUPPORTED` | This validator cannot judge a real algorithm | Reported separately, and deliberately: reporting it as a forgery blames the zone for the validator's gap. |
| `INSECURE` | The parent proved there is no DS | **Not a failure.** The chain ended legitimately. |

Three that are subtler, and are called out in the page rather than smoothed over:

- **Opt-Out weakens what a covering NSEC3 proves.** With the flag set, an unsigned delegation may sit inside a covered gap with no record of its own. That is what keeps `.com`'s NSEC3 chain proportional to the number of *signed* domains — and it means a covering record proves less than it appears to.
- **Online signing trades one risk for another.** Minimally covering denial removes the enumeration problem by putting a private key on an internet-facing server and making every denial a signature operation. That is the property offline signing existed to avoid, and it makes a query-flood into a signature-flood.
- **The wildcard half of an NXDOMAIN proof is not optional.** A denial that shows only a covering NSEC, without also showing that no wildcard could have answered, lets an attacker turn a real wildcard answer into a forged NXDOMAIN. This lab checks both halves and shows both.

---

## Real-World Usage

The root zone has been signed since July 2010. `.com` and `.net` are signed and, since Verisign's migration, sign with ECDSA P-256 (algorithm 13) — you can read both facts straight off the capture in `src/vectors/pinned-chain.txt`. Sweden's `.se` was the first signed TLD (2005); most ccTLDs and all new gTLDs are signed today. Second-level adoption is far patchier, which is exactly why `INSECURE` is the normal outcome rather than an exceptional one.

The techniques this lab shows are all deployed:

- **Zone walking** is why NSEC3 exists at all; RFC 7129 §3.4 describes it as defeating attempts to administratively block zone transfers.
- **NSEC3 with Opt-Out** is what the large TLDs use, for the reason above.
- **Minimally covering denial** is deployed at scale by Cloudflare — the capture in this repository is a real one — and is why a nonexistent name under `cloudflare.com` answers `NOERROR` rather than `NXDOMAIN`.
- **RFC 9276's guidance** (zero iterations, no salt) came out of measurements showing that high iteration counts were a denial-of-service vector against the servers using them, with no meaningful gain against enumeration.
- **KSK rollover** was performed on the root itself in October 2018, moving from KSK-2010 to KSK-2017 — an operation planned over years precisely because of the cached-DS problem the seventh exhibit reproduces. The current anchors, both in this repository and in your resolver, are KSK-2017 (tag 20326) and KSK-2024 (tag 38696).

---

## How to Run Locally

```bash
npm install
npm run dev        # http://localhost:5173/crypto-lab-dnssec-chain/
```

```bash
npm test           # unit + known-answer tests (Vitest)
npm run build      # typecheck (src and e2e) + production build
npm run test:a11y  # axe WCAG 2.1 A/AA gate against the production build
npm run test:claims # the page-tells-the-truth suite
```

The Playwright suites need a browser once:

```bash
npx playwright install chromium
```

To re-take the real-world capture (it is committed, and the lab validates it at the instant it was taken, so this is never necessary — only useful if you want a fresher one):

```bash
npm run capture    # scripts/capture-chain.sh -> src/vectors/pinned-chain.txt
```

---

## Related Demos

- **[PKI Chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/)** — the *other* trust hierarchy. X.509 certificate chains, trust stores and Certificate Transparency. Reading the two side by side is the point: same idea, entirely disjoint infrastructure, and DNSSEC's hierarchy is the one that answers first.
- **[Chain of Trust](https://systemslibrarian.github.io/crypto-lab-chain-of-trust/)** — the general shape of delegated trust, without the DNS specifics.
- **[Time Trust](https://systemslibrarian.github.io/crypto-lab-time-trust/)** — why a wrong clock is a security failure. `RRSIG_NOT_YET_VALID` in the second exhibit is that lab's thesis with a DNS accent.
- **[Merkle Proofs](https://systemslibrarian.github.io/crypto-lab-merkle-proofs/)** and **[Accumulator](https://systemslibrarian.github.io/crypto-lab-accumulator/)** — the other ways to prove *non*-membership. An accumulator answers "not in the set" with a constant-size proof; NSEC answers it by naming the neighbours, and that difference is the whole of the fourth exhibit.
- **[Blind Hello](https://systemslibrarian.github.io/crypto-lab-blind-hello/)** — Encrypted ClientHello. The honest cross-link, stated on this page too: RFC 9849 §10.2 specifies that ECH delivers its configuration through SVCB/HTTPS records *without requiring any verifiable authenticity or provenance information*, and names DNSSEC and encrypted DNS transport as two separate defences against DNS tampering. DNSSEC is an available protection for the ECHConfig, **not** the source of ECH's authenticity — that comes from the TLS certificate for the configuration's public name.

---

## Build & Verify

**132 unit tests pass** (Vitest), across six files. The ones that decide whether anything else means something:

- `src/dnssec/kat.test.ts` — **38 known-answer tests against the specifications.** Key tags from RFC 4034 §5.4 (60485), RFC 6605 (55648, 10771), RFC 8080 (3613, 35217, 9713) and RFC 5155 Appendix A (40430, 12708). DS digests in SHA-1, SHA-256 and SHA-384 from those same sections. All twelve hashed owner names from RFC 5155 Appendix A, plus coverage and wrap-around against three NSEC3 records from that same appendix. And the three that exercise the whole canonicalisation pipeline at once: **RFC 6605 §6.1's ECDSA P-256 signature and both of RFC 8080 §6.1's Ed25519 signatures verify** over signed data this repository assembles from scratch — one wrong TTL, one label left uppercase or one RDATA out of order and none of them would.
- `src/dnssec/realworld.test.ts` — **19 tests against the pinned capture.** The full root → `.com` → `cloudflare.com` chain validates from IANA's anchors, across two signing algorithms; the key tags and DS digests this repository computes from the root's served DNSKEY records reproduce the digests IANA publishes; `.com`'s real Opt-Out proof for `google.com` reaches `INSECURE`; and Cloudflare's synthesized denial is checked to be what it claims to be.
- `src/dnssec/downgrade.test.ts` — **18 tests that attack the CLASSIFICATION rather than the cryptography.** None of them forges a signature; each tries to make the validator reach a weaker verdict than the evidence supports. Two unrelated Ed25519 keys with a deliberately collided key tag (found in 406 tries — a tag is a 16-bit checksum) are published side by side and the DNSKEY set is signed with the wrong one; a denial from one zone is offered for a name in another; a child's own apex record is offered as proof that its delegation is unsigned; an unsigned no-DS proof is offered to end a chain at `INSECURE`. Every one is rejected, and the reason is checked.
- `src/zone/demo.test.ts` — 24 tests over a hierarchy signed in-process: every RRset it signs is verified back cryptographically (including the whole NSEC chain), a wildcard answer is signed and re-verified through the Labels reconstruction, every named failure, both `INSECURE` shapes, both denial styles, and all four rollover stages.
- `src/attack/attack.test.ts` — 13 tests pinning the two enumeration results, including that 150 extra NSEC3 iterations recover *exactly the same set* for 151× the hashing.
- `src/dns/name.test.ts` — 20 tests on names and character-strings, including the canonical-order example printed in RFC 4034 §6.1 and the `\DDD` escape rule from RFC 1035 §5.1.

**Vector files.** `src/vectors/rfc.ts` (RFC 4034 §5.4, RFC 5155 Appendix A, RFC 6605 §6.1–6.2, RFC 8080 §6.1–6.2 with errata 4935 applied, plus IANA's root anchors), `src/vectors/pinned-chain.txt` (the `dig` capture, verbatim), `src/vectors/root-anchors.xml` (as fetched from `data.iana.org`), `src/vectors/demo-keys.ts` (published teaching keys).

**The accessibility gate.** `npm run build && npm run test:a11y` must pass with zero violations. It scans the *production build* served by `vite preview`, driving the real controls through about fifty states — every panel, every break, every rollover stage, the walk at zero/one/complete, the dictionary run on both label sets, every disclosure, three hover states and two focus rings — at 1280px and again at 380px. It asserts axe's `incomplete` bucket as well as its `violations` array, computes contrast arithmetically over composited backdrops (including `aria-hidden` text, which both axe and the default walk skip), measures WCAG 1.4.11 non-text contrast per border side against a ratchet baseline that is **empty**, and checks reflow, keyboard-reachable scrollers and focusable-but-invisible controls — none of which axe has a rule for. It found **three real defects** in its first three runs — an `aria-label` on a role-less `<pre>` (which axe files under `incomplete`, where a violations-only gate never looks), an explicit `role="list"` on a list that can render empty, and a WCAG 1.4.10 reflow failure at 380px caused by a missing `box-sizing` reset. All three are fixed in the source; the baseline is empty.

It has also been mutation-checked itself, which is the only way to know a gate is looking: degrading `--text-dim` from 10.7:1 to 1.9:1 makes it fail with **153 named findings across the drive** — each giving the measured ratio, the required ratio, the element, the composited foreground and background, and the text — while the build still succeeds and the bundle hash changes. A gate that stayed green there would be worth nothing.

**The claims suite.** `npm run test:claims` checks that the page tells the truth: the walk transcript is re-linked from the rendered text alone, the digest the page computes is compared against the digest IANA publishes, the signed-octet runs are summed and checked against the total the signature line states, every break is checked to produce the failure its own description promised, and the two negative claims — no confidentiality, and no ECH dependency — are checked against evidence the page itself supplies.

**Mutation-checked.** A green suite is not evidence until it has been watched failing. Eleven one-line inversions were applied to `src/`, one at a time — the key tag's alternating shift; the canonical RDATA sort reversed; the NSEC3 iteration count off by one; the NSEC wrap interval's `||` turned into `&&`; the bailiwick guard removed from each of the two provers where it is the only thing standing in the way; the DS-to-signer binding put back to comparing tags; the NSEC3 no-DS SOA condition dropped; the no-DS signature check skipped; `checkDenial` reading the zone file instead of the response; and the unsupported-DS-algorithm branch disabled. Every one produced a **successful build with a changed bundle hash** (a mutation that breaks `tsc` proves nothing — the suite would run against the last good bundle) and a **failing test**, and the hash returned to its pre-mutation value on restore.

Two of those started green, which is the point of doing it: the NSEC wrap branch and the bailiwick guards had no test that reached them. Both now have one — a name sorting past the end of the zone, which only the wrapping record can cover, and a foreign zone's record that matches the query perfectly and must still be refused.

---

## Performance

Signing the in-page hierarchy takes roughly 100–300 ms — three zones, around thirty RRsets, real ECDSA P-256 and Ed25519 signatures over each. The zone walk is one local query per name and completes instantly. The NSEC3 dictionary run is the only long operation: 1,329 candidates at 0 iterations is about 1,300 SHA-1 invocations and finishes in a frame; at 150 iterations it is roughly 200,000, which is why it runs in slices with the progress reported honestly rather than behind a spinner. Production bundle: 166 kB, 60 kB gzipped.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
