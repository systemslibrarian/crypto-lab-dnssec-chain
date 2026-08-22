/**
 * Known-answer vectors, quoted from the specifications.
 *
 * Each block is the example as its RFC prints it, with the base64 and hex runs
 * joined onto one line (the line breaks are presentation wrapping, not data)
 * and nothing else changed. They are parsed by the same master-file reader the
 * lab uses on `dig` output, so a vector that fails here fails for the same
 * reason a real answer would.
 *
 * ONE CORRECTION IS APPLIED, AND IT IS FLAGGED. RFC 8080's published Section 6
 * prints its RRSIG records as `RRSIG MX 3 3600 ...` — the algorithm field is
 * missing, so `3` reads as the algorithm and `3600` as the label count — and
 * the signature base64 alongside it does not verify. Verified Errata 4935
 * (Tom Thorogood, verified 2017-02-16) supplies the corrected records:
 * `RRSIG MX 15 2 3600 ...` with different signatures. This file uses the
 * errata text. Taking the published text at face value would have produced a
 * test that "proved" the Ed25519 path by failing to parse it.
 */

// ── RFC 4034 section 5.4 — DNSKEY and its DS ────────────────────────────────
// Algorithm 5 (RSA/SHA-1) with digest type 1 (SHA-1). Neither is implemented
// for verification here, and neither needs to be: the key tag and the DS
// digest are computed over bytes, independent of the signing algorithm, so
// this vector exercises exactly the two pieces it can.

export const RFC4034_DSKEY = `
dskey.example.com. 86400 IN DNSKEY 256 3 5 AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==
dskey.example.com. 86400 IN DS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118
`;

/** The RFC's own comment on the DNSKEY: `; key id = 60485`. */
export const RFC4034_DSKEY_TAG = 60485;

// ── RFC 6605 section 6.1 — ECDSA P-256, algorithm 13 ────────────────────────
// The signature vector: `www.example.net.`'s A RRset, its RRSIG, and the
// zone's DNSKEY. Verifying it end to end proves the signed-data construction
// byte for byte — get the original TTL, the canonical owner name, the RDATA
// ordering or the RRSIG prefix wrong by one octet and it fails.

export const RFC6605_P256 = `
example.net. 3600 IN DNSKEY 257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==
example.net. 3600 IN DS 55648 13 2 b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17
www.example.net. 3600 IN A 192.0.2.1
www.example.net. 3600 IN RRSIG A 13 3 3600 20100909100439 20100812100439 55648 example.net. qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==
`;

export const RFC6605_P256_TAG = 55648;

// ── RFC 6605 section 6.2 — ECDSA P-384, algorithm 14 ────────────────────────
// Algorithm 14 is NOT implemented here, which makes this vector do double
// duty: its key tag and its SHA-384 DS digest must both come out right, and
// its RRSIG must be reported as ALG_UNSUPPORTED rather than as a forgery.

export const RFC6605_P384 = `
example.net. 3600 IN DNSKEY 257 3 14 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40
example.net. 3600 IN DS 10771 14 4 72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6
www.example.net. 3600 IN A 192.0.2.1
www.example.net. 3600 IN RRSIG A 14 3 3600 20100909102025 20100812102025 10771 example.net. /L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm
`;

export const RFC6605_P384_TAG = 10771;

// ── RFC 8080 section 6.1 — Ed25519, algorithm 15 (ERRATA 4935 APPLIED) ──────

export const RFC8080_ED25519_1 = `
example.com. 3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=
example.com. 3600 IN DS 3613 15 2 3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b
example.com. 3600 IN MX 10 mail.example.com.
example.com. 3600 IN RRSIG MX 15 2 3600 1440021600 1438207200 3613 example.com. oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==
`;

export const RFC8080_ED25519_1_TAG = 3613;

export const RFC8080_ED25519_2 = `
example.com. 3600 IN DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=
example.com. 3600 IN DS 35217 15 2 401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c
example.com. 3600 IN MX 10 mail.example.com.
example.com. 3600 IN RRSIG MX 15 2 3600 1440021600 1438207200 35217 example.com. zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT410QPRITQSqJSnzQoSm5poJ7gD7AQR0O7KuI5k2pcBg==
`;

export const RFC8080_ED25519_2_TAG = 35217;

/**
 * RFC 8080 section 6.2 — Ed448, algorithm 16. Not implemented here. Present
 * because the DS digests still have to come out right, and because a validator
 * must be able to say "I cannot judge this" about a perfectly valid zone.
 */
export const RFC8080_ED448 = `
example.com. 3600 IN DNSKEY 257 3 16 3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA
example.com. 3600 IN DS 9713 16 2 6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2b19c7
`;

export const RFC8080_ED448_TAG = 9713;

// ── RFC 5155 Appendix A — the NSEC3 example zone ────────────────────────────

/**
 * The zone's parameters, from its NSEC3PARAM: SHA-1, flags 0, 12 iterations,
 * salt `aabbccdd`.
 */
export const RFC5155_PARAMS = { hashAlgorithm: 1, iterations: 12, saltHex: 'aabbccdd' } as const;

/**
 * The hashed owner names RFC 5155 Appendix A lists ahead of the zone, quoted
 * verbatim. The RFC introduces them as usable test vectors for the hash, which
 * is exactly what they are used for here.
 *
 * The last entry is the interesting one: hashing an owner name that is ITSELF
 * a base32hex hash label. It is in the RFC because it catches an implementation
 * that hashes the presentation TEXT of a name instead of its wire form.
 */
export const RFC5155_HASHES: readonly (readonly [string, string])[] = [
  ['example.', '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom'],
  ['a.example.', '35mthgpgcu1qg68fab165klnsnk3dpvl'],
  ['ai.example.', 'gjeqe526plbf1g8mklp59enfd789njgi'],
  ['ns1.example.', '2t7b4g4vsa5smi47k61mv5bv1a22bojr'],
  ['ns2.example.', 'q04jkcevqvmu85r014c7dkba38o0ji5r'],
  ['w.example.', 'k8udemvp1j2f7eg6jebps17vp3n8i58h'],
  ['*.w.example.', 'r53bq7cc2uvmubfu5ocmm6pers9tk9en'],
  ['x.w.example.', 'b4um86eghhds6nea196smvmlo4ors995'],
  ['y.w.example.', 'ji6neoaepv8b5o6k4ev33abha8ht9fgc'],
  ['x.y.w.example.', '2vptu5timamqttgl4luu9kg21e0aor3s'],
  ['xx.example.', 't644ebqk9bibcna874givr6joj62mlhv'],
  ['2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.', 'kohar7mbb8dc2ce8a9qvl8hon4k53uhi'],
];

/**
 * Two DNSKEYs from the same appendix, whose tags are pinned by the RRSIGs in
 * the zone: the ZSK signs everything at tag 40430, the KSK signs the DNSKEY
 * RRset at tag 12708.
 */
export const RFC5155_KEYS = `
example. 3600 IN DNSKEY 256 3 7 AwEAAaetidLzsKWUt4swWR8yu0wPHPiUi8LUsAD0QPWU+wzt89epO6tHzkMBVDkC7qphQO2hTY4hHn9npWFRw5BYubE=
example. 3600 IN DNSKEY 257 3 7 AwEAAcUlFV1vhmqx6NSOUOq2R/dsR7Xm3upJj7IommWSpJABVfW8Q0rOvXdM6kzt+TAu92L9AbsUdblMFin8CVF3n4s=
`;

export const RFC5155_ZSK_TAG = 40430;
export const RFC5155_KSK_TAG = 12708;

/**
 * An NSEC3 chain excerpt from the same appendix, used to exercise coverage and
 * the wrap-around at the end of the ring.
 */
export const RFC5155_NSEC3 = `
0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 3600 IN NSEC3 1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG
2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 3600 IN NSEC3 1 1 12 aabbccdd 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG
2vptu5timamqttgl4luu9kg21e0aor3s.example. 3600 IN NSEC3 1 1 12 aabbccdd 35mthgpgcu1qg68fab165klnsnk3dpvl MX RRSIG
`;

// ── IANA root trust anchors ─────────────────────────────────────────────────

/**
 * The two live root KSK trust anchors, transcribed from
 * `src/vectors/root-anchors.xml` (fetched from data.iana.org). These are the
 * real anchors a validating resolver ships with, and the digests here are the
 * ones IANA publishes — so hashing the DNSKEY records in the pinned capture
 * and getting these values back is a known-answer test whose answer key is
 * maintained by somebody else entirely.
 */
export interface TrustAnchor {
  readonly id: string;
  readonly zone: string;
  readonly keyTag: number;
  readonly algorithm: number;
  readonly digestType: number;
  readonly digestHex: string;
  readonly validFrom: string;
  readonly label: string;
}

export const ROOT_TRUST_ANCHORS: readonly TrustAnchor[] = [
  {
    id: 'Klajeyz',
    zone: '.',
    keyTag: 20326,
    algorithm: 8,
    digestType: 2,
    digestHex: 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
    validFrom: '2017-02-02',
    label: 'KSK-2017',
  },
  {
    id: 'Kmyv6jo',
    zone: '.',
    keyTag: 38696,
    algorithm: 8,
    digestType: 2,
    digestHex: '683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16',
    validFrom: '2024-07-18',
    label: 'KSK-2024',
  },
];
