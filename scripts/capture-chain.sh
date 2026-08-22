#!/usr/bin/env bash
# Capture a real DNSSEC chain, verbatim, straight from the authoritative
# servers, into src/vectors/pinned-chain.txt.
#
# Run by hand, never at page load. The demo validates the captured RRSIGs at
# the PINNED capture instant recorded in the header below, which is why the
# file keeps working long after those signatures expire in the real world --
# and why moving the clock is a first-class act in the lab rather than a bug.
#
# Every query is +norec against the server that is authoritative for the data,
# so what lands here is what that server signed, not a resolver's rendering.
set -euo pipefail
out="$(dirname "$0")/../src/vectors/pinned-chain.txt"
mkdir -p "$(dirname "$out")"

ROOT=a.root-servers.net
GTLD=a.gtld-servers.net
CFNS=ns3.cloudflare.com

q() { # q <label> <server> <name> <type>
  printf '\n;; ==== %s ====\n' "$1"
  printf ';; dig +dnssec +norec @%s %s %s\n' "$2" "$3" "$4"
  dig +dnssec +norec +noall +comments +answer +authority "@$2" "$3" "$4" \
    | grep -vE '^;; (Query time|SERVER|WHEN|MSG SIZE|;)' \
    | sed -e 's/[[:space:]]*$//' \
    | cat -s
}

{
  printf ';; PINNED DNSSEC CHAIN -- captured %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf ';; capture-unixtime %s\n' "$(date -u +%s)"
  printf ';; Captured by scripts/capture-chain.sh. Committed on purpose: the lab\n'
  printf ';; never queries DNS at runtime. Validate against the pinned instant above.\n'
  q 'root-dnskey'            "$ROOT" '.'                'DNSKEY'
  q 'root-ds-for-com'        "$ROOT" 'com.'             'DS'
  q 'com-dnskey'             "$GTLD" 'com.'             'DNSKEY'
  q 'com-ds-for-cloudflare'  "$GTLD" 'cloudflare.com.'  'DS'
  q 'cloudflare-dnskey'      "$CFNS" 'cloudflare.com.'  'DNSKEY'
  q 'cloudflare-a'           "$CFNS" 'cloudflare.com.'  'A'
  q 'cloudflare-nxdomain'    "$CFNS" 'no-such-name-9x7q.cloudflare.com.' 'A'
  q 'com-ds-for-google-none' "$GTLD" 'google.com.'      'DS'
} > "$out"
echo "wrote $out ($(wc -l < "$out") lines)"
