#!/usr/bin/env bash
set -euo pipefail
ARKIME_ENDPOINT="${ARKIME_ENDPOINT:-arkime.lab.local:8005}"
ES_ENDPOINT="${ES_ENDPOINT:-192.168.64.10:9200}"
OUTDIR="phases/01-foundation/devsecops/outputs"
mkdir -p "$OUTDIR"
testssl() { /usr/local/bin/testssl.sh --fast --quiet --jsonfile-pretty "$2" "$1" >"$3" 2>&1 || true; }
echo "[*] Testing TLS for $ARKIME_ENDPOINT and $ES_ENDPOINT"
testssl "$ARKIME_ENDPOINT" "$OUTDIR/testssl-arkime.json" "$OUTDIR/testssl-arkime.log"
testssl "$ES_ENDPOINT"     "$OUTDIR/testssl-es.json"     "$OUTDIR/testssl-es.log"
echo "[+] TLS evidence written to $OUTDIR"
