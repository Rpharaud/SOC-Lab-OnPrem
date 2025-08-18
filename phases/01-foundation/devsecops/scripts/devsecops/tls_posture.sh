#!/usr/bin/env bash
set -euo pipefail
ARKIME_ENDPOINT="${ARKIME_ENDPOINT:-arkime.lab.local:8005}"
ES_ENDPOINT="${ES_ENDPOINT:-192.168.64.10:9200}"
OUTDIR=".ci-outputs"; mkdir -p "$OUTDIR"
echo "[*] Testing TLS for $ARKIME_ENDPOINT and $ES_ENDPOINT"
run() { /usr/local/bin/testssl.sh --fast --quiet --jsonfile-pretty "$2" "$1" >"$3" 2>&1 || true; }
run "$ARKIME_ENDPOINT" "$OUTDIR/testssl-arkime.json" "$OUTDIR/testssl-arkime.log"
run "$ES_ENDPOINT"     "$OUTDIR/testssl-es.json"     "$OUTDIR/testssl-es.log"
echo "[+] TLS evidence -> $OUTDIR"
