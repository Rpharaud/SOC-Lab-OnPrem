#!/usr/bin/env bash
set -euo pipefail
fail=0
dir="phases/01-foundation/grc"
need=(scope.md baseline_policy.md control_mapping.md raci.md risk_register.csv)
missing=()
for f in "${need[@]}"; do [[ -f "$dir/$f" ]] || missing+=("$f"); done
if (( ${#missing[@]} )); then
  echo "[-] Missing Phase 1 GRC docs: ${missing[*]}"; fail=1
fi
if [[ -f "$dir/risk_register.csv" ]]; then
  head -n1 "$dir/risk_register.csv" | grep -q '^risk_id,description,likelihood,impact,owner,treatment,status,notes$' \
    || { echo "[-] risk_register.csv header incorrect"; fail=1; }
fi
echo "[=] GRC checks complete"; exit $fail
