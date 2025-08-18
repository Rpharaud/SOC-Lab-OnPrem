#!/usr/bin/env bash
set -euo pipefail
declare -A MAP=(
  ["Phase_1"]="01-foundation"
  ["Phase_1.5"]="01.5-edge-cases"
  ["Phase_2"]="02-tls-hardening"
  ["Phase_2.5"]="02.5-api-abuse"
  ["Phase_2.7"]="02.7-web3-osint"
)
ensure_phase(){ local s="$1"; for p in soc crypto redteam devsecops grc; do mkdir -p "phases/$s/$p"; done; }
gmv(){ if git ls-files --error-unmatch "$1" >/dev/null 2>&1; then git mv -k "$1" "$2"; else mv -n "$1" "$2"; fi; }

mkdir -p phases
for legacy in "${!MAP[@]}"; do
  [ -d "$legacy" ] || { echo "skip $legacy (not found)"; continue; }
  slug="${MAP[$legacy]}"; echo ">> $legacy -> phases/$slug/soc/legacy-import"
  ensure_phase "$slug"; mkdir -p "phases/$slug/soc/legacy-import"
  shopt -s dotglob nullglob
  for item in "$legacy"/*; do
    base=$(basename "$item")
    [ -e "phases/$slug/soc/legacy-import/$base" ] || gmv "$item" "phases/$slug/soc/legacy-import/"
  done
  # clean up empty legacy dir
  git rm -r "$legacy" 2>/dev/null || rmdir "$legacy" 2>/dev/null || true
done
echo "[✓] Layout rebuilt."
