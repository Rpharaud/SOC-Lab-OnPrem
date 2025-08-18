# tools_bulk_phase_import.sh
set -euo pipefail

# Map old Phase_X names -> new slug directories
declare -A MAP=(
  ["Phase_1"]="01-foundation"
  ["Phase_1.5"]="01.5-edge-cases"
  ["Phase_2"]="02-tls-hardening"
  ["Phase_2.5"]="02.5-api-abuse"
  ["Phase_2.7"]="02.7-web3-osint"
  ["Phase_3"]="03-automation-kms"
  ["Phase_3.5"]="03.5-lab-monitoring"
  ["Phase_4"]="04-cloud-soc-aws"
  ["Phase_5"]="05-soar"
  ["Phase_5.5"]="05.5-honeypot-auto-flagger"
  ["Phase_6"]="06-threat-hunting"
  ["Phase_6.5"]="06.5-ml-detection"
  ["Phase_7"]="07-purple-team"
  ["Phase_8"]="08-dashboards-reporting"
  ["Phase_9"]="09-adversary-emulation"
  ["Phase_9.5"]="09.5-dfir-deepfake"
  ["Phase_9.6"]="09.6-mobile-security"
  ["Phase_10"]="10-stress-testing"
  ["Phase_11"]="11-residential"
  ["Phase_12"]="12-grc-finalization"
)

echo "[+] Creating unified phase structure…"
for old in "${!MAP[@]}"; do
  new="phases/${MAP[$old]}"
  mkdir -p "$new"/{soc,crypto,redteam,devsecops,grc}
  # Pillar README stubs (only create if missing)
  for p in soc crypto redteam devsecops grc; do
    f="$new/$p/README.md"
    [[ -f "$f" ]] || printf "# %s – %s\n\nAdd artifacts for this pillar here.\n" "${MAP[$old]}" "$p" > "$f"
  done
done

echo "[+] Importing legacy Phase_* folders if present…"
for old in "${!MAP[@]}"; do
  if [[ -d "$old" ]]; then
    dest="phases/${MAP[$old]}/legacy-import"
    mkdir -p "$dest"
    echo "    - Moving $old -> $dest"
    # Use git mv if possible to preserve history
    if command -v git >/dev/null 2>&1; then
      git mv "$old" "$dest" 2>/dev/null || mv "$old" "$dest"
    else
      mv "$old" "$dest"
    fi
  fi
done

echo "[+] Done. Review the tree under ./phases/"
