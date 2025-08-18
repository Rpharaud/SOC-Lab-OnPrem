#!/usr/bin/env bash
set -euo pipefail

# Map legacy Phase_* → new slug
declare -A MAP=(
  ["Phase_1"]="01-foundation"
  ["Phase_1.5"]="01.5-edge-cases"
  ["Phase_2"]="02-tls-hardening"
  ["Phase_2.5"]="02.5-api-abuse"
  ["Phase_2.7"]="02.7-web3-osint"
)

# Where old Phase_* folders might live
LEGACY_ROOTS=( "." "archive/legacy-phases" )

# Create a phase skeleton with all pillars
ensure_phase() {
  local slug="$1"
  for pillar in soc crypto redteam devsecops grc; do
    mkdir -p "phases/$slug/$pillar"
  done
}

# Try git mv, else mv (preserve history when tracked)
gmv() {
  local src="$1" dst="$2"
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if git ls-files --error-unmatch "$src" >/dev/null 2>&1; then
      git mv -k "$src" "$dst" && return 0
    fi
  fi
  mv -n "$src" "$dst"
}

# Warn if working tree has staged/unstaged changes
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "[!] You have uncommitted changes. Consider 'git commit -m \"savepoint\"' first."
fi

mkdir -p phases

for legacy in "${!MAP[@]}"; do
  slug="${MAP[$legacy]}"
  found=""
  for root in "${LEGACY_ROOTS[@]}"; do
    src="$root/$legacy"
    [[ -d "$src" ]] || continue
    found="yes"

    echo "==> Phase '$legacy' → phases/$slug"
    ensure_phase "$slug"

    dest="phases/$slug/soc/legacy-import"
    mkdir -p "$dest"

    shopt -s dotglob nullglob
    items=("$src"/*)
    if ((${#items[@]}==0)); then
      echo "    (empty: $src)"
    else
      for item in "${items[@]}"; do
        base="$(basename "$item")"
        # skip self/empties
        [[ "$base" == "." || "$base" == ".." ]] && continue
        # avoid moving the entire phases/ tree into itself by mistake
        [[ "$item" == phases/* ]] && continue

        target="$dest/$base"
        if [[ -e "$target" ]]; then
          echo "    [skip] $base already exists in $dest"
        else
          echo "    moving: $item -> $dest/"
          gmv "$item" "$dest/"
        fi
      done
    fi
    # Remove empty legacy dir (git rm if possible)
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      git rm -r "$src" 2>/dev/null || rmdir "$src" 2>/dev/null || true
    else
      rmdir "$src" 2>/dev/null || true
    fi
  done
  [[ -z "$found" ]] && echo "==> Phase '$legacy' not found (skipping)"
done

echo "[✓] Rebuild complete. Preview:"
command -v tree >/dev/null 2>&1 && tree -L 3 phases || find phases -maxdepth 3 -type d -print

echo
echo "Next:"
echo "  git add -A && git commit -m \"Rebuild phases layout (SOC imported to soc/legacy-import)\" && git push"
