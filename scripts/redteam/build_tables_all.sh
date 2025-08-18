#!/usr/bin/env bash
set -euo pipefail
gen_table () {
  local in="$1" out_dir; out_dir="$(dirname "$in")"
  local out="$out_dir/services_table.md"
  {
    echo "| IP | Port/Proto | Service | Version |"
    echo "|---|---|---|---|"
    ip=""
    while IFS= read -r line; do
      if [[ "$line" =~ ^Nmap\ scan\ report\ for\  ]]; then
        last=$(awk '{print $NF}' <<<"$line")
        [[ "$last" =~ ^\(.+\)$ ]] && ip="${last:1:${#last}-2}" || ip="$last"
        continue
      fi
      if [[ "$line" =~ ^[0-9]+/tcp[[:space:]]+open[[:space:]]+ ]]; then
        portproto=$(awk '{print $1}' <<<"$line")
        service=$(awk '{print $3}' <<<"$line")
        version=$(sed -E 's/^[0-9]+\/tcp[[:space:]]+open[[:space:]]+[[:graph:]]+[[:space:]]*//' <<<"$line")
        [[ -z "$version" || "$version" == "$line" ]] && version="-"
        printf "| %s | %s | %s | %s |\n" "${ip:-unknown}" "$portproto" "$service" "$version"
      fi
    done < "$in" | sort -t'|' -k2,2
  } > "$out"
  echo "[+] Wrote $out"
}
found=0
while IFS= read -r -d '' f; do found=1; gen_table "$f"; done \
  < <(find phases -type f -path '*/redteam/tcp_services.nmap' -print0)
[[ $found -eq 0 ]] && echo "[i] No tcp_services.nmap files found (skip)"
