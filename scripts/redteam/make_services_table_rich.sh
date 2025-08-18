#!/usr/bin/env bash
set -euo pipefail
IN="phases/01-foundation/redteam/tcp_services.nmap"
OUT="services_table.md"
[[ -f "$IN" ]] || { echo "[-] $IN not found"; exit 1; }
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
  done < "$IN" | sort -t'|' -k2,2
} > "$OUT"
