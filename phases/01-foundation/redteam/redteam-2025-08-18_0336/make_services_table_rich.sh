#!/usr/bin/env bash
set -euo pipefail

IN="tcp_services.nmap"
OUT="services_table.md"

if [[ ! -f "$IN" ]]; then
  echo "[-] $IN not found. Run your nmap service scan first." >&2
  exit 1
fi

{
  echo "| IP | Port/Proto | Service | Version |"
  echo "|---|---|---|---|"

  ip=""
  while IFS= read -r line; do
    # Detect host header lines like:
    # "Nmap scan report for regserver (192.168.64.10)"
    # or "Nmap scan report for 192.168.64.10"
    if [[ "$line" =~ ^Nmap\ scan\ report\ for\  ]]; then
      lastfield=$(echo "$line" | awk '{print $NF}')
      if [[ "$lastfield" =~ ^\(.+\)$ ]]; then
        ip="${lastfield:1:${#lastfield}-2}"     # strip parentheses
      else
        ip="$lastfield"
      fi
      continue
    fi

    # Match open TCP service lines, e.g.:
    # "22/tcp   open  ssh          OpenSSH 9.6p1 Ubuntu ..."
    if [[ "$line" =~ ^[0-9]+/tcp[[:space:]]+open[[:space:]]+ ]]; then
      portproto=$(echo "$line" | awk '{print $1}')
      service=$(echo "$line" | awk '{print $3}')
      # The version is everything after column 3; may be empty
      version=$(echo "$line" | sed -E 's/^[0-9]+\/tcp[[:space:]]+open[[:space:]]+[[:graph:]]+[[:space:]]*//')
      if [[ -z "$version" || "$version" == "$line" ]]; then
        version="-"
      fi
      printf "| %s | %s | %s | %s |\n" "${ip:-unknown}" "$portproto" "$service" "$version"
    fi
  done < "$IN" | sort -t'|' -k2,2

} > "$OUT"

echo "[+] Wrote $OUT"
