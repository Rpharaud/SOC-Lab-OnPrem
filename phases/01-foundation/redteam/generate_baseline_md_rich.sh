# generate_baseline_md_rich.sh
set -euo pipefail
LAB_NET="${LAB_NET:-192.168.64.0/24}"
SCANNER_IP="$(hostname -I | awk '{print $1}')"
DATE="$(date +%F)"

OUT="baseline_attack_surface.md"

{
  echo "# Phase 1 – Red Team Baseline Attack Surface"
  echo "_Date: ${DATE}_  "
  echo "_Subnet(s): ${LAB_NET}_  "
  echo "_Scanner: ${SCANNER_IP}_  "
  echo
  echo "## Targets discovered"
  if [[ -s targets.txt ]]; then
    awk '{print "- " $0}' targets.txt
  else
    echo "- (none)"
  fi
  echo
  echo "## Service inventory (open TCP only)"
  if [[ -f services_table.md ]]; then
    cat services_table.md
  else
    echo "_(Run \`bash make_services_table.sh\` to generate the table from tcp_services.gnmap.)_"
  fi
  echo
  echo "## High-level findings"
  echo "- Arkime (8005/tcp) is **HTTPS** with lab PKI (Digest auth)."
  echo "- Elasticsearch (9200/tcp) is **TLS + auth**; currently reachable from subnet (restrict to localhost/VPN or proxy)."
  echo "- Apache (80/tcp) default page exposed; minimize or restrict."
  echo "- Postfix (25/tcp) reachable; disable or bind to localhost if not needed."
  echo
  echo "## Evidence files"
  echo "- Host discovery: \`hosts_pingsweep.nmap\`, \`hosts_pingsweep.gnmap\`"
  echo "- TCP services: \`tcp_services.nmap\`, \`tcp_services.gnmap\`"
  echo "- TLS checks: \`tls_checks.nmap\`"
  echo "- HTTP enums: \`http_enums.nmap\`"
  echo "- UDP quick pass: \`udp_top20.nmap\`"
  echo
  echo "## Notes & next steps"
  echo "1. Optionally proxy Arkime behind Nginx on :443 and enforce TLS1.3 + HSTS."
  echo "2. Restrict 9200 to localhost/admin VLAN, or require auth via reverse proxy."
  echo "3. SSH: keys-only auth + source restrictions."
  echo "4. Remove/lock down services not needed (25/tcp, 80/tcp)."
} > "$OUT"

echo "[+] Wrote $OUT"
