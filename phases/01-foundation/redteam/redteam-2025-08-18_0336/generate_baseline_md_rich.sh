# generate_baseline_md_rich.sh
set -euo pipefail
LAB_NET="${LAB_NET:-192.168.64.0/24}"
SCANNER_IP="$(hostname -I | awk '{print $1}')"
DATE="$(date +%F)"; OUT="baseline_attack_surface.md"
{
  echo "# Phase 1 – Red Team Baseline Attack Surface"
  echo "_Date: ${DATE}_  "; echo "_Subnet(s): ${LAB_NET}_  "; echo "_Scanner: ${SCANNER_IP}_  "; echo
  echo "## Targets discovered"; [[ -s targets.txt ]] && awk '{print "- " $0}' targets.txt || echo "- (none)"; echo
  echo "## Service inventory (open TCP only)"; [[ -f services_table.md ]] && cat services_table.md || echo "_(Generate services_table.md first)_"; echo
  echo "## High-level findings"
  echo "- Arkime (8005/tcp) is **HTTPS** with lab PKI (Digest auth)."
  echo "- Elasticsearch (9200/tcp) is **TLS + auth**; reachable from subnet (restrict)."
  echo "- Apache (80/tcp) default page exposed (minimize/restrict)."
  echo "- Postfix (25/tcp) reachable; disable/bind to localhost if not needed."; echo
  echo "## Evidence files"
  echo "- hosts: hosts_pingsweep.nmap / .gnmap"
  echo "- tcp: tcp_services.nmap / .gnmap"
  echo "- tls: tls_checks.nmap"
  echo "- http: http_enums.nmap"
  echo "- udp: udp_top20.nmap"; echo
  echo "## Notes & next steps"
  echo "1. Optionally proxy Arkime behind Nginx on :443; enforce TLS1.3 + HSTS."
  echo "2. Restrict 9200 to localhost/admin VLAN, or front with auth proxy."
  echo "3. SSH: keys-only auth + source restrictions."
  echo "4. Remove/lock down services not needed (25/tcp, 80/tcp)."
} > "$OUT"
echo "[+] Wrote $OUT"
