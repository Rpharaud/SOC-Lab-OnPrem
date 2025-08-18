#!/usr/bin/env bash
set -euo pipefail
LAB_NET="${LAB_NET:-192.168.64.0/24}"
SCANNER_IP="$(hostname -I | awk '{print $1}')"
DATE="$(date +%F)"; OUT="baseline_attack_surface.md"
{
  echo "# Phase 1 – Red Team Baseline Attack Surface"
  echo "_Date: ${DATE}_  "; echo "_Subnet(s): ${LAB_NET}_  "; echo "_Scanner: ${SCANNER_IP}_  "; echo
  echo "## Targets discovered"
  [[ -s phases/01-foundation/redteam/targets.txt ]] \
    && awk '{print "- " $0}' phases/01-foundation/redteam/targets.txt || echo "- (none)"; echo
  echo "## Service inventory (open TCP only)"
  [[ -f services_table.md ]] && cat services_table.md || echo "_(Run make_services_table_rich.sh first)_"; echo
  echo "## High-level findings"
  echo "- Arkime (8005/tcp) is **HTTPS** with lab PKI (Digest auth)."
  echo "- Elasticsearch (9200/tcp) is **TLS + auth**; reachable from subnet (restrict)."
  echo "- Apache (80/tcp) default page exposed."
  echo "- Postfix (25/tcp) reachable; disable/bind to localhost if not needed."; echo
  echo "## Evidence files"
  echo "- hosts: hosts_pingsweep.nmap / .gnmap"
  echo "- tcp: tcp_services.nmap / .gnmap"
  echo "- tls: tls_checks.nmap"
  echo "- http: http_enums.nmap"
  echo "- udp: udp_top20.nmap"
} > "$OUT"
