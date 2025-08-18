# generate_baseline_md.sh
set -euo pipefail
LAB_NET="${LAB_NET:-192.168.64.0/24}"
SCANNER_IP="$(hostname -I | awk '{print $1}')"
DATE="$(date +%F)"

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
    echo "- (none)  "
  fi
  echo
  echo "## High-level findings"
  echo "- Arkime (8005/tcp) is **HTTPS** with lab PKI (Digest auth)."
  echo "- Elasticsearch (9200/tcp) requires auth (401) and is TLS-enabled; currently reachable from the subnet."
  echo "- Apache (80/tcp) default page exposed."
  echo "- Postfix (25/tcp) reachable; consider disabling or restricting if not needed."
  echo
  echo "## Evidence files"
  echo "- Host discovery: \`hosts_pingsweep.nmap\`, \`hosts_pingsweep.gnmap\`"
  echo "- TCP services: \`tcp_services.nmap\`"
  echo "- TLS checks: \`tls_checks.nmap\`"
  echo "- HTTP enums: \`http_enums.nmap\`"
  echo "- UDP quick pass: \`udp_top20.nmap\`"
  echo
  echo "## Service summary (from tcp_services.gnmap)"
  echo "| IP | Open Ports (raw) |"
  echo "|---|---|"
  if [[ -f tcp_services.gnmap ]]; then
    awk '/Ports: /{
      ip=$2;
      ports=$0; sub(/.*Ports: /,"",ports);
      gsub(/, /,"<br>",ports);
      print "| " ip " | " ports " |"
    }' tcp_services.gnmap
  else
    echo "| (no file) | |"
  fi
  echo
  echo "## Notes & next steps"
  echo "1. Consider placing Arkime behind Nginx on :443 and enforcing TLS1.3-only + HSTS."
  echo "2. Restrict Elasticsearch (9200) to localhost/admin VLAN or proxy with auth."
  echo "3. If SMTP isn’t required, disable Postfix or bind to localhost."
  echo "4. SSH: enforce key-only auth and limit by security group/iptables."
} > baseline_attack_surface.md

echo "[+] Wrote baseline_attack_surface.md"
