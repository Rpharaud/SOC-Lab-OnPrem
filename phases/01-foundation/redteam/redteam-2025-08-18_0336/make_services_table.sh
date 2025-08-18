# make_services_table.sh
set -euo pipefail

IN="tcp_services.gnmap"
OUT="services_table.md"

{
  echo "| IP | Port/Proto | Service |"
  echo "|---|---|---|"
  awk '/Ports: /{
    ip=$2
    # grab the Ports: section
    ports=$0; sub(/.*Ports: /,"",ports)
    n=split(ports, arr, ", ")
    for(i=1;i<=n;i++){
      split(arr[i], f, "/")
      port=f[1]; state=f[2]; proto=f[3]; service=f[5]
      if(state=="open"){
        if(service=="") service="-"
        printf("| %s | %s/%s | %s |\n", ip, port, proto, service)
      }
    }
  }' "$IN" | sort -t'|' -k2,2 -k3,3
} > "$OUT"

echo "[+] Wrote $OUT"
