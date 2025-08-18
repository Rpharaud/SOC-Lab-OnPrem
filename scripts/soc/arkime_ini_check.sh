#!/usr/bin/env bash
set -euo pipefail
fail=0
while IFS= read -r -d '' ini; do
  echo "[*] Checking Arkime config: $ini"
  vSSL=$(awk -F= '/^\s*viewSSL\s*=/{gsub(/[[:space:]]/,"",$2); print tolower($2)}' "$ini" | tail -1 || true)
  vPort=$(awk -F= '/^\s*viewPort\s*=/{gsub(/[[:space:]]/,"",$2); print $2}' "$ini" | tail -1 || true)
  vHost=$(awk -F= '/^\s*viewHost\s*=/{gsub(/[[:space:]]/,"",$2); print $2}' "$ini" | tail -1 || true)
  vKey=$(awk -F= '/^\s*viewSSLKey\s*=/{sub(/^[[:space:]]+/,"",$2); print $2}' "$ini" | tail -1 || true)
  vCert=$(awk -F= '/^\s*viewSSLCert\s*=/{sub(/^[[:space:]]+/,"",$2); print $2}' "$ini" | tail -1 || true)

  [[ -z "$vPort" ]] && echo "  [!] viewPort not set" || echo "  [+] viewPort=$vPort"
  [[ -z "$vHost" ]] && echo "  [!] viewHost not set" || echo "  [+] viewHost=$vHost"

  if [[ "$vSSL" == "false" ]]; then
    echo "  [-] viewSSL=false (must be true)"; fail=1
  elif [[ "$vSSL" == "true" ]]; then
    echo "  [+] viewSSL=true"
    [[ -z "$vKey"  ]] && echo "  [!] viewSSLKey not set (warn)"
    [[ -z "$vCert" ]] && echo "  [!] viewSSLCert not set (warn)"
  else
    echo "  [!] viewSSL not explicitly set (warn)"
  fi
done < <(find phases -type f -path '*/soc/*' -name 'config.ini' -print0)
exit $fail
