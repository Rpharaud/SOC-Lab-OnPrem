#!/usr/bin/env bash
set -euo pipefail
fail=0

# 1) SSHD hardening checks (only if files exist in repo)
while IFS= read -r -d '' f; do
  echo "[*] Checking $f"
  if grep -Eiq '^\s*PasswordAuthentication\s+yes' "$f"; then
    echo "[-] $f: PasswordAuthentication yes (must be 'no')"; fail=1
  fi
  if grep -Eiq '^\s*PermitRootLogin\s+yes' "$f"; then
    echo "[-] $f: PermitRootLogin yes (should be 'no' or 'prohibit-password')"; fail=1
  fi
done < <(find . -type f -iname 'sshd_config*' -print0)

# 2) Suricata presence (soft check)
if ! find phases/01-foundation/soc -maxdepth 3 -iname 'suricata.yaml' | grep -q .; then
  echo "[!] Suricata config not found under phases/01-foundation/soc (ok for now)."
fi

# 3) Arkime TLS hint (soft check)
if ! grep -Riq 'viewSSL\s*=\s*true' phases/01-foundation/soc 2>/dev/null; then
  echo "[!] Could not confirm Arkime viewSSL=true in repo (ok if managed on host)."
fi

exit $fail
