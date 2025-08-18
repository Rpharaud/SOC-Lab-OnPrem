#!/usr/bin/env bash
set -euo pipefail
out=".ci-outputs/crypto_report.txt"; mkdir -p .ci-outputs; : > "$out"
fail=0; now=$(date +%s)

hash_pub () {
  openssl "$1" -in "$2" $3 -pubout -outform DER 2>/dev/null | openssl sha256 | awk '{print $2}'
}

echo "[*] Scanning repo certs/keys under phases/*/crypto" | tee -a "$out"
while IFS= read -r -d '' cert; do
  echo "---- $cert ----" | tee -a "$out"
  subj=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null || true)
  issr=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null || true)
  end=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | sed 's/notAfter=//' || true)
  echo "$subj" | tee -a "$out"; echo "$issr" | tee -a "$out"; echo "notAfter=$end" | tee -a "$out"

  if [[ -n "$end" ]]; then
    end_epoch=$(date -d "$end" +%s 2>/dev/null || echo 0)
    if (( end_epoch>0 && end_epoch<now )); then
      echo "[-] EXPIRED: $cert" | tee -a "$out"; fail=1
    fi
  fi

  base="${cert%.*}"
  for k in "$base.key" "${base%.fullchain}.key"; do
    [[ -f "$k" ]] || continue
    cfp=$(hash_pub x509 "$cert" -pubkey)
    kfp=$(hash_pub pkey "$k")
    if [[ -n "$cfp" && -n "$kfp" ]]; then
      if [[ "$cfp" == "$kfp" ]]; then
        echo "[+] Key matches cert ($k)" | tee -a "$out"
      else
        echo "[-] Key DOES NOT match cert ($k)" | tee -a "$out"; fail=1
      fi
    fi
  done

  if [[ "$cert" == *arkime* ]]; then
    if ! openssl x509 -in "$cert" -noout -text | grep -q 'DNS:arkime.lab.local'; then
      echo "[!] Arkime cert missing SAN DNS:arkime.lab.local (warn)" | tee -a "$out"
    fi
  fi
done < <(find phases -type f -path '*/crypto/*' \( -name '*.crt' -o -name '*.pem' \) -not -name '*ca*' -print0)

# Try chain verification when a CA is present
root="$(find phases -type f -path '*/crypto/*' -iname '*root*.crt' -o -iname '*Root*.pem' | head -1 || true)"
inter="$(find phases -type f -path '*/crypto/*' -iname '*intermediate*.crt' -o -iname '*Intermediate*.pem' | head -1 || true)"
if [[ -n "$root" ]]; then
  echo "[*] Verifying any *fullchain.crt against $root" | tee -a "$out"
  while IFS= read -r -d '' fc; do
    if openssl verify -CAfile "$root" "$fc" >/dev/null 2>&1; then
      echo "[+] Verified: $fc" | tee -a "$out"
    else
      echo "[!] Could not verify: $fc (warn)" | tee -a "$out"
    fi
  done < <(find phases -type f -path '*/crypto/*' -name '*fullchain.crt' -print0)
fi

echo "[=] Crypto checks complete -> $out"; exit $fail
