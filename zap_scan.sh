#!/bin/bash
# zap_scan.sh v4 — Full API Security Phase 2.5 test
# Author: Reggie
# Location: SOC-Lab-OnPrem/Phase_2.5/

API_URL="http://192.168.64.10:5000"

echo "[+] Starting ZAP Spider for: $API_URL"
spiderid=$(curl -s "http://127.0.0.1:8080/JSON/spider/action/scan/?url=$API_URL" | jq -r '.scan')
echo "[+] Spider started with ID: $spiderid"

progress=0
while [ $progress -lt 100 ]; do
  progress=$(curl -s "http://127.0.0.1:8080/JSON/spider/view/status/?scanId=$spiderid" | jq -r '.status')
  echo "    [*] Spider progress: $progress%"
  sleep 2
done

echo "[+] Spider complete."

echo "[+] Starting ZAP Active Scan for: $API_URL"
activescanid=$(curl -s "http://127.0.0.1:8080/JSON/ascan/action/scan/?url=$API_URL" | jq -r '.scan')
echo "[+] Active Scan started with ID: $activescanid"

progress=0
while [ $progress -lt 100 ]; do
  progress=$(curl -s "http://127.0.0.1:8080/JSON/ascan/view/status/?scanId=$activescanid" | jq -r '.stat$
  echo "    [*] Active Scan progress: $progress%"
  sleep 5
done

echo "[+] Active Scan complete."

# ---------
# Manual API-specific abuse tests
# ---------

echo "[+] Testing Broken Auth with invalid JWT..."
curl -s -H "x-access-token: invalidtoken" "$API_URL/data" || echo "[*] Should be 401 or 403"

echo "[+] Testing Brute Force Login..."
for i in {1..50}; do
    curl -s -X POST -H "Content-Type: application/json" -d '{"username":"admin", "password":"wrongpass"}$
done
echo "[*] 50 invalid logins sent."

echo "[+] Testing Valid JWT Flow..."
RAW_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin", "password":"admin"}' "$API_URL/login")

echo "[DEBUG] Raw Login Response: $RAW_RESPONSE"
TOKEN=$(echo "$RAW_RESPONSE" | jq -r '.token')
echo "[+] Got Token: $TOKEN"

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    echo "[❌] Login failed. Token is null or invalid. Skipping authenticated tests..."
else
    echo "[+] Authenticated Data Fetch..."
    curl -s -H "x-access-token: $TOKEN" "$API_URL/data"

    echo "[+] Testing BOLA (Insecure Direct Object Reference)..."
    curl -s -H "x-access-token: $TOKEN" "$API_URL/user/2"

    echo "[+] SQLi Fuzz (POST body)..."
    curl -s -X POST -H "Content-Type: application/json" -H "x-access-token: $TOKEN" \
        -d '{"query":"1 OR 1=1 --"}' "$API_URL/search"
    curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        -d "query=' OR '1'='1" "$API_URL/search"

    echo "[+] Testing Rate Limit (authenticated)..."
    for i in {1..50}; do
        curl -s -H "x-access-token: $TOKEN" "$API_URL/data" > /dev/null
    done
    
    echo "[+] Revoking Token (logout)..."
    curl -s -X POST -H "x-access-token: $TOKEN" "$API_URL/logout"
    echo "[+] Testing Revoked Token..."
    curl -s -H "x-access-token: $TOKEN" "$API_URL/data"
fi

echo "[+] Testing Rate Limit (unauthenticated)..."
for i in {1..50}; do
    curl -s "$API_URL/" > /dev/null
done

echo "[+] OPTIONS Method Test..."
curl -s -X OPTIONS "$API_URL/"

echo "[+] Expecting 429 after brute force..."
curl -i "$API_URL/" | grep "429" && echo "[✔️] Rate limit enforced" || echo "[❌] Rate limit not triggered"

echo "[+] Fetching ZAP alerts..."
curl -s "http://localhost:8090/JSON/core/view/alerts/?baseurl=$API_URL" | jq '.alerts[] | {risk, name, url, solution}'

echo "[+] ✅ Phase 2.5 scan script complete. Check Arkime, Zeek, Suricata, and api_events.log for detection results."
