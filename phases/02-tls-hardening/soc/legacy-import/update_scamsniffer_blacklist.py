import requests

def update_scamsniffer_blacklist(local_file="scamsniffer_blacklist.json"):
    url =  "https://raw.githubusercontent.com/ScamSniffer/scam-database/main/blacklist/domains.json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            with open(local_file, "w") as f:
                f.write(resp.text)
            print("[UPDATE] ScamSniffer blacklist updated.")
        else:
            print(f"[UPDATE ERROR] HTTP {resp.status_code} from ScamSniffer GitHub.")
    except Exception as e:
        print(f"[UPDATE ERROR] Could not update ScamSniffer: {e}")
