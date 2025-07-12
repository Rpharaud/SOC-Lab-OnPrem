#!/usr/bin/env python3

"""
enrich.py
----------
This script:
1️⃣ Pulls unique IPs from Filebeat logs (host.ip).
2️⃣ Checks each IP against a local SQLite cache.
3️⃣ If not cached: Queries multiple threat feeds (VirusTotal, OTX, AbuseIPDB, GreyNoise, Abuse.ch).
4️⃣ Builds a threat_score from the results.
5️⃣ Stores the results to the local DB and indexes them in Elasticsearch.
6️⃣ Tags matching Arkime sessions with threat_score, country, ASN.
"""

import os
import time
import requests
import sqlite3
import json
import ipaddress
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from urllib3.exceptions import InsecureRequestWarning
import warnings
from db import create_table, fetch_ioc, insert_or_update_ioc

# ---------------------------
# Ignore insecure SSL warning
# ---------------------------
warnings.simplefilter('ignore', InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)


# ---------------------------
# Load .env API keys
# ---------------------------
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")

# ---------------------------
# Connect to local Elasticsearch
# ---------------------------
es = Elasticsearch(
    "https://localhost:9200",
    http_auth=("elastic", "elastic123"),
    verify_certs=False
)

# ---------------------------
# Get unique IPs from Filebeat logs
# ---------------------------
def get_unique_ips(index_name, field):
    query = {
        "size": 0,
        "aggs": {
            "unique_ips": {
                "terms": {
                    "field": field,
                    "size": 1000
                }
            }
        }
    }
    res = es.search(index=index_name, **query)
    ips = [bucket["key"] for bucket in res["aggregations"]["unique_ips"]["buckets"]]
    return ips

# ---------------------------
# Determine if an IP is public
# ---------------------------
def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

# ---------------------------
# External threat feeds
# ---------------------------
def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 429:
        print("VT rate limit hit, waiting...")
        time.sleep(30)
        return check_virustotal(ip)
    return {}

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    return {}

def query_otx(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return {}

def query_abusech(ip):
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    response = requests.get(url)
    if response.status_code == 200:
        lines = response.text.splitlines()
        if ip in lines:
            return {"listed": True}
        return {"listed": False}
    return {}

def query_greynoise(ip):
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": GREYNOISE_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return {}

# ---------------------------
# Threat Score Calculation 
# ---------------------------

# 🏷️ Define WEIGHTS up top so they’re easy to adjust anytime:
VT_MALICIOUS_WEIGHT = 40     # How much VirusTotal malicious engines count
ABUSEIPDB_WEIGHT = 30        # How much AbuseIPDB high confidence counts
OTX_WEIGHT = 20              # How much OTX pulse matches count
ABUSECH_WEIGHT = 20          # How much if IP found on Abuse.ch blocklist
GREYNOISE_WEIGHT = 10        # How much GreyNoise noise context adds

# 🎚️ Define thresholds — when each source “counts”:
ABUSEIPDB_THRESHOLD = 50     # Only scores if abuseConfidenceScore is >50
VT_MALICIOUS_THRESHOLD = 1   # How many malicious engines minimum for score

def calculate_threat_score(feeds):
    """
    Given threat feeds dict → calculate final threat score.
    Adds up points if certain feed conditions are true.
    Caps at 100.
    """

    score = 0  # Start from zero

    # 🍃 Get each feed safely
    vt = feeds.get("VirusTotal", {})
    abuseipdb = feeds.get("AbuseIPDB", {})
    otx = feeds.get("OTX", {})
    abusech = feeds.get("Abuse.ch", {})
    greynoise = feeds.get("GreyNoise", {})

    # ✅ VirusTotal logic
    vt_malicious = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    if vt_malicious >= VT_MALICIOUS_THRESHOLD:
        score += VT_MALICIOUS_WEIGHT

    # ✅ AbuseIPDB logic
    abuse_score = abuseipdb.get("data", {}).get("abuseConfidenceScore", 0)
    if abuse_score >= ABUSEIPDB_THRESHOLD:
        score += ABUSEIPDB_WEIGHT

    # ✅ OTX logic
    otx_count = otx.get("pulse_info", {}).get("count", 0)
    if otx_count > 0:
        score += OTX_WEIGHT

    # ✅ Abuse.ch logic
    if abusech.get("listed", False):
        score += ABUSECH_WEIGHT

    # ✅ GreyNoise logic
    if greynoise.get("noise", False):
        score += GREYNOISE_WEIGHT

    # 📌 Optional: Debug print to see raw values + final score
    print(f"[SCORE DEBUG] VT:{vt_malicious} AbuseIPDB:{abuse_score} OTX:{otx_count} AbuseCH:{abusech.get('listed')} GreyNoise:{greynoise.get('noise')} → Raw:{score}")

    # 🎯 Always cap to 100 so it stays normalized
    return min(score, 100)

# ----------------------------------------------
# Index to Elasticsearch and tag Arkime sessions
# ----------------------------------------------
def index_enriched(ip, feeds, threat_score):
    import json  # ensure available

    vt_data = feeds.get("VirusTotal", {})

    # Defensive parse: handle DB string or dict
    if isinstance(vt_data, str):
        try:
            vt_data = json.loads(vt_data)
        except Exception as e:
            print(f"[WARN] Could not parse VT data as JSON: {e}")
            vt_data = {}

    # Extract safe fields
    country = vt_data.get("data", {}).get("attributes", {}).get("country", None)
    asn = None
    network_info = vt_data.get("data", {}).get("attributes", {}).get("network")
    if isinstance(network_info, dict):
        asn = network_info.get("asn", None)

    doc = {
        "ip": ip,
        "threat_score": threat_score,
        "country": country,
        "asn": asn
    }

    # Index to local threat index
    es.index(index="enriched-threatintel", document=doc)
    print(f"[INDEX] Enriched doc written for {ip} (country: {country}, ASN: {asn}, threat_score: {threat_score})")

    # Build Arkime query
    query = {
        "query": {
            "bool": {
                "should": [
                    {"match": {"source.ip": ip}},
                    {"match": {"destination.ip": ip}}
                ]
            }
        }
    }

    res = es.search(index="arkime_sessions*", body=query)
    hits = res.get("hits", {}).get("hits", [])
    print(f"[DEBUG] Found {len(hits)} Arkime docs for {ip}")

    for hit in hits:
        doc_id = hit["_id"]
        es.update(
            index=hit["_index"],
            id=doc_id,
            body={
                "doc": {
                    "threat_score": threat_score,
                    "ioc_country": country,
                    "ioc_asn": asn,
                    "ioc_tag": True
                }
            }
        )
        print(f"[UPDATE] Arkime doc updated: {doc_id}")
        print(f"   → threat_score: {threat_score}")
        print(f"   → ioc_country: {country}")
        print(f"   → ioc_asn: {asn}")

# ---------------------------
# MAIN
# ---------------------------
if __name__ == "__main__":
    create_table()
    ips = ["185.100.87.202","185.220.101.1","104.244.72.115","91.219.236.15","185.100.87.84","209.141.38.71","66.70.190.18","185.220.102.4"]
    print(f"Using test IPs: {ips}")
    #ips = get_unique_ips(index_name="filebeat-*", field="host.ip")
    print(f"Found {len(ips)} unique IPs for enrichment")

    skipped = 0
    enriched = 0

    for ip in ips:
        if not is_public_ip(ip):
            continue

        cached = fetch_ioc(ip)
        if cached:
            skipped += 1
            index_enriched(ip, cached["feeds"], cached["threat_score"])
        else:
            feeds = {
                "VirusTotal": check_virustotal(ip),
                "AbuseIPDB": check_abuseipdb(ip),
                "OTX": query_otx(ip),
                "Abuse.ch": query_abusech(ip),
                "GreyNoise": query_greynoise(ip)
            }

            if all(not v for v in feeds.values()):
                continue  # Skip empty enrichment

            threat_score = calculate_threat_score(feeds)
            insert_or_update_ioc(ip, "IP", feeds, threat_score)
            index_enriched(ip, feeds, threat_score)
            enriched += 1

            time.sleep(1)

    print(f"[SUMMARY] Cache hits reused: {skipped}")
    print(f"[SUMMARY] New enrichments: {enriched}")
