import os
import requests
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
import warnings
import json
import time
import ipaddress
from db import create_table, fetch_ioc, insert_or_update_ioc

# Suppress SSL warnings
warnings.filterwarnings("ignore")

# Load .env keys
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")

# Connect to Elasticsearch
es = Elasticsearch(
    "https://localhost:9200",
    http_auth=("elastic", "elastic123"),
    verify_certs=False,
)

# IP filter
def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

# Pull unique IPs from Arkime sessions
def get_unique_ips():
    query = {
        "size": 0,
        "aggs": {
            "unique_ips": {
                "terms": {
                    "field": "destination.ip",
                    "size": 1000
                }
            }
        }
    }
    res = es.search(index="arkime_sessions*", body=query)
    ips = [bucket["key"] for bucket in res["aggregations"]["unique_ips"]["buckets"]]
    return ips

# Threat score
def calculate_threat_score(feeds):
    score = 0
    vt = feeds.get("VirusTotal", {})
    if isinstance(vt, str):
        try:
            vt = json.loads(vt)
        except Exception:
            vt = {}
    vt_stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    if vt_stats.get("malicious", 0) > 0:
        score += 40
    abuse = feeds.get("AbuseIPDB", {}).get("data", {})
    if abuse.get("abuseConfidenceScore", 0) > 50:
        score += 30
    otx = feeds.get("OTX", {}).get("pulse_info", {})
    if otx.get("count", 0) > 0:
        score += 20
    if feeds.get("Abuse.ch", {}).get("listed", False):
        score += 10
    if feeds.get("GreyNoise", {}).get("noise", False):
        score += 10
    return min(score, 100)

# Index + update
def index_enriched(ip, feeds, threat_score):
    vt_data = feeds.get("VirusTotal", {})
    if isinstance(vt_data, str):
        try:
            vt_data = json.loads(vt_data)
        except Exception:
            vt_data = {}

    country = vt_data.get("data", {}).get("attributes", {}).get("country", None)
    network_info = vt_data.get("data", {}).get("attributes", {}).get("network")
    asn = None
    if isinstance(network_info, dict):
        asn = network_info.get("asn")

    es.index(index="enriched-threatintel", document={
        "ip": ip,
        "threat_score": threat_score,
        "ioc_country": country,
        "ioc_asn": asn
    })
    print(f"[INDEX] Enriched doc written for {ip} (country: {country}, ASN: {asn}, threat_score: {threat_score})")

    query = {
        "query": {
            "bool": {
                "should": [
                    {"term": {"source.ip": ip}},
                    {"term": {"destination.ip": ip}}
                ]
            }
        }
    }
    res = es.search(index="arkime_sessions*", body=query)
    hits = res["hits"]["hits"]
    print(f"[DEBUG] Found {len(hits)} Arkime docs for {ip}")

    for hit in hits:
        es.update(
            index=hit["_index"],
            id=hit["_id"],
            body={"doc": {
                "threat_score": threat_score,
                "ioc_country": country,
                "ioc_asn": asn
            }}
        )
        updated = es.get(index=hit["_index"], id=hit["_id"])
        src = updated["_source"]
        print(f"[UPDATE] Arkime doc updated: {hit['_id']}")
        print(f"   → threat_score: {src.get('threat_score')}")
        print(f"   → ioc_country: {src.get('ioc_country')}")
        print(f"   → ioc_asn: {src.get('ioc_asn')}")

if __name__ == "__main__":
    create_table()
    ips = get_unique_ips()
    ips = [ip for ip in ips if is_public_ip(ip)]

    if not ips:
        ips = ["45.83.66.132"]  # fallback

    print(f"Found {len(ips)} IPs for enrichment")

    for ip in ips:
        cached = fetch_ioc(ip)
        if cached:
            print(f"[CACHE HIT] {ip}")
            index_enriched(ip, cached["feeds"], cached["threat_score"])
        else:
            print(f"[CACHE MISS] {ip} — fetching feeds...")
            feeds = {}  # Run API lookups here
            threat_score = calculate_threat_score(feeds)
            insert_or_update_ioc(ip, "IP", feeds, threat_score)
            index_enriched(ip, feeds, threat_score)
