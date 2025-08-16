#!/usr/bin/env python3

"""
enrich.py — Threat Intelligence Enrichment Script
Version: 2.7
Last Updated: 2025-07-15

🔍 Description:
This script enriches network indicators (IPs and domains) with open-source threat intelligence,
adds context scoring, and pushes results back into the SOC lab pipeline (e.g., Arkime).

✅ Features:
- Enrichment of both IP addresses and domain names
- Inline integration with OTX, VirusTotal, AbuseIPDB, GreyNoise, Shodan, IPInfo, PassiveDNS, and WHOIS
- Separate threat scoring functions:
    • calculate_threat_score(feeds) → IP-specific threat logic
    • calculate_domain_threat_score(feeds) → Domain-specific threat logic
- Context-based risk scoring via:
    • WHOIS domain age
    • IPInfo VPN/proxy/relay flags
    • PassiveDNS high resolution count
    • Netlas open ports
    • High-risk country detection
- Automated detection of PTR records
- Built-in caching and Arkime index update support
- Smart deduplication using get_unique_targets()

📌 Notes:
- Designed for use in SOC Lab Phase 2.7: OSINT Enrichment Expansion
- API rate limits and missing API keys will gracefully degrade results
- Dependencies: requests, datetime, socket, re, json

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
import whois
from datetime import datetime
import socket
import requests

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
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
NETLAS_API_KEY = os.getenv("NETLAS_API_KEY")
CENSYS_API_KEY = os.getenv("CENSYS_API_KEY")
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
    headers = {
        "Accept": "application/json",
        "key": GREYNOISE_API_KEY
    }
    try:
        response = requests.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {
                "gn_classification": data.get("classification"),
                "gn_tags": data.get("tags", [])
            }
        else:
            print(f"[GN ERROR] {response.status_code}: {response.text}")
            return {}
    except Exception as e:
        print(f"[GN EXCEPTION] {e}")
        return {}


def query_whois(ip_or_domain):
    import ipaddress
    try:
        # Skip IP addresses; WHOIS module is domain-focused
        ipaddress.ip_address(ip_or_domain)
        print(f"[WHOIS SKIPPED] {ip_or_domain} is an IP address.")
        return {}
    except ValueError:
        # Not an IP, proceed as domain
        pass

    try:
        w = whois.whois(ip_or_domain)
        return {
            "registrar": w.registrar,
            "org": w.org,
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
            "country": w.country
        }
    except Exception as e:
        print(f"[WHOIS ERROR] {ip_or_domain}: {e}")
        return {}

def query_passive_dns(ip):
    api_key = os.getenv("SECURITYTRAILS_API_KEY")
    headers = {"apikey": api_key}
    url = f"https://api.securitytrails.com/v1/ips/nearby/{ip}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {
                "passive_dns_domains": data.get("records", [])
            }
        elif response.status_code == 404:
            return {"passive_dns_domains": []}
        else:
            print(f"[PASSIVE DNS ERROR] Status {response.status_code}: {response.text}")
            return {}
    except Exception as e:
        print(f"[PASSIVE DNS EXCEPTION] {e}")
        return {}

def query_netlas(ip):
    headers = {"API-Key": NETLAS_API_KEY}
    params = {"query": f"ip:{ip}"}
    try:
        response = requests.get("https://app.netlas.io/api/responses/", headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            open_ports = sorted({srv.get("port") for srv in data.get("data", {}).get("services", []) if srv.get("port")})
            return {"netlas_open_ports": open_ports}
        else:
            print(f"[NETLAS ERROR] Status {response.status_code}: {response.text}")
            return {}
    except Exception as e:
        print(f"[NETLAS EXCEPTION] {e}")
        return {}

def query_ipinfo(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/privacy?token={IPINFO_API_KEY}")
        if response.status_code == 200:
            return {"ipinfo_privacy": response.json()}
        else:
            print(f"[IPINFO ERROR] {response.status_code}: {response.text}")
            return {}
    except Exception as e:
        print(f"[IPINFO EXCEPTION] {e}")
        return {}

# ----------------------------------
# Threat & Context Score Calculation 
# ----------------------------------

THREAT_WEIGHTS = {
    "VirusTotal": 40,
    "AbuseIPDB": {
        "low": 10,    # 10–49
        "medium": 20, # 50–89
        "high": 30    # 90+
    },
    "OTX": {
        "low": 10,    # 1–2
        "high": 20    # 3+
    },
    "AbuseCH": 20,
    "GreyNoise": {
        "classification": {
            "malicious": 15,
            "unknown": 5
        },
        "tags": {
            "c2": 10,
            "massscan": 5,
            "mirai": 5,
            "ssh bruteforce": 10
        }
    }
}

CONTEXT_WEIGHTS = {
    "WHOIS": {
        "recent": 15,       # < 30 days
        "semi_recent": 5    # < 180 days
    },
    "IPInfo": {
        "risky_privacy": 10
    },
    "Netlas": {
        "many_open_ports": 5
    },
    "PassiveDNS": {
        "high_resolution_count": 10
    },
    "GeoIP": {
        "risky_countries": {
            "RU", "KP", "CN", "IR", "SY",
            "BY", "VE", "PK", "VN", "UA",
            "BR", "NG", "TR", "IN", "KZ"

        },
        "score": 25
    }
}

def calculate_threat_score(feeds):
    score = 0
    weights = THREAT_WEIGHTS  # Reference the global weight config

    # VirusTotal
    vt = feeds.get("VirusTotal", {})
    vt_stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    vt_malicious = vt_stats.get("malicious", 0)
    if vt_malicious >= 1:
        score += weights.get("VirusTotal", 0)

    # AbuseIPDB
    abuseipdb = feeds.get("AbuseIPDB", {})
    abuse_score = abuseipdb.get("data", {}).get("abuseConfidenceScore", 0)
    if abuse_score >= 90:
        score += weights["AbuseIPDB"]["high"]
    elif abuse_score >= 50:
        score += weights["AbuseIPDB"]["medium"]
    elif abuse_score >= 10:
        score += weights["AbuseIPDB"]["low"]

    # OTX
    otx = feeds.get("OTX", {})
    otx_count = otx.get("pulse_info", {}).get("count", 0)
    if otx_count >= 3:
        score += weights["OTX"]["high"]
    elif otx_count > 0:
        score += weights["OTX"]["low"]

    # Abuse.ch
    abusech = feeds.get("Abuse.ch", {})
    if abusech.get("listed", False):
        score += weights.get("AbuseCH", 0)

    # GreyNoise
    greynoise = feeds.get("GreyNoise", {})
    classification = greynoise.get("classification")
    tags = greynoise.get("tags", [])

    if classification in weights["GreyNoise"]["classification"]:
        score += weights["GreyNoise"]["classification"][classification]

    for tag in tags:
        if tag in weights["GreyNoise"]["tags"]:
            score += weights["GreyNoise"]["tags"][tag]

    return min(score, 100)

def calculate_context_score(feeds):
    score = 0
    weights = CONTEXT_WEIGHTS
    
    geoip_risky = {
        "RU", "CN", "IR", "KP", "SY",
        "BY", "VE", "PK", "VN", "UA",
        "BR", "NG", "TR", "IN", "KZ"
    }
    # WHOIS → Domain age
    whois_data = feeds.get("WHOIS", {})
    creation_date = whois_data.get("creation_date")
    try:
        if creation_date:
            creation_dt = datetime.strptime(creation_date, "%Y-%m-%d %H:%M:%S")
            age_days = (datetime.now() - creation_dt).days
            if age_days < 30:
                score += weights["WHOIS"]["recent"]
            elif age_days < 180:
                score += weights["WHOIS"]["semi_recent"]
    except Exception:
        pass

    # IPInfo → VPN / Proxy / Relay
    ipinfo = feeds.get("IPInfo", {})
    privacy = ipinfo.get("ipinfo_privacy", {})
    if any(privacy.get(flag) for flag in ["vpn", "proxy", "relay"]):
        score += weights["IPInfo"]["risky_privacy"]

    # Netlas → Too many open ports
    netlas = feeds.get("Netlas", {})
    ports = netlas.get("netlas_open_ports", [])
    if len(ports) > 5:
        score += weights["Netlas"]["many_open_ports"]

    # PassiveDNS → Many resolutions
    pdns = feeds.get("PassiveDNS", {})
    records = pdns.get("records", [])
    if len(records) > 20:
        score += weights["PassiveDNS"]["high_resolution_count"]

    # GeoIP → High-risk countries
    geo_country = feeds.get("GeoIP", {}).get("country")
    risky_countries = weights["GeoIP"]["risky_countries"]
    if geo_country in risky_countries:
        print(f"[CTX] Risky country detected: {geo_country}")
        score += weights["GeoIP"]["score"]

    # Cap it (optional)
    return min(score, 50)

def calculate_domain_threat_score(feeds):
    score = 0

    # VirusTotal logic
    vt = feeds.get("VirusTotal", {})
    vt_malicious = vt.get("malicious_count", 0)
    if vt_malicious >= 5:
        score += 40
    elif vt_malicious >= 1:
        score += 20

    # OTX pulse matches
    otx = feeds.get("OTX", {})
    pulse_count = otx.get("pulse_count", 0)
    if pulse_count >= 3:
        score += 20
    elif pulse_count >= 1:
        score += 10

    # Passive DNS anomalies
    pdns = feeds.get("PassiveDNS", {})
    if pdns:
        record_count = len(pdns.get("records", []))
        if record_count > 5:
            score += 10

    # PTR Record
    ptr = feeds.get("PTR", "")
    if ptr and any(s in ptr.lower() for s in ["phish", "malware", "botnet", "exploit"]):
        score += 10

    return score

def calculate_context_score(feeds):
    score = 0

    # WHOIS enrichment
    whois = feeds.get("WHOIS", {})
    if whois.get("registrar"):
        score += 10
    if whois.get("creation_date"):
        score += 5
    if whois.get("expiration_date"):
        score += 5
    if whois.get("org") or whois.get("country"):
        score += 5

    # PTR Record presence (reverse DNS)
    ptr = feeds.get("PTR")
    if ptr:
        score += 5
        if any(keyword in ptr.lower() for keyword in ["cloud", "corp", "mail", "auth", "edge", "sec"]):
            score += 5

    # IPInfo ASN and country (for IP-associated domains)
    ipinfo = feeds.get("IPInfo", {})
    if ipinfo.get("asn"):
        score += 5
    if ipinfo.get("country"):
        score += 5

    # PassiveDNS records (diverse resolving history = useful pivot point)
    pdns = feeds.get("PassiveDNS", {})
    if pdns and len(pdns.get("records", [])) > 1:
        score += 5

    # Netlas or RiskIQ infrastructure data
    netlas = feeds.get("Netlas", {})
    riskiq = feeds.get("RiskIQ", {})
    if netlas or riskiq:
        score += 5

    return min(score, 30)  # Cap to 30 for normalization


# ----------------------------------------------
# Index to Elasticsearch and tag Arkime sessions
# ----------------------------------------------
def index_enriched(ioc, feeds, threat_score, context_score):
    is_ip = is_public_ip(ioc)

    doc = {
        "ioc": ioc,
        "ioc_type": "IP" if is_ip else "Domain",
        "feeds": json.dumps(feeds),
        "threat_score": threat_score,
        "context_score": context_score,
        "ioc_country": feeds.get("IPInfo", {}).get("country"),
        "ioc_asn": feeds.get("IPInfo", {}).get("asn"),
        "timestamp": datetime.utcnow().isoformat()
    }

    # 🔒 Only try to update Arkime for IPs
    if is_ip:
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"match": {"ip": ioc}},
                        {"match": {"ip.dst": ioc}},
                        {"match": {"ip.src": ioc}}
                    ]
                }
            }
        }

        try:
            res = es.search(index="arkime_sessions*", body=query)
            hits = res["hits"]["hits"]
            print(f"[DEBUG] Found {len(hits)} Arkime docs for {ioc}")

            for hit in hits:
                doc_id = hit["_id"]
                es.update(
                    index=hit["_index"],
                    id=doc_id,
                    body={"doc": {
                        "threat_score": threat_score,
                        "context_score": context_score,
                        "ioc_country": doc["ioc_country"],
                        "ioc_asn": doc["ioc_asn"]
                    }}
                )
                print(f"[UPDATE] Arkime doc updated: {doc_id}")
        except Exception as e:
            print(f"[ERROR] Failed to update Arkime: {e}")
    else:
        print(f"[SKIP] No Arkime update for domain: {ioc}")

    # Index the enriched IOC for long-term tracking (IP or Domain)
    es.index(index="enriched_iocs", id=ioc, body=doc)
    print(f"[INDEX] Enriched doc written for {ioc} (country: {doc['ioc_country']}, ASN: {doc['ioc_asn']}, threat_score: {threat_score}, context_score: {context_score})")

# ---------------
# Target ACQUIRED
# ---------------

def get_unique_targets(index_name="filebeat-*", fields=["host.ip", "dns.question.name"]) -> list:
    seen = set()
    targets = []

    for field in fields:
        query = {
            "size": 0,
            "aggs": {
                "unique_targets": {
                    "terms": {
                        "field": field,
                        "size": 1000
                    }
                }
            }
        }

        try:
            res = es.search(index=index_name, body=query)
            buckets = res["aggregations"]["unique_targets"]["buckets"]
            for b in buckets:
                target = b["key"]
                if target not in seen:
                    seen.add(target)
                    targets.append(target)
        except Exception as e:
            print(f"[ERROR] Failed to retrieve {field} targets: {e}")

    return targets
 

# ---------------------------
# MAIN
# ---------------------------
if __name__ == "__main__":
    create_table()

    # 🧪 Test targets: IPs and domains
    targets = [
        "185.100.87.202", "185.220.101.1", "104.244.72.115", "91.219.236.15", "185.100.87.84",
        "209.141.38.71", "66.70.190.18", "185.220.102.4", "45.83.66.132", "23.129.64.67",
        "222.186.180.130", "185.234.219.98",
        "login-microsoft-account.com", "paypal-login-verification.net", "github.com", "appleid-verify.info"
    ]
    # target = get_unique_targets(index_name="filebeat-*")
    print(f"Using test targets: {targets}")
    print(f"Found {len(targets)} unique targets for enrichment")
    
    skipped = 0
    enriched = 0

    for target in targets:
        is_ip = is_public_ip(target)

        # Skip invalid entries (non-IP, non-domain)
        if not is_ip and "." not in target:
            continue

        cached = fetch_ioc(target)
        if cached:
            skipped += 1
            context_score = calculate_context_score(cached["feeds"])
            index_enriched(target, cached["feeds"], cached["threat_score"], context_score)
        else:
            feeds = {}

            # IP-based feeds
            if is_ip:
                feeds.update({
                    "VirusTotal": check_virustotal(target),
                    "AbuseIPDB": check_abuseipdb(target),
                    "OTX": query_otx(target),
                    "Abuse.ch": query_abusech(target),
                    "GreyNoise": query_greynoise(target),
                    "PassiveDNS": query_passive_dns(target),
                    "Netlas": query_netlas(target),
                    "IPInfo": query_ipinfo(target)
                })

            # Domain-based feeds (can apply to both IPs and domains)
            feeds["WHOIS"] = query_whois(target)
            feeds["VirusTotal"] = feeds.get("VirusTotal") or check_virustotal(target)
            feeds["OTX"] = feeds.get("OTX") or query_otx(target)

            if all(not v for v in feeds.values()):
                continue  # Skip empty enrichment

            threat_score = calculate_threat_score(feeds)
            context_score = calculate_context_score(feeds)
            insert_or_update_ioc(target, "Domain" if not is_ip else "IP", feeds, threat_score)
            index_enriched(target, feeds, threat_score, context_score)
            enriched += 1

            time.sleep(1)

    print(f"[SUMMARY] Cache hits reused: {skipped}")
    print(f"[SUMMARY] New enrichments: {enriched}")

# Save enriched output for Phase 3 correlation testing
#with open("../Phase_3/enriched_output.json", "w") as f:
#    for doc in indexed_enriched:
#        f.write(json.dumps(doc) + "\n")
#print("[EXPORT] Saved enriched results to Phase_3/enriched_output.json")
