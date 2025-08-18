""" This update introduces enrich_v2.py — a major improvement over the original enrich.py.

Enhancements include:
• Expanded OSINT coverage:
  - Passive DNS lookups (OTX, ViewDNS, DNSTwist)
  - WHOIS parsing for domain age and registrar anomalies
  - GeoIP/ASN fallback for missing data
  - SSL certificate history analysis via crt.sh
  - Web3 abuse detection for .eth/.sol domains and scam wallets

• Improved scoring logic:
  - Separated threat_score, context_score, and optional osint_score
  - Tiered dictionary-based scoring system for consistent results
  - Domain age weighting for suspiciously young domains

• Output & tagging:
  - Enriched JSON and NDJSON export for ingestion
  - Arkime /tagger API integration for session metadata tagging
  - Support for live, test, and hybrid enrichment modes

• Code structure refinements:
  - Better error handling for missing API data
  - Consistent logging format
  - Modularized enrichment steps for easier future updates

This file replaces enrich.py for future SOC Lab enrichment phases.
"""
import os
import time
import requests
from ipaddress import ip_address
import json
import whois
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ElasticsearchException
from dotenv import load_dotenv
from urllib3.exceptions import InsecureRequestWarning
import warnings
from db import create_table, fetch_ioc, insert_or_update_ioc
import subprocess
from bs4 import BeautifulSoup
import socket
from dateutil import parser
import json
from update_scamsniffer_blacklist import update_scamsniffer_blacklist
from urllib.parse import quote
from requests.auth import HTTPDigestAuth
update_scamsniffer_blacklist()


def arkime_tag_indicator(target, tags, label=None, is_ip=False,
                         arkime_host="http://localhost:8005",
                         username="admin", password="admin"):
    """
    Pushes tags to Arkime's /tagger API.

    Args:
        target (str): Domain or IP
        tags (list): Tags from enrichment
        label (str): Optional label (e.g., known bad)
    """
    if not tags:
        return

    is_ip = is_public_ip(target)

    # Skip tagging for private IPs
    if is_ip and not is_public_ip(target):
        print(f"[SKIP] Not tagging private/bogon IP: {target}")
        return

    tag_list = list(set(tags + ([label] if label else [])))
    tag_str = ",".join(quote(t) for t in tag_list)

    payload = {
        "ip" if is_ip else "host": target,
        "tag": tag_str
    }

    try:
        session = requests.Session()
        session.auth = HTTPDigestAuth(username, password)
        session.verify = False  # Only for dev/test
        resp = session.post(
            f"{arkime_host}/tagger",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if resp.status_code == 200:
            print(f"[ARKIME ✅] Tagged {target} with: {tag_str}")
        else:
            print(f"[ARKIME ❌] {target} — HTTP {resp.status_code}: {resp.text}")
    except requests.exceptions.RequestException as e:
        print(f"[ARKIME ❌] {target} — {e}")

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
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")
NETLAS_API_KEY = os.getenv("NETLAS_API_KEY")

# ---------------------------
# Connect to Elasticsearch
# ---------------------------
es = Elasticsearch(
    ["https://localhost:9200"],
    http_auth=("elastic", "elastic123"),
    verify_certs=False,  # Only disable in dev/lab mode
)
try:
    print("[DEBUG] Auth Test:", es.info())
except Exception as e:
    print("[ERROR] Failed auth test:", e)

print(f"[DEBUG] Using Elasticsearch client: {es}")


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
    res = es.search(index=index_name, body=query)
    ips = [bucket["key"] for bucket in res["aggregations"]["unique_ips"]["buckets"]]
    return ips

# ------------------
# Get Unique Strings
# ------------------
def get_unique_strings(index_name="filebeat-*", field="dns.question.name", size=500):
    """
    Query Elasticsearch to get unique values for a specific string field.
    """
    try:
        query_field = f"{field}.keyword"
        body = {
            "size": 0,
            "aggs": {
                "unique_values": {
                    "terms": {
                        "field": query_field,
                        "size": size
                    }
                }
            }
        }

        response = es.search(index=index_name, body=body)
        buckets = response.get("aggregations", {}).get("unique_values", {}).get("buckets", [])

        return [bucket["key"] for bucket in buckets]

    except Exception as e:
        print(f"[ES ERROR] Failed to query field '{field}': {e}")
        return []

# ---------------------------
# Helpers
# ---------------------------
def is_valid_domain(domain):
    return (
        domain and
        isinstance(domain, str) and
        "." in domain and
        not domain.endswith((".local", ".arpa")) and
        not any(bad in domain for bad in ["localdomain", "broadcasthost"])
    )

# Global blacklist loaded once
SCAM_SNIFFER_FILE = "scamsniffer_blacklist.json"

def is_crypto_relevant(target):
    """
    Determines if a target (domain or address) is relevant to cryptocurrency or Web3.
    Returns True if it contains common crypto-related keywords or TLDs.
    """
    CRYPTO_KEYWORDS = [
        "wallet", "btc", "eth", "crypto", "nft", "token",
        ".eth", ".sol", ".crypto", ".nft", ".web3", "defi", "airdrop"
    ]
    target_lower = target.lower()
    return any(kw in target_lower for kw in CRYPTO_KEYWORDS)


def load_scamsniffer_blacklist():
    try:
        with open(SCAM_SNIFFER_FILE, "r") as f:
            domains = json.load(f)
            return set(d.lower() for d in domains)
    except Exception as e:
        print(f"[SCAM SNIFFER] Failed to load: {e}")
        return set()

scamsniffer_blacklist = load_scamsniffer_blacklist()

def is_public_ip(ip):
    try:
        return ip_address(ip).is_global
    except ValueError:
        return False  # Likely a domain


   

# ---------------------------
# WHOIS Enrichment
# ---------------------------
def query_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "org": w.org,
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
            "country": w.country
        }
    except Exception as e:
        print(f"[WHOIS ERROR] {domain}: {e}")
        return {}

# ---------------------------
# IPInfo (GeoIP / ASN)
# ---------------------------
def query_ipinfo(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"[IPINFO ERROR] {ip}: {e}")
    return {}

# ---------------------------
# AbuseIPDB (Threat Score)
# ---------------------------
def check_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"[ABUSEIPDB ERROR] {ip}: {e}")
    return {}

# ---------------------------
# Netlas (Port Exposure)
# ---------------------------
def query_netlas(ip):
    try:
        headers = {"API-Key": NETLAS_API_KEY}
        params = {"query": f"ip:{ip}"}
        url = "https://app.netlas.io/api/responses/"
        r = requests.get(url, headers=headers, params=params)
        if r.status_code == 200:
            data = r.json()
            ports = sorted({s.get("port") for s in data.get("data", {}).get("services", []) if s.get("port")})
            return {"open_ports": ports}
    except Exception as e:
        print(f"[NETLAS ERROR] {ip}: {e}")
    return {}

# ---------------------------
# AlienVault OTX
# ---------------------------
def query_otx(ip):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"[OTX ERROR] {ip}: {e}")
    return {}

# ---------------------------
# crt.sh SSL Certificate Check
# ---------------------------
def query_crtsh(domain):
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"[CRT.SH ERROR] {domain}: {e}")
    return []


# ---------------------------
# Parse SSL for context signals
# ---------------------------
def parse_ssl_for_context(cert_list):
    tags = []
    score = 0
    if not cert_list:
        return tags, score
    seen_issuers = set()
    for cert in cert_list:
        issuer = cert.get("issuer_name")
        if issuer:
            seen_issuers.add(issuer)
    if len(cert_list) > 3:
        tags.append("multiple_ssl_certificates")
        score += 1
    if len(seen_issuers) > 1:
        tags.append("multiple_issuers")
        score += 1
    return tags, score

# ---------------------------
# Scoring
# ---------------------------
def calculate_threat_score(feeds):
    abuse = feeds.get("AbuseIPDB", {}).get("data", {})
    score = abuse.get("abuseConfidenceScore", 0)
    if score >= 90: return 30
    if score >= 50: return 20
    if score >= 10: return 10
    return 0

def score_passivedns(passivedns_data):
    score = 0
    tags = []
    all_entries = []

    for source, entries in passivedns_data.items():
        if entries and isinstance(entries, list):
            all_entries.extend(entries)

    if all_entries:
        score += 3  # general signal of resolution activity

        if any("tor" in e or "dark" in e for e in all_entries):
            score += 2
            tags.append("tor_related_dns")

        if len(all_entries) > 5:
            score += 2
            tags.append("fast_flux_candidate")

        if any("wallet" in e for e in all_entries):
            tags.append("wallet_related_dns")
    else:
        score -= 1  # no resolution history at all

    return score, tags

# --------------------
# Creation Date Handler
# --------------------

def get_creation_date(whois_record):
    raw_date = whois_record.creation_date
    if not raw_date:
        return None
    if isinstance(raw_date, list):
        raw_date = raw_date[0]
    try:
        return raw_date.strftime("%Y-%m-%d")
    except Exception:
        return None

def calculate_context_score(feeds):
    try:
        score = 0
        tags = []
        
        # === OTX Scoring ===
        otx_tags = feeds.get("OTX", {}).get("pulse_info", {}).get("related_tags", [])
        print(f"[DEBUG] OTX Tags: {otx_tags}")

        if otx_tags:
            score += 5 + len(otx_tags) * 5
            tags.append("otx-tagged")


        # === WHOIS Age Scoring ===        
        creation_raw = feeds.get("WHOIS", {}).get("creation_date")
        print(f"[DEBUG] WHOIS creation_date raw: {creation_raw}")

        if creation_raw:
            try:
                if isinstance(creation_raw, list):
                    creation_raw = creation_raw[0]
                if isinstance(creation_raw, datetime):
                    dt = creation_raw
                else:
                    dt = datetime.strptime(str(creation_raw), "%Y-%m-%d %H:%M:%S")
                age_days = (datetime.now() - dt).days
                print(f"[DEBUG] Domain age (days): {age_days}")

                if age_days < 30:
                    score += 10
                    tags.append("new-domain")
                elif age_days < 90:
                    score += 5
                    tags.append("young-domain")
                elif age_days < 180:
                    score += 3
                    tags.append("somewhat-young")
            except Exception as e:
                print(f"[CTX WARN] Invalid WHOIS date format: {creation_raw} - {e}")
        else:
            print(f"[CTX INFO] WHOIS creation_date not present or valid.") 
            # === Passive DNS Scoring ===
        try:
            pdns_data = feeds.get("PassiveDNS", {})
            print(f"[DEBUG] PassiveDNS Data: {pdns_data}")

            all_records = []
            for src in ["otx", "viewdns", "dnstwist"]:
                source_data = pdns_data.get(src)
                if not source_data:
                    continue


                if isinstance(source_data, dict):
                        all_records += pdns_data[src].get("records", [])
                elif isinstance(source_data, list):
                        all_records += source_data
                else:
                    continue
            
            pdns_flat = {"records": all_records}
            print(f"[DEBUG] PassiveDNS Flattened: {pdns_flat}")

            passivedns_score, dns_tags = score_passivedns(all_records)
            score += passivedns_score
            tags.extend(dns_tags)
        except Exception as e:
            print(f"[PASSIVEDNS ERROR] Failed to score PassiveDNS: {e}")

        # === PTR Record Scoring ===
        try:
            ip = feeds.get("meta", {}).get("target")  # Assumes the IP or domain is stored in feeds["meta"]["target"]
            if ip and '.' in ip and not ip.replace('.', '').isdigit():  # skip if it's a domain
                raise ValueError("Target is not an IP address; skipping PTR lookup.")

            ptr_hostname = socket.gethostbyaddr(ip)[0]
            print(f"[DEBUG] PTR record for {ip}: {ptr_hostname}")

            if ptr_hostname:
                score += 5
                tags.append("ptr-present")

                generic_keywords = ["static", "dynamic", "unknown", "localhost", "broadband", "dhcp"]
                if any(kw in ptr_hostname.lower() for kw in generic_keywords):
                    score -= 5  # Penalize generic PTR
                    tags.append("generic-ptr")
        except Exception as e:
            print(f"[PTR ERROR] Failed PTR lookup for {ip}: {e}")




        return score, tags

    except Exception as e:
        print(f"[CTX ERROR] Fallback exception: {e}")
        return 0, []

def calculate_osint_score(feeds, threat):
    """
    Calculate OSINT score based on threat and context scores.
    Defensive against type errors and missing enrichment.
    """
    score = 0
    tags = []
    try:
        # Extract context from feeds safely
        context = feeds.get("ContextScore", 0)

        # Handle case where context is a dict instead of a number
        if isinstance(context, dict):
            context_val = context.get("score", 0)
            if not isinstance(context_val, (int, float)):
                print("[OSINT WARN] Context score is not numeric, defaulting to 0.")
                context_val = 0
        elif isinstance(context, (int, float)):
            context_val = context
        else:
            print(f"[OSINT WARN] Unexpected context type: {type(context)}, defaulting to 0.")
            context_val = 0

        # Ensure threat is numeric
        if not isinstance(threat, (int, float)):
            print(f"[OSINT WARN] Threat score is not numeric ({threat}), defaulting to 0.")
            threat = 0

        osint_score = min(10, round((context_val + threat) / 15))
        return osint_score, tags

    except Exception as e:
        print(f"[OSINT ERROR] Failed to compute OSINT score: {e}")
        return score, tags




def score_passivedns(records):
    score = 0
    tags = []

    if not records or not isinstance(records, list):
        return score, tags

    domains = set()
    for rec in records:
        hostname = rec.get("hostname")
        if hostname:
            domains.add(hostname)

    if domains:
        tags.append("passive-dns-present")
        score += 1

    if len(domains) > 3:
        tags.append("multiple-domains")
        score += 2

    if any(".tor-exit." in d for d in domains):
        tags.append("tor-exit-domain")
        score += 5

    return min(score, 10), tags



def generate_tags(feeds):
    tags = []
    abuse_score = feeds.get("AbuseIPDB", {}).get("data", {}).get("abuseConfidenceScore", 0)
    if abuse_score > 90: tags.append("high_abuse_score")
    if feeds.get("IPInfo", {}).get("country") in {"RU", "CN", "IR", "KP", "SY"}:
        tags.append("risky_geo")
    if len(feeds.get("Netlas", {}).get("open_ports", [])) > 5:
        tags.append("broad_exposure")
    if feeds.get("OTX", {}).get("pulse_info", {}).get("related_tags"):
        tags.append("apt_association")
    try:
        creation = feeds.get("WHOIS", {}).get("creation_date")
        if creation:
            dt = datetime.strptime(creation, "%Y-%m-%d %H:%M:%S")
            if (datetime.now() - dt).days < 30:
                tags.append("new_domain")
    except: pass
    return tags


def write_enriched_json(target, enriched_data, output_dir="output/enriched_json"):
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, f"{target.replace('/', '_')}.json")
    with open(file_path, "w") as f:
        json.dump(enriched_data, f, indent=2, default=str)

# ---------------------------
# Elasticsearch Indexer
# ---------------------------
def index_enriched(ioc, feeds, threat, context, context_tags=None, label=None):
    is_ip = is_public_ip(ioc)
    ipinfo = feeds.get("IPInfo", {})
    whois = feeds.get("WHOIS", {})
    osint = calculate_osint_score(feeds, threat)
    tags = generate_tags(feeds)
    doc = {
        "ioc": ioc,
        "ioc_type": "IP" if is_ip else "Domain",
        "feeds": json.dumps(feeds),
        "threat_score": threat,
        "context_score": context,
        "osint_score": osint,
        "tags": context_tags,
        "context_tags": context_tags or [],
        "wallet_tags": feeds.get("WalletTags", []),
        "campaign_tags": feeds.get("CampaignTags", []),
        "ioc_country": whois.get("country") or ipinfo.get("country"),
        "ioc_org": whois.get("org"),
        "timestamp": datetime.now(datetime.utcnow().astimezone().tzinfo).isoformat()
    }
    es.index(index="enriched_iocs", id=ioc, document=doc)
    print(f"[INDEX] {ioc} — Threat: {threat}, Context: {context}, OSINT: {osint}, Country: {doc['ioc_country']}, Org: {doc['ioc_org']}, Tags: {context_tags}, Label: {label if label else 'N/A'}")


# ------------
# Arkime Query
# ------------
import requests
from requests.auth import HTTPDigestAuth
import urllib3
urllib3.disable_warnings()

def query_arkime_sessions(expression=None,
                           tag=None,
                           label=None,
                           ioc=None,
                           time_window="-1d",
                           limit=500,
                           arkime_host="http://localhost:8005",
                           username="admin",
                           password="admin"):
    """
    Queries Arkime sessions dynamically using tag, label, IOC, or custom expression.

    Args:
        expression (str): Raw Arkime search expression (overrides tag/label/ioc if set)
        tag (str or list): Single or list of tags to search for
        label (str): Optional label to match in session
        ioc (str): IP/domain/hash/hostname to search for
        time_window (str): Time range (e.g. '-1d', '-2h', '0', etc.)
        limit (int): Max number of results to return
        arkime_host (str): Arkime API base URL
        username (str): Arkime user
        password (str): Arkime password

    Returns:
        list: List of matched Arkime sessions (dicts), or empty list on failure
    """
    if not expression:
        expressions = []

        # Tag filter
        if tag:
            if isinstance(tag, list):
                tag_expr = " || ".join([f'tags=="{t}"' for t in tag])
                expressions.append(f"({tag_expr})")
            else:
                expressions.append(f'tags=="{tag}"')

        # Label filter (assumes custom tagging uses labels)
        if label:
            expressions.append(f'label=="{label}"')

        # IOC filter
        if ioc:
            if ":" in ioc or "." in ioc:
                # Heuristic: IP or domain
                if ":" in ioc or all(part.isdigit() for part in ioc.split(".") if part):
                    expressions.append(f'ip=={ioc}')
                else:
                    expressions.append(f'host=="{ioc}"')
            else:
                expressions.append(f'raw=="{ioc}"')

        # Combine all expressions
        expression = " && ".join(expressions)

    url = f"{arkime_host}/api/sessions.json"
    params = {
        "expression": expression,
        "startTime": time_window,
        "length": limit
    }

    headers = {
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest"
    }

    try:
        response = requests.get(url, headers=headers,
                                auth=HTTPDigestAuth(username, password),
                                params=params, verify=False, timeout=10)

        if response.status_code == 200:
            results = response.json().get("data", [])
            print(f"[ARKIME ✅] Found {len(results)} session(s) for: {expression}")
            return results
        else:
            print(f"[ARKIME ERROR] HTTP {response.status_code} — {response.text[:200]}")
    except requests.exceptions.RequestException as e:
        print(f"[ARKIME ERROR] {expression}: {e}")

    return []


# ---------------------------
# OTX Passive DNS (Domain or IP)
# ---------------------------
def query_otx_passivedns(target):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{target}/passive_dns"
        if is_public_ip(target):
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/passive_dns"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            records = data.get("passive_dns", [])
            return {"records": records[:5]} if records else {}
    except Exception as e:
        print(f"[PASSIVEDNS ERROR] {target}: {e}")
    return {}


# -----------------
# DNS Twist Domains
# -----------------
def get_dnstwist_domains(domain):
    try:
        result = subprocess.run(['dnstwist', '--format', 'json', domain], capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout)
        return [entry['domain-name'] for entry in data if entry.get('dns-a') or entry.get('dns-ns')]
    except Exception as e:
        print(f"[DNSTWIST ERROR] {domain}: {e}")
        return []

# ---------------------
# Query & Parse ViewDNS
# ---------------------
def query_viewdns(domain):
    url = f"https://viewdns.info/iphistory/?domain={domain}"
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        table = soup.find_all("table")[3]
        ips = [row.find_all("td")[1].text.strip() for row in table.find_all("tr")[1:]]
        return list(set(ips))
    except Exception as e:
        print(f"[VIEWDNS ERROR] {domain}: {e}")
        return []

def parse_viewdns(html: str) -> list:
    try:
        soup = BeautifulSoup(html, "html.parser")
        table = soup.find("table", {"border": "1"})
        if not table:
            return []

        rows = table.find_all("tr")[1:]  # Skip header
        records = []
        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 4:
                record = {
                    "domain": cols[0].text.strip(),
                    "first_seen": cols[1].text.strip(),
                    "last_seen": cols[2].text.strip(),
                    "ip_address": cols[3].text.strip(),
                }
                records.append(record)
        return records

    except Exception as e:
        print(f"[VIEWDNS PARSE ERROR] {e}")
        return []


def get_domain_creation_date(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            return creation_date
    except Exception as e:
        print(f"[WHOIS ERROR] {domain}: {e}")
    
    # Hardcoded fallback for missing WHOIS
    print(f"[CTX INFO] WHOIS creation_date not present or valid.")
    return "WHOIS_NOT_FOUND"


# ---------------------------
# Calculate domain age score
# ---------------------------
def calculate_domain_age_score(creation_date):
    score = 0
    tags = []
    if not creation_date:
        return score, tags
    try:
        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # Some WHOIS libraries return a list
        age_days = (datetime.utcnow() - creation_date).days
        if age_days < 30:
            score += 4
            tags.append("domain-<30d")
        elif age_days < 90:
            score += 3
            tags.append("domain-<90d")
        elif age_days < 180:
            score += 2
            tags.append("domain-<180d")
        elif age_days < 365:
            score += 1
            tags.append("domain-<365d")
        else:
            tags.append("domain->1y")
    except Exception as e:
        print(f"[CTX WARN] Error calculating domain age: {e}")
    return score, tags

def calculate_domain_threat_score(feeds):
    score = 0
    whois_data = feeds.get("WHOIS", {})
    otx_tags = feeds.get("OTX", {}).get("tags", [])
    passive_dns = feeds.get("PassiveDNS", {}).get("records", [])

    creation_date = whois_data.get("creation_date")
    if creation_date is None:
        score += 5
    elif isinstance(creation_date, datetime):
        age_days = (datetime.utcnow() - creation_date).days
        if age_days < 30:
            score += 10

    if "phishing" in otx_tags:
        score += 25

    if len(passive_dns) > 5:
        score += 5

    if any("wallet" in k for k in feeds.get("WalletTags", [])):
        score += 5

    return min(score, 100)


def calculate_domain_context_score(feeds):
    score = 0
    tags = []

    if feeds.get("WHOIS", {}).get("registrar") is None:
        score += 2
        tags.append("no-registrar")

    if feeds.get("PassiveDNS") and feeds["PassiveDNS"].get("records"):
        score += 5
        tags.append("passive-dns-present")

    if feeds.get("WalletTags"):
        score += 3
        tags.extend(feeds.get("WalletTags", []))

    return score, list(set(tags))

def calculate_domain_osint_score(feeds):
    score = 0
    tags = []

    otx = feeds.get("OTX", {})
    if otx.get("pulse_info", {}).get("count", 0) > 0:
        score += 10
        tags.append("otx-pulse")

        pulse_names = [
            pulse.get("name", "").lower()
            for pulse in otx.get("pulse_info", {}).get("pulses", [])
        ]

        if any(k in name for name in pulse_names for k in ["phish", "scam", "exploit"]):
            score += 10
            tags.append("osint-malicious-keywords")

    if "phishing" in otx.get("tags", []):
        score += 15
        tags.append("tag-phishing")

    ssl_data = feeds.get("SSL", [])
    if isinstance(ssl_data, list) and len(ssl_data) > 0:
        if any("let's encrypt" in str(cert).lower() for cert in ssl_data):
            score += 3
            tags.append("lets-encrypt")

    if feeds.get("WalletTags"):
        score += 5
        tags.append("wallet-flag")

    return min(score, 100), list(set(tags))

# ----
# Web3
# ----
def query_chainabuse(target):
    """
    Queries Chainabuse API for crypto scam reports related to the target.

    Returns a dictionary with reputation or empty dict on failure.
    """
    # Only .eth, .sol, .crypto, wallet, or other crypto strings allowed
    if not any(kw in target.lower() for kw in ["eth", "btc", ".sol", "wallet", ".crypto", ".nft"]):
        print(f"[CHAINABUSE SKIP] {target} is not crypto-relevant.")
        return {}

    url = f"https://api.chainabuse.com/api/v1/reports?search={target}"

    try:
        resp = requests.get(url, timeout=10)

        if resp.status_code == 400:
            print(f"[CHAINABUSE SKIP] {target} not supported (HTTP 400)")
            return {}
        elif resp.status_code != 200:
            print(f"[CHAINABUSE ERROR] {target}: HTTP {resp.status_code}")
            return {}

        data = resp.json()
        if not data.get("reports"):
            return {}

        # Return summary data for now
        return {
            "report_count": len(data["reports"]),
            "report_types": list(set(r.get("type", "unknown") for r in data["reports"] if isinstance(r, dict)))
        }

    except Exception as e:
        print(f"[CHAINABUSE EXCEPTION] {target}: {e}")
        return {}


def check_web3_reputation(target, blacklist):
    """
    Enrich Web3 targets with scam history, blacklists, and address/domain reputation.
    Supports .eth domains, scam sniffer blacklists, Chainabuse.
    """
    tags = []
    score = 0
    target_lc = target.lower()

    # Load local ScamSniffer list
    scamsniffer_blacklist = load_scamsniffer_blacklist()

    # Heuristic: if it's a .eth or .sol name
    if target_lc.endswith(".eth") or target_lc.endswith(".sol"):
        tags.append("ens-name")
        score += 1

    # ScamSniffer blocklist match
    if target_lc in scamsniffer_blacklist:
        tags.append("scamsniffer-blacklist")
        score += 3

    # Chainabuse lookup
    abuse_data = query_chainabuse(target_lc)
    if abuse_data.get("reports", 0) > 0:
        tags.append("chainabuse-reported")
        tags.extend([f"abuse:{cat}" for cat in abuse_data.get("categories", []) if cat])
        score += 4

    return {"web3_score": min(score, 10), "web3_tags": list(set(tags))}


# ---------------------------
# Main Enrichment Flow
# ---------------------------
if __name__ == "__main__":
    create_table()
    MODE = "hybrid"  # options: "test", "live", "hybrid"

    TEST_INDICATORS = {
        "8.8.8.8": "GOOGLE_DNS",
        "1.1.1.1": "CLOUDFLARE_DNS",
        "github.com": "KNOWN_GOOD",
        "microsoft.com": "KNOWN_GOOD",
        "apple.com": "KNOWN_GOOD",
        "185.220.101.1": "TOR_EXIT_NODE",
        "104.244.72.115": "SUSPICIOUS_IP",
        "secure-appleid-loogin.biz": "PHISHING_SITE",
        "paypal-login-verification.net": "FAKE_PAYPAL",
        "login-microsoft-account.com": "FAKE_MICROSOFT",
        "mywallet.eth": "WEB3_DOMAIN",
        "dydx.trade": "CRYPTO_DAPP",
        "xn--googl-fsa.com": "IDN_HOMOGRAPH",
        "test--wallet-btc.net": "SUSPICIOUS_WALLET",
        "fbi.gov": "HIGH_PROFILE_DOMAIN",
    }

    if MODE == "live":
        dns_domains = get_unique_strings("filebeat-*", "dns.question.name")
        url_domains = get_unique_strings("filebeat-*", "url.domain")
        http_hosts = get_unique_strings("filebeat-*", "http.host")
        all_domains = set(dns_domains + url_domains + http_hosts)
        filtered_domains = [d for d in all_domains if is_valid_domain(d)]
        ips = get_unique_ips("filebeat-*", "host.ip")
        targets = list(set(ips + filtered_domains))
        labels = {}
    elif MODE == "test":
        targets = list(TEST_INDICATORS.keys())
        labels = TEST_INDICATORS
    else:  # hybrid
        ips, domains = [], []
        try:
            ips = get_unique_ips("filebeat-*", "host.ip")
        except Exception as e:
            print(f"[ES ERROR] IPs: {e}")
        for field in ["dns.question.name", "url.domain", "http.host"]:
            try:
                domains += get_unique_strings("filebeat-*", field)
            except Exception as e:
                print(f"[ES ERROR] Field '{field}': {e}")
        filtered_domains = [d for d in domains if is_valid_domain(d)]
        targets = list(set(ips + filtered_domains + list(TEST_INDICATORS.keys())))
        labels = {t: TEST_INDICATORS.get(t) for t in targets if t in TEST_INDICATORS}

    print(f"[INFO] Running in {MODE.upper()} mode — {len(targets)} targets queued.")

    for target in targets:
        is_ip = is_public_ip(target)
        feeds = {"meta": {"target": target}}
        cached = fetch_ioc(target)

        if cached:
            try:
                context, context_tags = calculate_context_score(cached["feeds"]) if is_ip else calculate_domain_context_score(cached["feeds"])
            except Exception as e:
                print(f"[CTX ERROR] Cached {target}: {e}")
                context, context_tags = -1, []
            index_enriched(target, cached["feeds"], cached["threat_score"], context, context_tags, label=labels.get(target))
            continue

        # Enrichment
        if is_ip:
            feeds["AbuseIPDB"] = check_abuseipdb(target)
            feeds["Netlas"] = query_netlas(target)
            feeds["IPInfo"] = query_ipinfo(target)
            feeds["OTX"] = query_otx(target)
            feeds["PassiveDNS"] = {
                "dnstwist": get_dnstwist_domains(target),
                "viewdns": query_viewdns(target),
                "otx": query_otx_passivedns(target),
            }
            geoip_result = query_ipinfo(target)
            feeds["GeoIP"] = geoip_result if isinstance(geoip_result, dict) else {"asn": geoip_result[0], "asn_org": geoip_result[1]}
            pulses = feeds["OTX"].get("pulse_info", {}).get("pulses", [])
            feeds["CampaignTags"] = list({p["name"] for p in pulses if any(x in p.get("name", "").lower() for x in ["apt", "lazarus", "fin", "apt28", "apt29"])})
        else:
            whois_data = query_whois(target)
            feeds["WHOIS"] = whois_data
            feeds["SSL"] = query_crtsh(target)
            feeds["PassiveDNS"] = query_otx_passivedns(target)
            feeds["CampaignTags"] = []
            if not whois_data.get("creation_date"):
                print(f"[DEBUG] WHOIS creation_date raw: {whois_data.get('creation_date')}")

        # ASN fallback from Netlas
        geoip = feeds.get("GeoIP", {})
        if not geoip.get("asn") or geoip.get("asn") == "AS0":
            netlas_geo = feeds.get("Netlas", {}).get("asn", {})
            if isinstance(netlas_geo, dict) and netlas_geo.get("asn"):
                geoip["asn"] = netlas_geo["asn"]
                geoip["asn_org"] = netlas_geo.get("org", "")
                feeds["GeoIP"] = geoip
                print(f"[FALLBACK] ASN from Netlas for {target}")

        # Web3 check
        web3_result = {}
        if is_crypto_relevant(target):
            feeds["WalletTags"] = ["suspected_wallet"]
            web3_result = check_web3_reputation(target, scamsniffer_blacklist)
            feeds["Web3"] = web3_result
        else:
            feeds["WalletTags"] = []
            feeds["Web3"] = {}

        # Scoring
        threat = calculate_threat_score(feeds) if is_ip else calculate_domain_threat_score(feeds)
        osint_score, osint_tags = calculate_osint_score(feeds, threat) if is_ip else calculate_domain_osint_score(feeds)

        try:
            context, context_tags = calculate_context_score(feeds) if is_ip else calculate_domain_context_score(feeds)
        except Exception as e:
            print(f"[CTX ERROR] {target}: {e}")
            context, context_tags = -1, []

        if web3_result.get("web3_score"):
            context += web3_result["web3_score"]
        if web3_result.get("web3_tags"):
            context_tags.extend(web3_result["web3_tags"])
            osint_tags.extend(web3_result["web3_tags"])

        feeds["OSINT_SCORE"] = osint_score
        feeds["OSINT_TAGS"] = osint_tags

        all_tags = set(context_tags + osint_tags)
        if labels.get(target):
            all_tags.add(labels[target])

        print(f"[INDEX] {target} — Type: {'IP' if is_ip else 'Domain'}, Threat: {threat}, Context: {context}, OSINT: {osint_score}, Tags: {list(all_tags)}, Label: {labels.get(target)}")

        insert_or_update_ioc(target, "IP" if is_ip else "Domain", feeds, threat)
        index_enriched(target, feeds, threat, context, context_tags, label=labels.get(target))

        arkime_tag_indicator(
            target=target,
            tags=list(all_tags),
            is_ip=is_ip
        )

        write_enriched_json(target, {
            "target": target,
            "type": "IP" if is_ip else "Domain",
            "threat_score": threat,
            "context_score": context,
            "osint_score": osint_score,
            "feeds": feeds,
            "tags": list(all_tags),
            "label": labels.get(target)
        })

        time.sleep(1)

