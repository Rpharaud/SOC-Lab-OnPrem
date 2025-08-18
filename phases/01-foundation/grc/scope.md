# System Boundary & Scope (Phase 1)

**System Name:** Enterprise Architecture Lab  
**Environment:** On-prem lab (single host + bridged/host-only segments)  
**Pillars in scope:** SOC, Crypto, Red, DevSecOps, GRC (Phase 1 only)

## Boundary
- Zeek, Suricata, Arkime on `regserver` and lab subnet `192.168.64.0/24`
- Elasticsearch/OpenSearch backing Arkime
- Local PKI (Root + Intermediate), service certs (Arkime viewer TLS)

## Data
- Packet metadata (Arkime/Zeek), logs, detection configs
- No production PII; lab test data only

## Assumptions
- Single-admin model; self-hosted runner on `regserver`
- Access via VPN or local LAN; least-privileged SSH access enforced
