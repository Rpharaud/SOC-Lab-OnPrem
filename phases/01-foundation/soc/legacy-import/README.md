# 🛡️ SOC Lab: Phase 1 – On-Prem Lab Foundation

This repository contains the configuration files and documentation for Phase 1 of a hands-on SOC (Security Operations Center) lab deployed on an **ARM64 Ubuntu server**. The goal of this phase is to build a lean, self-contained environment for capturing, analyzing, and visualizing network traffic without relying on the full ELK stack.

---

## 🚀 Lab Overview

**Objective:**  
Establish a hardened, on-prem SOC using lightweight open-source tools for packet capture, threat detection, and metadata visualization.

**Tools Installed:**
- [Zeek](https://zeek.org/) – Network traffic analyzer
- [Suricata](https://suricata.io/) – IDS/IPS engine
- [Arkime](https://arkime.com/) – Full-packet capture & visual analysis
- [Elasticsearch](https://www.elastic.co/elasticsearch) – Storage backend for Arkime metadata
- [Filebeat](https://www.elastic.co/beats/filebeat) – Log forwarder for Zeek/Suricata JSON

---

## 🗂️ Repo Contents

| File/Folder | Description |
|-------------|-------------|
| `configs` | Sanitized Arkime, Suricata, and Filebeat configuration |
| `README.md` | This documentation file |

---

## 🔒 Security Hardening

- SSH key-based access configured
- UFW firewall enabled with port restrictions
- Fail2Ban enabled for SSH brute-force protection

---

## 📈 Live Log Sources

| Source | Log File Path |
|--------|----------------|
| Zeek | `/opt/zeek/logs/current/*.log` |
| Suricata | `/var/log/suricata/eve.json` |

---

## 🧪 How to Replicate

1. Clone the repo:
   ```bash
   git clone https://github.com/your-username/SOC-Lab-OnPrem.git
   cd SOC-Lab-OnPrem
