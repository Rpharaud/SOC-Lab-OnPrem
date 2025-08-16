# Phase 1.5 — Edge Case Detection & Log Enrichment

## Overview
Phase 1.5 extends the SOC Lab by validating detection coverage for edge cases, ensuring robust pipelines for real-world scenarios. This phase includes custom Zeek and Suricata configurations, Arkime ingestion validation, and parser tuning using Logstash and Filebeat.

## Objectives
- Design and test edge cases (extreme values, boundary conditions, malformed logs)
- Tune detection pipelines to handle edge conditions gracefully
- Validate ingestion pipelines with Arkime, Elasticsearch, and Logstash
- Document runbooks, commands, and acronyms for repeatability

## Repo Structure
- `edge_cases/` — Table of all edge cases tested
- `configs/` — Custom Suricata rules, Zeek scripts, Logstash pipelines, Filebeat config
- `logs/` — Sample test logs and malformed JSON examples
- `screenshots/` — Proof of ingestion, Arkime session view, Zeek & Suricata output
- `appendix/` — Commands used, acronyms list

## 📸 Screenshots

Below are selected screenshots demonstrating detection coverage and edge case validation:

- **Figure 1** — Zeek DNS log Detection  
  ![Figure 1](./screenshots/Figure1_Zeek_DNS_log_Detection.png)

- **Figure 2** — Zeek SSH log Detection  
  ![Figure 2](./screenshots/Figure2_Zeek_SSH_log_Detection.png)

- **Figure 3** — HTTP log Spike Alert  
  ![Figure 3](./screenshots/Figure3_HTTP_log_Spike_Alert.png)

- **Figure 4** — Suricata Eve JSON log  
  ![Figure 4](./screenshots/Figure4_Suricata_Eve_Json.png)

- **Figure 5** — SSL log Weak Cipher  
  ![Figure 5](./screenshots/Figure5_SSL_log_Weak_Cipher.png)

- **Figure 6** — Zeek Conn log Beacon Detection  
  ![Figure 6](./screenshots/Figure6_Zeek_Conn_log_Beacon.png)

- **Figure 7** — Zeek Conn log Reverse Shell  
  ![Figure 7](./screenshots/Figure7_Zeek_Conn_log_Reverse_Shell.png)

- **Figure 8** — Zeek DNS log Large TXT Record  
  ![Figure 8](./screenshots/Figure8_Zeek_DNS_log_Large_TXT.png)

- **Figure 9** — Elasticsearch Indices for Various Edge Cases  
  ![Figure 9](./screenshots/Figure9_Elasticsearch_Indices.png)

- **Figure 10** — Elasticsearch Index Template Mismatch  
  ![Figure 10](./screenshots/Figure10_Elasticsearch_Index_Template_Mismatch.png)

- **Figure 11** — Arkime SPIView Missing GEO/ASN Metadata  
  ![Figure 11](./screenshots/Figure11_Arkime_SPIView_Missing_GEO_ASN.png)

- **Figure 12** — Evidence of Large PCAP for Stress Test  
  ![Figure 12](./screenshots/Figure12_Large_PCAP_Stress_Test.png)

- **Figure 13** — Arkime SPIView Fields with No GEO for Private IP  
  ![Figure 13](./screenshots/Figure13_Arkime_SPIView_PrivateIP_NoGEO.png)


## Next Steps
Transition to Phase 2: Threat Intelligence Enrichment Pipeline and Phase 3: Automated Alerting & Correlation.
