# Appendix B — Commands Used

This appendix lists the core commands used during Phase 1.5 for validation, enrichment, replay, and ingestion of edge case data.

---

## 📡 **Elasticsearch & API Checks**

| Command | Explanation |
|-----------------|-------------|
| `curl -u username:password -k "https://localhost:9200/_cat/indices?v"` | List all indices and their health status |
| `curl -u user:password -k -X GET/POST/DELETE "https://localhost:9200/zeek-*/_search?q=uid=testuid&pretty"` | Query, add, or delete specific index data for test events |
| `curl -u username:password -k "https://localhost:9200/zeek-*/_mapping?pretty"` | View index mappings and field structures |

---

## 🕵️ **Arkime & PCAP Handling**

| Command | Explanation |
|-----------------|-------------|
| `sudo /opt/arkime/bin/capture -r /opt/pcaps/test_sample.pcap -n test-source` | Replay PCAP file for Arkime indexing and session metadata creation |
| `editcap -c 1000 bigfile.pcap chunked_part.pcap` | Split large PCAP into smaller, manageable segments |
| `sudo tcpdump -i <interface> -w live_test.pcap` | Capture live packets for later replay and detection tuning |
| `sudo tcpreplay -i <interface> test_traffic.pcap` | Replay PCAP traffic to network interface for Zeek/Suricata ingestion |

---

## 🌐 **GeoIP Updates**

| Command | Explanation |
|-----------------|-------------|
| `sudo geoipupdate` | Sync MaxMind GeoIP2 City and ASN database for up-to-date geolocation enrichment |

---

## 🔍 **Filebeat & Logstash Pipeline Debug**

| Command | Explanation |
|-----------------|-------------|
| `sudo filebeat -e -d "multiline,harvester"` | Run Filebeat with multiline and harvester debug for edge case parsing |
| `sudo systemctl restart logstash` | Restart Logstash to apply new pipeline rules (standard) |
| `sudo tail -f /var/log/logstash/logstash-plain.log` | Live tail Logstash logs for parsing errors |

---

## ✅ **Optional General Checks**

| Command | Explanation |
|-----------------|-------------|
| `sudo systemctl status elasticsearch` | Verify Elasticsearch service status |
| `sudo systemctl restart elasticsearch` | Restart Elasticsearch if mapping changes or config updates |
| `sudo systemctl status arkimeviewer` | Check Arkime Viewer status |
| `curl -I localhost:5601` | Verify Kibana port (if used in earlier phases) |

---

## 🔑 **Notes**

- Replace `<interface>` with your actual network interface (e.g., `eth0` or `en0`).
- Use test PCAPs only; do not replay production traffic.
- All commands assume local testing on secure, isolated lab infrastructure.

---

**End of Appendix B**
