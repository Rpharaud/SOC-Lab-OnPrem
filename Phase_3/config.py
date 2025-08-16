# config.py
KAFKA_BROKER = "localhost:9092"
ZEEK_TOPIC = "zeek_alerts"
SURICATA_TOPIC = "suricata_alerts"

# Paths to logs
ZEEK_LOG = "/opt/zeek/logs/current/notice.log"
SURICATA_LOG = "/var/log/suricata/eve.json"
