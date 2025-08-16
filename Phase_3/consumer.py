from kafka import KafkaConsumer
import json

consumer = KafkaConsumer(
    'zeek_alerts', 'suricata_alerts',
    bootstrap_servers='localhost:9092',
    auto_offset_reset='earliest',
    enable_auto_commit=True,
    group_id='enrichment_group',
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

print("[CONSUMER] Listening for alerts...")
for message in consumer:
    print(f"[ALERT] Topic={message.topic}, Data={message.value}")
