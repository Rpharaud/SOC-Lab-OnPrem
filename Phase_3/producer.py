import json
import time
import os
from kafka import KafkaProducer
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from config import KAFKA_BROKER, ZEEK_TOPIC, SURICATA_TOPIC, ZEEK_LOG, SURICATA_LOG

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

def send_to_kafka(topic, data):
    producer.send(topic, data)
    producer.flush()
    print(f"[PRODUCER] Sent to {topic}: {data}")

class LogHandler(FileSystemEventHandler):
    def __init__(self, source, topic):
        self.source = source
        self.topic = topic
        self.last_pos = 0

    def on_modified(self, event):
        if event.src_path == self.source:
            with open(self.source, "r") as f:
                f.seek(self.last_pos)
                for line in f:
                    try:
                        alert = self.parse_alert(line)
                        if alert:
                            send_to_kafka(self.topic, alert)
                    except Exception as e:
                        print(f"[ERROR] {e}")
                self.last_pos = f.tell()

    def parse_alert(self, line):
        if self.topic == SURICATA_TOPIC:
            data = json.loads(line)
            if "alert" in data:  # Suricata alert event
                return {
                    "src_ip": data.get("src_ip"),
                    "dest_ip": data.get("dest_ip"),
                    "alert": data["alert"].get("signature"),
                    "severity": data["alert"].get("severity")
                }
        elif self.topic == ZEEK_TOPIC:
            if not line.startswith("#"):  # Skip Zeek header lines
                fields = line.strip().split("\t")
                # Basic: ts, uid, id.orig_h, id.resp_h, note
                if len(fields) >= 5:
                    return {
                        "src_ip": fields[2],
                        "dest_ip": fields[3],
                        "alert": fields[4],
                        "severity": "info"  # Zeek doesn't have built-in severity
                    }
        return None

if __name__ == "__main__":
    zeek_handler = LogHandler(ZEEK_LOG, ZEEK_TOPIC)
    suricata_handler = LogHandler(SURICATA_LOG, SURICATA_TOPIC)

    observer = Observer()
    observer.schedule(zeek_handler, os.path.dirname(ZEEK_LOG), recursive=False)
    observer.schedule(suricata_handler, os.path.dirname(SURICATA_LOG), recursive=False)

    observer.start()
    print("[PRODUCER] Live producer started. Watching Zeek & Suricata logs...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
