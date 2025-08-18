import sqlite3
import json

DB_PATH = "threatintel_cache.db"

def trim_feed(feeds):
    try:
        vt = feeds.get("VirusTotal", {}).get("data", {})
        attributes = vt.get("attributes", {})

        return {
            "VirusTotal": {
                "id": vt.get("id"),
                "reputation": attributes.get("reputation"),
                "as_owner": attributes.get("as_owner"),
                "link": vt.get("links", {}).get("self")
            },
            "AbuseIPDB": feeds.get("AbuseIPDB", {}),
            "OTX": feeds.get("OTX", {}),
            "GreyNoise": feeds.get("GreyNoise", {}),
            "AbuseCH": feeds.get("AbuseCH", {})
        }
    except Exception as e:
        print(f"[ERROR] Feed trim failed: {e}")
        return feeds  # fallback to original

def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT ioc, feeds FROM ioc_cache")
    rows = cursor.fetchall()

    for ioc, feed_json in rows:
        try:
            feeds = json.loads(feed_json)
            trimmed = trim_feed(feeds)
            trimmed_json = json.dumps(trimmed)
            cursor.execute(
                "UPDATE ioc_cache SET feeds = ? WHERE ioc = ?",
                (trimmed_json, ioc)
            )
        except Exception as ex:
            print(f"[WARN] Failed to trim IOC {ioc}: {ex}")

    conn.commit()
    conn.close()
    print("[DONE] IOC cache trimmed.")

if __name__ == "__main__":
    main()
