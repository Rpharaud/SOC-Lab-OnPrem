import sqlite3, time

DB_NAME = "threatintel_cache.db"
MAX_AGE_DAYS = 30

def cleanup_old():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    cutoff = int(time.time()) - MAX_AGE_DAYS * 86400
    c.execute("DELETE FROM ioc_cache WHERE last_seen < ?", (cutoff,))
    deleted = conn.total_changes
    conn.commit()
    conn.close()
    print(f"[CLEANUP] Deleted {deleted} stale IOCs older than {MAX_AGE_DAYS} days")

if __name__ == "__main__":
    cleanup_old()
