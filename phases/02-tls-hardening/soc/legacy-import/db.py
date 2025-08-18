import sqlite3
import json
import time


DB_NAME = "threatintel_cache.db"

def create_table():
    print(" [DEBUG] Running create_table()")
    conn = sqlite3.connect("threatintel_cache.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ioc_cache (
        ioc TEXT PRIMARY KEY,
        ioc_type TEXT,
        feeds TEXT,
        threat_score INTEGER,
        last_seen INTEGER
    )
    """)
    conn.commit()
    conn.close()

def insert_or_update_ioc(ioc, ioc_type, feeds, threat_score):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    now = int(time.time())
    c.execute("""
        INSERT INTO ioc_cache (ioc, ioc_type, feeds, threat_score, last_seen)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ioc) DO UPDATE SET feeds = ?, threat_score = ?, last_seen = ?
    """, (ioc, ioc_type, json.dumps(feeds), threat_score, now, json.dumps(feeds), threat_score, now))
    conn.commit()
    conn.close()

def fetch_ioc(ioc):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT feeds, threat_score FROM ioc_cache WHERE ioc=?", (ioc,))
    row = c.fetchone()
    if row:
        now = int(time.time())
        c.execute("UPDATE ioc_cache SET last_seen=? WHERE ioc=?", (now, ioc))
        conn.commit()
    conn.close()
    if row:
        feeds = json.loads(row[0])
        return {"feeds": feeds, "threat_score": row[1]}
    return None

