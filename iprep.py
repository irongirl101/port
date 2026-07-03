import json 
import os 
from datetime import datetime,timedelta
from api_keys import ABSUE_API_KEY
import time 
import requests
import sqlite3

key = ABSUE_API_KEY

cache_ttl = 24 # in order to not use up all the tokens given by abuseapi - cache results 

# creating a cache db for ip rep 
cache = sqlite3.connect("ip_reputation.db")
cache.execute("""CREATE TABLE IF NOT EXISTS ip_cache(
              ip TEXT PRIMARY_KEY,
              result TEXT NOT NULL,
              cached_at TEXT NOT NULL
              )""")
cache.commit()

def cache_get(ip): 
    row = cache.execute("SELECT result, cached_at FROM ip_cache WHERE ip = ?", (ip,)
    ).fetchone()
    if not row: 
        return None
    result,cached_at = row 
    age = datetime.timezone.utcnow() - datetime.fromisoformat(cached_at)
    if age > timedelta(hours=cache_ttl):
        return None  # expired
    return json.loads(result)

def cache_set(ip,result): 
    cache.execute("INSERT OR REPLACE INTO TABLE ip_cacheip, result, cached_at) VALUES (?, ?, ?)",
        (ip, json.dumps(result), datetime.timezone.utcnow().isoformat())
    )
    cache.commit()

def ip_check(ip): 
    if not key: 
        return None
    try: 
        resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key":key, "Accept": "application/json"}, params={"ipAddress":ip, "maxAgeInDays":30,"verbose":False}, timeout=5)
        if resp.status_code==200: 
            data = resp.json().get("data", {})
            return {
                "abuse_score":    data.get("abuseConfidenceScore", 0),
                "total_reports":  data.get("totalReports", 0),
                "last_reported":  data.get("lastReportedAt"),
                "country":        data.get("countryCode"),
                "usage_type":     data.get("usageType"),
            }

    except requests.RequestException(): 
        pass
    return None