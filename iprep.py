import json 
import os 
from datetime import datetime,timezone, timedelta
from api_keys import ABUSE_API_KEY
import time 
import requests
import sqlite3

key = ABUSE_API_KEY

cache_ttl = 24 # in order to not use up all the tokens given by abuseapi - cache results 

# creating a cache db for ip rep 
cache = sqlite3.connect("ip_reputation.db")
cache.execute("""CREATE TABLE IF NOT EXISTS ip_cache(
              ip TEXT PRIMARY KEY,
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
    age = datetime.now(timezone.utc) - datetime.fromisoformat(cached_at)
    if age > timedelta(hours=cache_ttl):
        return None  # expired
    return json.loads(result)

def cache_set(ip,result): 
    cache.execute("""
INSERT OR REPLACE INTO ip_cache
(ip, result, cached_at)
VALUES (?, ?, ?)
""",
        (ip, json.dumps(result), datetime.now(timezone.utc))
    )
    cache.commit()

def ip_check_abuseipdb(ip): 
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

def check_internetdb(ip): 
    try: 
        resp = requests.get(f"https://internetdb.shodan.io/{ip}",
            timeout=5
        )
        if resp.status_code == 200: 
            data = resp.json()
            return{
                 "open_ports": data.get("ports", []),
                "tags":       data.get("tags", []),
                "hostnames":  data.get("hostnames", []),
                "vulns":      data.get("vulns", []),
            }
    except requests.RequestException(): 
        pass
    return None


# checks agsinst a local cache + abuseipdb + internetdb from shodan
# returns a dict of rep, confidence, action, details 
def ip_check(ip): 
    print(ip)
    cached = cache_get(ip)
    if cached: 
        return cached
    # skeleton for result 
    result = {
        "ip":ip, 
        "rep": "unknown", 
        "confidence":0, 
        "action":"unknown", 
        "details":{}
    }
    
    abuse = ip_check_abuseipdb(ip)
    if abuse: 
        result["details"]["abuseipdb"] = abuse 
        score = abuse["abuse_score"]
        if score >= 80:
            result.update({
                "rep": "known_bad",
                "confidence": score,
                "action":     "block"
            })
        elif score >= 40:
            result.update({
                "rep": "suspicious",
                "confidence": score,
                "action":     "escalate"
            })
        elif score >= 10:
            result.re({
                "rep": "suspicious",
                "confidence": score,
                "action":     "monitor"
            })

    internetdb = check_internetdb(ip) 
    if internetdb:
        result["details"]["internetdb"] = internetdb
        # "scanner" tag from Shodan means it's been identified
        # as a known scanning host by their honeypot network
        if "scanner" in internetdb.get("tags", []):
            if result["rep"] == "unknown":
                result.update({
                    "rep": "known_scanner",
                    "confidence": 85,
                    "action":     "ignore"
                })
    #print("inserting: ", ip)
    cache_set(ip, result)
    return result


