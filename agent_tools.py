import re 
from collections import defaultdict
from datetime import datetime
import json
from embed import analyze_by_port,init_embed_db


# threshold for what is counted as a scan 
THRESHOLD = 10 

init_embed_db() 

# parsing what zeek has given + ignores all the unimportant headers etc etc 
def parse_conn_log(filepath):
    records = [] 
    with open(filepath, 'r') as f: 
        for line in f: 
            if line[0] == "#" or not line.strip(): 
                continue
            fields = line.strip().split('\t')
            if len(fields) < 12: 
                continue
            try: 
                record = {
                    "ts" : float(fields[0]),  # time stamp 
                    "hash" : fields[1],
                    "src_ip": fields[2],
                    "src_port": fields[3],
                    "dest_ip": fields[4],
                    "dest_port":fields[5],
                    "protocol": fields[6],
                    "conn_state": fields[11]
                }
                records.append(record)
            except (ValueError,IndexError):
                continue
    return records

# groupds records by source and dest ip, flags any pair thats above the threshold. returns a list of summaries 
def detect_scan(records, threshold = THRESHOLD): 
    groups = defaultdict(list)
    for r in records: 
        key = (r["src_ip"],r["dest_ip"])
        groups[key].append(r)
    
    detected = [] 
    for (src_ip,dest_ip), conn in groups.items():
        distinct_port = set(c["dest_port"] for c in conn) 
        if len(distinct_port) >= threshold: 
            timestamp = [c["ts"] for c in conn]
            first = min(timestamp)
            last = max(timestamp)
            duration = last-first

            state = defaultdict(int)
            for c in conn: 
                state[c["conn_state"]]+=1
            dom_state = max(state,key = state.get)

            scan_type_map = {
                "S0": "SYN scan (no response)",
                "REJ": "scan (connection rejected)",
                "RSTR": "scan (reset by responder)",
                "SF": "completed connection scan",
            }
            scan_type = scan_type_map.get(dom_state, f"unknown pattern ({dom_state})")
            detected.append({
                "src_ip" : src_ip, 
                "dest_ip" : dest_ip,
                "distinct_ports" : sorted(distinct_port,key = int),
                "port_count" : len(distinct_port), 
                "duration" :round(duration,3),
                "scan_type": scan_type,
                "first_seen": datetime.fromtimestamp(first).isoformat() })
    return detected

# calls analyze port from main.py when required 
def process_log(filepath): 
    records = parse_conn_log(filepath)
    scans = detect_scan(records)
    print(f"Detected {len(scans)} scan pattern(s) "
          f"(threshold: {THRESHOLD}+ distinct ports).\n")

    results = []
    for scan in scans:
        print(f"Scan detected: {scan['src_ip']} -> {scan['dest_ip']}")
        print(f"  Ports probed: {scan['port_count']}")
        print(f"  Type: {scan['scan_type']}")
        print(f"  Duration: {scan['duration']}s")
        rep_port = int(scan["distinct_ports"][0])

        result = analyze_by_port(port = rep_port, scan_type=scan["scan_type"], source_ip=scan["src_ip"])
        result["dest_ip"] = scan["dest_ip"]
        result["all_ports_probed"] = scan["distinct_ports"]
        results.append(result)

        print(f"Verdict : Verdict: {result['severity']} - {result['recommended_action']}")
        print(f"  Intent: {result['intent']}\n")
    
    return results

# parse eve.json suricata and resturns a list of alert events only 
def parse_json(filepath): 
    alerts = [] 
    with open(filepath,"r") as f: 
        for line in f: 
            line = line.strip()
            if not line:
                continue
            try: 
                event = json.loads(line)
            except json.JSONDecodeError: 
                continue

            if event.get('event_type') != "alert": 
                continue
            alert = event.get("alert",{})

            alerts.append({
                "timestamp":  event.get("timestamp"),
                "src_ip":     event.get("src_ip"),
                "src_port":   event.get("src_port"),
                "dest_ip":    event.get("dest_ip"),
                "dest_port":  event.get("dest_port"),
                "proto":      event.get("proto"),
                "signature":  alert.get("signature"),
                "severity":   alert.get("severity"),
                "category":   alert.get("category"),
                "signature_id": alert.get("signature_id"),
            })
    return alert

# summarize and find out scan pattern - ports by dict 
def summarize(alerts):
    by_port ={}
    for alert in alerts: 
        port = alert.get("dest_port")
        if port not in by_port:
            by_port[port] = {
                "dest_port":  port,
                "src_ips":    set(),
                "signatures": [],
                "severity":   alert["severity"],
            }
        by_port[port]["src_ips"].add(alert["src_ip"])
        by_port[port]["signatures"].append(alert["signature"])
        if alert["severity"] and alert["severity"] < by_port[port]["severity"]:
            by_port[port]["severity"] = alert["severity"]
        
    for port in by_port:
        by_port[port]["src_ips"] = list(by_port[port]["src_ips"])

    return by_port




if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python agent_tools.py <path-to-conn.log>")
        sys.exit(1)
    process_log(sys.argv[1])
            


