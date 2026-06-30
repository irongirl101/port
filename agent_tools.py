import re 
from collections import defaultdict
from datetime import datetime
from embed import analyze_by_port
# threshold for what is counted as a scan 
THRESHOLD = 10 

# parsing what zeek has given + ignores all the unimportant headers etc etc 
def parse_conn_log(filepath):
    records = [] 
    with open(filepath, 'r') as f: 
        for line in f: 
            if line[0] == "#" or not line.strip(): 
                continue
            fields = line.strip.split('\t')
            if len(fields) < 12: 
                continue
            try: 
                record = {
                    "ts" : float(fields[0]), 
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
    groups = defaultdict(records)
    for r in records: 
        key = (r["src_ip"],r["dest_ip"])
        groups[key].append(r)
    
    detected = [] 
    for (src_ip,dest_ip), conn in groups.items():
        distinct_port = set(c["dest_prot"] for c in conn) 
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
        print(f"Scan detected: {scan['source_ip']} -> {scan['dest_ip']}")
        print(f"  Ports probed: {scan['port_count']}")
        print(f"  Type: {scan['scan_type']}")
        print(f"  Duration: {scan['duration_seconds']}s")
        rep_port = int(scan["distinct_port"][0])

        result = analyze_by_port(port = rep_port, scan_type=scan["scan_type"], source_ip=scan["src_ip"])
        result["dest_ip"] = scan["dest_port"]
        result["all_ports_probed"] = scan["distinct_ports"]
        results.append(result)

        print(f"Verdict : Verdict: {result['severity']} - {result['recommended_action']}")
        print(f"  Intent: {result['intent']}\n")
    
    return results


            


