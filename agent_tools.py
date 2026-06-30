import re 
from collections import defaultdict
from datetime import datetime

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


            


