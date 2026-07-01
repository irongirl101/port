import ollama
import sqlite3
import numpy as np
from database import Session,CVE 

# creation of embeddings table 
session = Session() 
emb = sqlite3.connect("embeddings.db")
emb.execute("""CREATE TABLE IF NOT EXISTS embeddings(
            id INTEGER, 
            cve_id TEXT NOT NULL,
            port INTEGER, 
            embedding BLOB NOT NULL, 
            PRIMARY KEY(id))""")
emb.commit() 

EMBEDDING_MODEL ='hf.co/CompendiumLabs/bge-base-en-v1.5-gguf'
LANGUAGE_MODEL = 'hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF'

VECTOR_DB = [] 

#add embedding values into the database, by creating into a blob and inserting into the table. 
def save_embedding(id,cve_id,port,embedding): 
    blob= np.array(embedding, dtype=np.float32).tobytes()
    emb.execute("""INSERT OR REPLACE INTO embeddings (id,cve_id,port,embedding) VALUES (?,?,?,?)""",(id,cve_id,port,blob))
    emb.commit()

# loads all the embedded values, and adds to vector_db 
def load_embedding(): 
    VECTOR_DB.clear() 
    rows = emb.execute("""SELECT id,cve_id,port,embedding FROM embeddings""").fetchall()
    for id,cve_id,port,blob in rows: 
        vector = np.frombuffer(blob,dtype=np.float32).tolist() 
        cve_row = session.query(CVE).filter_by(id=id).first()
        if cve_row:
            severity = (
                "Critical" if cve_row.cvss >= 9 else
                "High" if cve_row.cvss >= 7 else
                "Medium" if cve_row.cvss >= 4 else
                "Low"
                        )
            chunk = f"""
            CVE ID: {cve_row.cve_id}
            Port: {cve_row.port}
            Application: {cve_row.application}
            Severity: {severity}
            CVSS Score: {cve_row.cvss}
            Description: {cve_row.description}
            """
            VECTOR_DB.append({
                "chunk": chunk,
                "embedding": vector,
                "cve_id": cve_id,
                "port": port,
                "cvss": cve_row.cvss
            })

# finds the unembedded values 
def get_unembbeded(): 
    embedded = {
        row[0]
        for row in emb.execute(
            "SELECT id FROM embeddings"
        ).fetchall()
    }
    rows = session.query(CVE).all()
    return [
        r for r in rows
        if (r.id) not in embedded
    ]

# initializes the database 
def init_embed_db(): 
    load_embedding()
    missing = get_unembbeded() 
    for cve_row in missing: 
        if cve_row:
            severity = (
                "Critical" if cve_row.cvss >= 9 else
                "High" if cve_row.cvss >= 7 else
                "Medium" if cve_row.cvss >= 4 else
                "Low"
                        )
            chunk = f"""
            CVE ID: {cve_row.cve_id}
            Port: {cve_row.port}
            Application: {cve_row.application}
            Severity: {severity}
            CVSS Score: {cve_row.cvss}
            Description: {cve_row.description}
            """
            try:
                embedding = ollama.embed(
                    model=EMBEDDING_MODEL,
                    input=chunk
                )['embeddings'][0]
            except Exception as e:
                print(f"Failed on {cve_row.cve_id}")
                print(repr(e))
            
            save_embedding(cve_row.id,cve_row.cve_id,cve_row.port,embedding)

            VECTOR_DB.append({
                "chunk": chunk,
                "embedding": embedding,
                "cve_id": cve_row.cve_id,
                "port": cve_row.port,
                "cvss": cve_row.cvss
            })

def cosine_similarity(a,b): 
    if len(a)!=len(b): 
        raise ValueError(f"Embedding size mismatch: {len(a)} vs {len(b)}")
    
    dot_product = sum(x*y for x,y in zip(a,b))
    norm_a = sum(x*x for x in a) ** 0.5
    norm_b = sum(y*y for y in b) ** 0.5

    if norm_a == 0 or norm_b == 0: 
        return 0 
    return dot_product/(norm_b*norm_a)

def retrieve(query, top_n = 3): 
    query_embedding = ollama.embed(model=EMBEDDING_MODEL,input=query)['embeddings'][0]
    similarities = []
    for item in VECTOR_DB: 
        sim = cosine_similarity(query_embedding,item["embedding"])
        similarities.append({
            "chunk": item["chunk"],
            "similarity": sim,
            "cve_id": item["cve_id"],
            "port": item["port"],
            "cvss": item["cvss"]
            })
    similarities.sort(key=lambda x:x['similarity'], reverse=True)
    return similarities[:top_n]

def retrieve_by_port(port,top_n=5): 
    matches = [item for item in VECTOR_DB if item["port"]== port]
    matches.sort(key=lambda x:x["cvss"], reverse=True)
    return matches[:top_n]


def analyze_by_port(port, scan_type = None, source_ip = None): # will only work when suricata and zeek and libpcap has been introduced 
    port_match = retrieve_by_port(port,top_n=3)
    event_desc = (
        f"Port scan detected on port {port}. "
        f"Scan type: {scan_type or 'unknown'}. "
        f"Source IP: {source_ip or 'unknown'}."
    )
    semantic = retrieve(event_desc,top_n=3)

    seen = {} 
    for item in port_match + semantic: 
        cve_id = item["cve_id"]
        if cve_id not in seen or item["cvss"] > seen[cve_id]["cvss"]:
            seen[cve_id] = item
    merged = sorted(seen.values(), key=lambda x:x["cvss"], reverse=True)[:5]

    if not merged:
        return {
            "port": port,
            "source_ip": source_ip,
            "scan_type": scan_type,
            "matched_cves": [],
            "intent": "unknown",
            "severity": "unknown",
            "recommended_action": "monitor",
            "reasoning": "No CVE data found for this port."
        }
    context = "\n\n".join(item["chunk"] for item in merged)
    system_prompt = f"""
You are a cybersecurity triage assistant analyzing a port scan event.

A port scan was detected:
    Source IP:  {source_ip or 'unknown'}
    Port:       {port}
    Scan type:  {scan_type or 'unknown'}

The following CVEs are associated with this port:

{context}

Based ONLY on the above CVE information, respond in this exact format:

INTENT: <what the attacker is likely after, one sentence>
SEVERITY: <Critical | High | Medium | Low>
ACTION: <block | escalate | monitor | ignore>
REASONING: <one or two sentences explaining the verdict>
"""

    response = ollama.chat(
        model=LANGUAGE_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this port scan on port {port}."}
        ]
    )

    raw = response["message"]["content"]

    
    def extract(label, text):
        for line in text.splitlines():
            if line.strip().upper().startswith(label + ":"):
                return line.split(":", 1)[1].strip()
        return "unknown"

    return {
        "port": port,
        "source_ip": source_ip,
        "scan_type": scan_type,
        "matched_cves": [
            {"cve_id": i["cve_id"], "cvss": i["cvss"]}
            for i in merged
        ],
        "intent":    extract("INTENT",    raw),
        "severity":  extract("SEVERITY",  raw),
        "recommended_action": extract("ACTION", raw),
        "reasoning": extract("REASONING", raw),
        "raw_llm_response": raw
    }

result = analyze_by_port(
    port=7878,
    scan_type="SYN",
    source_ip="192.168.1.50"
)

print(f"Intent:   {result['intent']}")
print(f"Severity: {result['severity']}")
print(f"Action:   {result['recommended_action']}")
print(f"Reason:   {result['reasoning']}")
print(f"CVEs:     {result['matched_cves']}")

