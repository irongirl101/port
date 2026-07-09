# Sentry

### Sentry is a layered detection agent, that sits on the network interface and identifies port scanning behaviour in real time. 

``` 
Port Scanning is a form of technique used to probe a device or network to determine which ports are closed, open or filtered. Malicious attackers use this technique as a form of reconnaissance, checking which doors are open that they may be able to exploit. 
```

Sentry, as a triage agent, can detect if any reconnaissance activity or port scanning behaviour, using LLMs and other tools like Zeek, Suricata and libpcap. 
(Note: this agent is not a live product as of yet.)


## Architecture 
```
    -----------------          -----------------        -----------------       -----------------       -----------------
    |    Traffic    |          |    Traffic    |        |   Signature   |       |    Triage     |       |               |
    |    Capture    | -------> |    History/   | ------>|   Detection   |------>|    Agent      |------>|    Result     |
    |      (1)      |          |     Logs (2)  |        |     (3)       |       |     (4)       |       |     (5)       |
    -----------------          -----------------        -----------------       -----------------       -----------------
```

### Why an LLM? 
Traditional IDS solutions excel at detecting known attack signatures but often struggle to explain alerts, correlate evidence across multiple sources, or prioritize analyst attention. Sentry uses a local LLM only after deterministic detection has narrowed the search space. Rather than replacing traditional security tooling, the model synthesizes evidence from Zeek, Suricata, IP reputation feeds, and a CVE knowledge base into a concise incident assessment, reducing analyst effort while keeping inference costs low.
   
**(1) Traffic Capture - libpcap** 

It captures the raw data of the packet - source and destination IP addresses and ports, payload, protocol, flags, timestamps, etc. 
This creates the foundation for which the tools will work on. 

**(2) Traffic History/Logs - Zeek** 

Parses packets into structured connection logs: who connected to what, when, how, and for how long. Provides behavioural context, pattern detection across connections, slow scan detection, and distributed scan detection — particularly useful when Suricata does not flag a scan due to larger timing gaps.

**(3) Signature Detection - Suricata** 

Port scanners usually operate with the help of scan patterns, like SYN, FIN, NULL, XMAS, UDP scans. Suricata helps in matching the traffic against 50,000+ community rules from the Emerging Threats Open ruleset.

**(4) Triage Agent - ollama + ip reputation lookup** 

The triage agent correlates evidence from four independent sources to produce a structured security assessment.
Combines four pillars to produce a verdict:
- Zeek connection pattern analysis
- Suricata signature match results
- IP reputation (AbuseIPDB + Shodan
  InternetDB, locally cached)
- CVE RAG pipeline: embeddings of a port-confirmed CVE database queried against the detected event, with an LLM producing a structured verdict (intent, severity, recommended action) False positive filtering, scan type classification, and attacker profiling happen at this layer. Expensive LLM calls are gated behind local filtering so the majority of decisions are handled for free.

**(5) Result - Incident Report** 

Structured output per detected scan: source IP, ports probed, scan type, IP reputation, matched CVEs, attacker intent, severity. 

The full stack is designed to be cost-efficient, with expensive model calls gated behind local filtering that handles the majority of decisions for free.

## Sample Output: 
```
Detected 1 scan pattern(s) (threshold: 10+ distinct ports).

Suricata alerts: 0 (none — no signature matches).

Scan detected: 192.168.100.103 -> 192.168.100.102
  Ports probed: 1000
  Type: SYN scan (no response)
  Duration: 21.106s
  Representative port: 21
  CVEs in VECTOR_DB for this port: 8
  Raw LLM:   INTENT: Attempt to access the FTP server on port 21.

SEVERITY: High
 ACTION: Escalate
 REASONING: This is a high-severity alert because the attack involves accessing a widely used and critical application (FTP) without authentication, which can lead to data theft or disruption of services. The use of a SYN scan and no response from the server indicates that the connection attempt will likely be successful, making it essential to escalate this incident to increase awareness and take preventive measures.
  Verdict:   High - Escalate
  Intent:    Attempt to access the FTP server on port 21.
  Reasoning: This is a high-severity alert because the attack involves accessing a widely used and critical application (FTP) without authentication, which can lead to data theft or disruption of services. The use of a SYN scan and no response from the server indicates that the connection attempt will likely be successful, making it essential to escalate this incident to increase awareness and take preventive measures.

```

## Tech Stack 
- Python - triage pipeline, embedding, and retrieval
- Zeek  - connection log generation
- Suricata - signature detection
- libpcap - packet capture
- Ollama - local LLM inference (bge-base-en-v1.5 for embeddings, Llama-3.2-1B for verdict generation)
- SQLite - CVE database + embedding store + IP reputation cache
- AbuseIPDB + Shodan InternetDB - IP reputation feeds

## Quick Start
1. **Clone the Repo** 

```bash
   git clone https://github.com/irongirl101/sentry.git
   cd sentry
```
2. **Install Zeek (Ubuntu 24.04)**
```bash
echo 'deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | \
    sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | \
    sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/security_zeek.gpg
sudo apt update && sudo apt install -y zeek-lts
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc && source ~/.bashrc
```

3. **Install Suricata (Ubuntu 24.04)**
```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update && sudo apt install -y suricata
sudo suricata-update
```

4. **Installing Ollama:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```
**Pulling the required models:**
```bash
ollama pull hf.co/CompendiumLabs/bge-base-en-v1.5-gguf
ollama pull hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF
```
5. **Python Dependencies** 
```bash
   pip install -r requirements.txt
```

### API Keys

| Service | Required | Purpose | Free Tier |
|---------|----------|---------|-----------|
| AbuseIPDB | Yes | IP reputation scoring | 1,000 checks/day |

Sign up at [abuseipdb.com](https://www.abuseipdb.com) and set your key:

```bash
export ABUSEIPDB_API_KEY="your_key_here"
# Add to ~/.bashrc to persist across sessions
echo 'export ABUSEIPDB_API_KEY="your_key_here"' >> ~/.bashrc
```

### Notes

- Zeek and Suricata require elevated privileges (`sudo`) for live packet capture.
  Batch mode against pcap files works without `sudo` for Zeek, but Suricata
  still requires it to read its config file.
- The Ollama models total approximately 875 MB of disk space.
- Tested on Ubuntu 24.04 LTS (recommended) and Ubuntu 26.04.
  macOS is not recommended for live capture — see Architecture notes.


6. **Build the CVE database**
```bash
   python3 triage.py /path/to/cvelistV5/cves --years 2024,2025,2026 \
       --save-db cve_candidates.sqlite
```
7. **Build the embeddings**
```bash
   python3 embed.py
```

8. **Run against a pcap file**
```bash
   # Generate logs
   zeek -r your_capture.pcap
   sudo suricata -r your_capture.pcap -l ./suricata-logs

   # Run Sentry
   python3 agent_tools.py conn.log suricata-logs/eve.json
```

## Future Enhancements 
- [ ] Add another layer (reasoning model) for the LLM to take care of ~1% of the cases that will not be flagged by the 4 pillars. 
- [ ] Live Monitoring - step away from the test conn.log and eve.json

## License 
MIT :D
            
