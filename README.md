# Port

Port is a layered detection agent, that sits on the network interface and identifies port scanning behaviour in real time. 

``` 
Port Scanning is a form of techinque used to probe a device or network to determine which ports are closed, open or filtered. Malicious attackers use this technique as a form of reconnaissance, checking for doors are open that they may be able to exploit. 
```

Port, as a triage agent, can detect if any reconnaisaance activity or port scanning behaviour, using LLMs and other tools like Zeek, Suricata and libpcap. 
(Note: this agent is not a live product as of yet.)

## Architecture 
```
    -----------------          -----------------        -----------------       -----------------       -----------------
    |    Traffic    |          |    Traffic    |        |   Signature   |       |    Triage     |       |               |
    |    Capture    | -------> |    History/   | ------>|   Detection   |------>|    Agent      |------>|    Result     |
    |      (1)      |          |     Logs (2)  |        |     (3)       |       |     (4)       |       |     (5)       |
    -----------------          -----------------        -----------------       -----------------       -----------------
```
   
**(1) Traffic Capture - libpcap** 
It captures the raw data of the packet - source and destination IP addresses and ports, payload, protocol, flags, timestamps, etc. 
This creates the foundation for which the tools will work on. 

**(2) Traffic History/Logs - Zeek** 
Parses packets into structured connection logs: who connected to what, when, how, and for how long. Provides behavioural context, pattern detection across connections, slow scan detection, and distributed scan detection — particularly useful when Suricata does not flag a scan due to larger timing gaps.

**(3) Signature Detection - Suricata** 
Port scanners usually operate with the help of scan patterns, like SYN, FIN, NULL, XMAS, UDP scans. Suricata helps in matching the traffic against 50,000+ community rules from the Emerging Threats Open ruleset.

**(4) Triage Agent - ollama + ip reputation lookup** 
Combines four pillars to produce a
verdict:
- Zeek connection pattern analysis
- Suricata signature match results
- IP reputation (AbuseIPDB + Shodan
  InternetDB, locally cached)
- CVE RAG pipeline: embeddings of a
  port-confirmed CVE database queried
  against the detected event, with an
  LLM producing a structured verdict
  (intent, severity, recommended action)

False positive filtering, scan type
classification, and attacker profiling
happen at this layer. Expensive LLM
calls are gated behind local filtering
so the majority of decisions are handled
for free.

**(5) Result - Incident Report** 
Generates a report based on the 4 pillars above. 

The full stack is designed to be cost-efficient, with expensive model calls gated behind local filtering that handles the majority of decisions for free.

## Tech Stack 
- Python - triage pipeline, embedding, and retrieval
- Zeek  — connection log generation
- Suricata — signature detection
- libpcap — packet capture
- Ollama— local LLM inference (bge-base-en-v1.5 for embeddings, Llama-3.2-1B for verdict generation)
- SQLite** — CVE database + embedding store + IP reputation cache
- AbuseIPDB + Shodan InternetDB — IP reputation feeds

## Future Enhancements 
[ ] Add another layer for the LLM to take care of ~1% of the cases that will not be flagged by the 4 pillars. 
[ ] Live Monitoring - step away from the test conn.log and eve.json

## License 
MIT :D
            
