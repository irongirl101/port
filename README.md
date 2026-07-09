# Port

Port is a layered detection agent, that sits on the network interface and identifies port scanning behaviour in real time. 

``` 
Port Scanning is a form of techinque used to probe a device or network to determine which ports are closed, open or filtered. Malicious attackers use this technique as a form of reconnaissance, checking for doors are open which they can exploit. 
```

Port, as a triage agent, can deduce if any reconnaisaance has occured or any scans has occured at a given time, using LLMs and other tools like Zeek, Suricata and libpcap. 
(Note: this agent is not a live product as of yet.)

## Architecture 
```
    -----------------          -----------------        -----------------       -----------------       -----------------
    |    Traffic    |          |    Traffic    |        |   Signnature  |       |    Triage     |       |               |
    |    Capture    | -------> |    History/   | ------>|   Detection   |------>|    Agent      |------>|    Result     |
    |      (1)      |          |     Logs (2)  |        |     (3)       |       |     (4)       |       |       (5)     |
    -----------------          -----------------        -----------------       -----------------       -----------------
```
   
   
    
            















```


A layered detection agent that sits on the network interface and identifies port scanning behaviour in real time. Incoming traffic is captured via libpcap, parsed into structured connection logs by Zeek, and matched against known scan signatures by Suricata. A local LLM (triage agent) then cross-references flagged activity against the CVE database via RAG — using IP reputation lookup and CVE intent classification as the four pillars of a final verdict. Novel or evasion-based scan patterns that defeat signature matching are escalated to a frontier reasoning model for deeper analysis. The full stack is designed to be cost-efficient, with expensive model calls gated behind local filtering that handles the majority of decisions for free.

