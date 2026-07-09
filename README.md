# Port

Port is a layered detection agent, that sits on the network interface and identifies port scanning behaviour in real time. 
A *blue team* tool, 




A layered detection agent that sits on the network interface and identifies port scanning behaviour in real time. Incoming traffic is captured via libpcap, parsed into structured connection logs by Zeek, and matched against known scan signatures by Suricata. A local LLM (triage agent) then cross-references flagged activity against the CVE database via RAG — using IP reputation lookup and CVE intent classification as the four pillars of a final verdict. Novel or evasion-based scan patterns that defeat signature matching are escalated to a frontier reasoning model for deeper analysis. The full stack is designed to be cost-efficient, with expensive model calls gated behind local filtering that handles the majority of decisions for free.

