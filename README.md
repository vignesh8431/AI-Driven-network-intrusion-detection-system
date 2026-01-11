# AI-Driven-network-intrusion-detection-and-prevention-system

This project presents an "AI-powered, real-time Network Intrusion Detection and Prevention System (NIDPS)" designed to protect hosts and small networks from cyber threats. It leverages unsupervised machine learning—specifically the Isolation Forest algorithm—to detect anomalous network behavior without relying on predefined attack signatures, enabling it to identify zero-day and polymorphic attacks.

The system operates Inline at the kernel level using Linux tools like iptables, ipset, and NFQUEUE. It captures live network packets, aggregates them into flows, extracts behavioral features (e.g., SYN rate, unique destination ports), and scores each flow for anomalies. If malicious activity is detected, the source IP is automatically blocked via firewall rules, providing immediate mitigation.

Key strengths include:
- Real-time detection and prevention (<10 ms latency)
- Lightweight design suitable for edge or SOHO environments
- No dependency on labeled attack data
- Self-learning capability during a baseline period

Tested against common attacks like SYN floods, port scans, and UDP floods using tools like hping3 and nmap, the system successfully blocked threats while allowing legitimate traffic—demonstrating its practicality as a low-cost, intelligent security solution.

--- 

This project bridges modern machine learning with practical cybersecurity, offering a proactive defense mechanism adaptable to evolving network threats
