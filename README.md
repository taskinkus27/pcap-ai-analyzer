# 🛡️ PCAP AI Analyzer

**PCAP AI Analyzer** is a full-stack, AI-powered network packet dissection and forensic investigation tool. It parses raw binary `.pcap` and `.pcapng` files at the byte level, runs an inline signature-based anomaly detection engine, provides a native Wireshark-like 3-pane UI experience, and leverages **Google Gemini AI** to generate executive incident response reports with MITRE ATT&CK mapping and firewall mitigation rules.

---

## ✨ Features

### 1. 🔍 Binary Dissection Engine
* **Native Parsing:** Parses `.pcap` and `.pcapng` binary streams (handling both Big-Endian and Little-Endian byte orderings) without relying solely on external OS dependencies.
* **Multi-Layer Protocol Support:**
  * **L2 / L3:** Ethernet II (MACs, EtherType), IPv4/IPv6 (TTL, Length, Protocol, Flags), ARP.
  * **L4:** TCP (Seq, Ack, Window, SYN/ACK/FIN/RST/PSH/URG flags), UDP, ICMP.
  * **L7 / Application:** DNS (QNAME, QTYPE, Shannon entropy calculation), HTTP (Methods, URI, Status, Headers, Payload preview), TLS Client Hello (SNI extraction), and plain-text protocols.

### 2. ⚡ Signature & Anomaly Detection Engine
* **Port Scan Detection:** Grouped tracking for TCP SYN, NULL, XMAS scans, and port sweeps originating from single/multiple sources.
* **Malicious Web Payload Detection:** Real-time inspection for SQL Injection (`UNION SELECT`, `' OR '1'='1`), Local File Inclusion (LFI `../../etc/passwd`), Command Injection (`whoami`, `; id`, `/bin/sh`), XSS, and Web Shell signatures.
* **DNS Tunneling & Exfiltration:** Identifies high-entropy subdomains and encoded C2 communications (Base64/Hex over DNS).
* **Cleartext Credential Exposure:** Flags exposed credentials across FTP (`USER`/`PASS`) and HTTP Basic Authentication.

### 3. 🖥️ Wireshark-Inspired 3-Pane UI
* **Top Pane (Packet Table):** Keyboard-navigable list (Up/Down keys) showing Frame No, Timestamp, Source/Destination IPs & Ports, Protocol badge, Length, Info summary, and Threat Level indicators.
* **Filter Bar:** Wireshark-style display filter simulator (`http`, `dns`, `ip.src == ...`, `tcp.syn == 1`, `anomaly == true`, `type == PORT_SCAN`).
* **Middle Pane (Tree View):** Expandable hierarchical breakdown of packet layers (`Frame` ➔ `Ethernet` ➔ `IP` ➔ `Transport` ➔ `Application` ➔ `Anomaly Rules`).
* **Bottom Pane (Hex Viewer):** Live Hex & ASCII dump with real byte offsets (`0000`, `0010`...) and text-copy support.

### 4. 🤖 Google Gemini AI Forensic Assistant
* Powered by `gemini-3.8-flash` via the `@google/genai` SDK.
* **Automated Threat Reports:**
  * Executive Summary & 0–100 Threat Score.
  * **MITRE ATT&CK** Tactic & Technique mapping (e.g., T1046, T1190, T1048).
  * Chronological attack timeline.
  * Ready-to-copy firewall rules (`iptables`, `ufw`, `Snort`, `Suricata`).
  * One-click Markdown export.
* **Interactive AI Copilot:** Embedded Q&A chat assistant for deep-dive questioning on PCAP packets and adversary tactics.

### 5. 🐍 Live Capture & Script Integration
* Included helper scripts (`capture_scapy.py`, `analyze_pyshark.py`) to capture live interface traffic (`eth0`, `wlan0`) via Scapy/PyShark and send to the analysis pipeline.
* Built-in interactive simulator with 5 pre-loaded scenarios:
  1. Nmap Port Scan
  2. Web SQL Injection
  3. DNS Tunneling / C2
  4. Cleartext Password Exposure
  5. Clean / Baseline Traffic

---

## 🚀 Quick Start

### Prerequisites
* **Python 3.10+**
* **Node.js 18+** (if running the web UI / backend service)
* **Google Gemini API Key** ([Get your API Key here](https://aistudio.google.com/))

### Installation

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/pcap-ai-analyzer.git](https://github.com/YOUR_USERNAME/pcap-ai-analyzer.git)
   cd pcap-ai-analyzer
