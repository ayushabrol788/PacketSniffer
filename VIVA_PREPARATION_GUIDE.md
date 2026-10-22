# 🎓 CyberSentinel: Comprehensive Viva Voce & Project Defense Guide

> **Prepared for:** Final Project Defense, Academic Viva & Technical Interviews  
> **Project Title:** Packet Sniffer & Defensive Network Anomaly Detection Engine  
> **Technology Stack:** C++20, libpcap, POSIX Sockets, Chrome Manifest V3, PowerShell

---

## 🎯 1. The 30-Second Elevator Pitch (Opening Statement)
*When your professor asks: "Tell me briefly about your project."*

> "Sir, my project is **CyberSentinel**, a modular defensive network packet analysis and behavioral anomaly detection engine built with modern C++20 and a companion browser extension. 
> 
> Unlike passive sniffers that merely display traffic like Wireshark, our engine operates a real-time **Stateful Heuristic Pipeline** that inspects network frames across Layers 2, 3, and 4. It autonomously flags cyber threats—specifically **Stealth Reconnaissance Port Sweeps**, **Volumetric DoS Bursts**, and **Cleartext Protocol Insecurities** using sliding-window algorithms—and allows the operator to **actively quarantine malicious hosts** with one-click firewall shun rules."

---

## ❓ 2. Top 10 Viva Questions & Exact Answers

### Q1: What is a Packet Sniffer, and how does it actually capture data from the network card?
**Answer:**
A packet sniffer intercepts binary frames directly from the Network Interface Card (NIC) before the operating system's kernel stack filters them for user applications. 

To achieve this, the network card must be placed into **Promiscuous Mode**. Normally, a NIC uses hardware address filtering to discard any frame whose destination MAC address doesn't match its own. In promiscuous mode, this filter is disabled, allowing the sniffer to ingest all incoming and outgoing frames on the wire. In our C++ implementation, we use `libpcap`'s `pcap_open_live()` and an asynchronous `pcap_dispatch()` loop to stream frames into user memory safely.

---

### Q2: Why are Administrator / Root (`sudo`) privileges required to run a raw packet sniffer?
**Answer:**
Because creating raw sockets (`SOCK_RAW`) or interacting with `libpcap` bypasses the standard OS transport-layer security boundaries. If non-privileged users had raw socket access, malicious software could eavesdrop on other users' private passwords, session cookies, and network secrets. Therefore, Linux requires root or the `CAP_NET_RAW` capability, and Windows requires an administrative driver like Npcap.

---

### Q3: How does your packet parsing pipeline unpack network layers?
**Answer:**
In [`PacketParser.cpp`](file:///c:/Users/hp/Documents/Antigravity%20project/PacketSniffer/src/PacketParser.cpp), packets are dissected hierarchically following the OSI model:
1. **Layer 2 (Data Link - Ethernet)**: We cast the first 14 bytes into `struct ether_header` to extract the Source MAC, Destination MAC, and the `ether_type`. If `ether_type == 0x0800`, we know an IPv4 payload follows.
2. **Layer 3 (Network - IPv4)**: At offset 14, we read the IP header (`struct ip`). We extract Source IP, Destination IP, Total Length, and the protocol field (`ip_p`).
3. **Layer 4 (Transport - TCP/UDP/ICMP)**: Using the IP header length (`ip_hl * 4`), we advance the byte offset to extract transport ports (`th_sport`, `th_dport` for TCP; `uh_sport`, `uh_dport` for UDP).
4. **Bounds Safety Check**: Every layer strictly checks `payload.size() >= offset + sizeof(header)` before reading, preventing memory out-of-bounds vulnerabilities or crashes from malformed frames.

---

### Q4: How does your Anomaly Detection Engine detect a Port Scan attack?
**Answer:**
In [`AnomalyDetector.cpp`](file:///c:/Users/hp/Documents/Antigravity%20project/PacketSniffer/src/AnomalyDetector.cpp), we use a **Stateful Sliding-Window Heuristic Model**:
* For every communicating Source IP, we track the timestamp and maintain a hash set (`std::unordered_map<uint16_t, size_t>`) of all distinct destination ports touched within a **5.0-second time window**.
* Normal applications connect to 1 or 2 ports (e.g., 443 for HTTPS, 53 for DNS).
* An attacker using tools like **Nmap** probes multiple sequential ports to discover open services. If a single IP contacts **$\ge 10$ unique ports** within 5 seconds, our engine flags a **Port Scan Reconnaissance Anomaly** (`MEDIUM` severity). If it exceeds 20 ports, it elevates to `CRITICAL`.
* We also include a **3-second deduplication window** so the operator isn't flooded with repeated alerts for the same ongoing scan.

---

### Q5: How does your engine differentiate between a Port Scan and a Volumetric DoS / Flood?
**Answer:**
They examine two completely different behavioral dimensions:
* **Port Scan Heuristic**: Measures **port diversity** ($\text{Unique Ports} \ge 10$ across moderate packet volume).
* **Volumetric Flood Heuristic**: Measures **packet frequency velocity** ($\text{Packet Count} > 200$ packets within the 5-second window to the same or single port, such as a SYN flood or UDP flood).

---

### Q6: Why did you use modern C++20 and OOP principles? What are the software engineering benefits?
**Answer:**
1. **RAII (Resource Acquisition Is Initialization)**: In classes like `PacketCapture` and `Logger`, resources like `pcap_t*` handles and file descriptors are automatically acquired in constructors and deterministically closed in destructors. This prevents socket and file descriptor leaks.
2. **Deterministic Error Boundaries**: We avoid raw owning pointers in favor of smart pointers (`std::make_unique`) and `std::optional<ParsedPacket>`, eliminating null-pointer dereferences.
3. **Multi-Thread Safety**: Capture happens on a background worker thread while queries happen on the console thread. We guard shared analytics structures using `std::mutex` and `std::lock_guard`.
4. **Zero-Overhead Abstractions**: C++20 provides modern high-level safety without sacrificing the microsecond throughput needed for gigabit network wire speeds.

---

### Q7: What is Active Quarantine / IP Shunning, and how did you implement it?
**Answer:**
Passive sniffers only watch and log attacks. Our engine features an **Active Defense ACL (Access Control List)**:
* When an attacker IP is flagged, the operator can quarantine the IP.
* The IP is stored in an in-memory quarantine set (`std::unordered_set<std::string> blockedIps_`).
* When subsequent raw frames enter the pipeline, `AnomalyDetector` checks the source IP against `blockedIps_`. If matched, the frame is **dropped at wire ingest**, and the engine outputs ready-to-use OS firewall rules (`sudo iptables -A INPUT -s <IP> -j DROP`).

---

### Q8: How does your Chrome/Edge Browser Extension differ from the low-level C++ network sniffer?
**Answer:**
They operate at different layers of the network stack:
* **C++ Engine**: Operates at **Layers 2, 3, and 4** (Ethernet frames, raw IP packets, TCP/UDP headers). It sees all traffic on the physical network card.
* **Browser Extension**: Operates at **Layer 7 (Application Layer)** using the browser's `chrome.webRequest` API. It specifically inspects web application requests, API calls, tracking beacons (`google-analytics`, `doubleclick`), unencrypted cleartext HTTP calls, and allows 1-click domain blocking directly inside the browser.

---

### Q9: Can this sniffer inspect the content of encrypted HTTPS payloads?
**Answer:**
No, and this is by design for security. TLS/HTTPS encrypts the Application Layer payload (HTTP headers, passwords, cookies) using end-to-end symmetric keys established during the TLS handshake. 

However, our sniffer **can still inspect the Layer 3 and Layer 4 headers** (IP addresses, Port 443, packet size, timing, and handshake packets). That is why behavioral anomaly detection is so powerful: even without decrypting the payload, we can detect port scans, traffic surges, and malicious communication patterns purely from traffic metadata!

---

### Q10: What are the limitations of your project, and how can it be extended in the future?
**Answer:**
1. **IPv6 Dissection**: The current parser focuses on IPv4; it can be expanded to full IPv6 extension header chains.
2. **Hardware Acceleration**: For 10Gbps+ enterprise backbones, integrating kernel-bypass frameworks like **DPDK** (Data Plane Development Kit) or **eBPF / XDP** would provide zero-copy kernel filtering.
3. **Machine Learning Classifier**: Integrating an ML clustering model (e.g., Isolation Forest or Random Forest) alongside our rule-based sliding-window heuristics to catch zero-day anomalies.

---

## 🎬 3. Step-by-Step Live Demo Presentation Script

When presenting to your professor, follow this exact 3-minute sequence:

### Step 1: Open the Interactive GUI App or Extension (Visual Wow Factor)
1. Double-click `launch_app.bat` or show the **CyberSentinel Chrome Extension**.
2. Point out:
   - *"Sir, this is our real-time SOC dashboard. It features live rolling canvas throughput graphs, protocol breakdown counters, and an active threat radar."*

### Step 2: Demonstrate Normal Traffic vs Malicious Attack Ingestion
1. Click **"+ Normal Traffic (HTTPS/DNS)"**:
   - *"Notice normal web traffic is ingested, parsed into L2/L3/L4 components, and confirmed safe."*
2. Click **"+ Reconnaissance Port Scan"**:
   - *"Now, we simulate an attacker launching an Nmap port sweep. Within milliseconds, our sliding-window heuristic detects that 16 distinct ports were probed within 5 seconds and elevates the threat to [HIGH] severity."*

### Step 3: Demonstrate Active Defense & 1-Click Quarantine
1. Click **"⛔ Quarantine IP"** on the attacker:
   - *"Instead of just logging the alert, our engine takes defensive action: the IP is placed into the Quarantine ACL. Any future frames from this host are intercepted and dropped at wire ingest, and the system generates the exact `iptables` drop command."*

### Step 4: Show the Core C++ Code Architecture
1. Open [`AnomalyDetector.cpp`](file:///c:/Users/hp/Documents/Antigravity%20project/PacketSniffer/src/AnomalyDetector.cpp) and [`PacketParser.cpp`](file:///c:/Users/hp/Documents/Antigravity%20project/PacketSniffer/src/PacketParser.cpp):
   - Highlight the bounds checking and the `std::chrono::steady_clock` sliding-window algorithm.
   - Explain the RAII memory management in `PacketCapture.cpp`.

---

## 💡 Quick Keywords to Mention to Get Top Marks:
- **Promiscuous Mode**: Disabling hardware MAC filtering on the NIC.
- **Hierarchical Dissection**: L2 Ethernet $\rightarrow$ L3 IPv4 $\rightarrow$ L4 TCP/UDP.
- **Sliding-Window Heuristics**: State tracking over a $\Delta t = 5.0$s interval.
- **Alert Deduplication**: Preventing operator fatigue through alert dampening.
- **RAII Principle**: Zero memory/socket handle leaks in C++.
- **Active Quarantine / Shunning**: Moving from passive logging to proactive packet dropping.
