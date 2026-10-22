<div align="center">

# 🛡️ PACKET SNIFFER & NETWORK DEFENSE ANALYZER
### *Modular C++20 / Linux Defensive Packet Analysis & Stateful Anomaly Detection Engine*

[![C++ Standard](https://img.shields.io/badge/C%2B%2B-20-00599C?style=for-the-badge&logo=c%2B%2B)](https://en.cppreference.com/w/cpp/20)
[![Target OS](https://img.shields.io/badge/OS-Linux%20%7C%20Kali%20%7C%20Ubuntu-E95420?style=for-the-badge&logo=linux)](https://www.kernel.org)
[![Engine](https://img.shields.io/badge/Capture-libpcap-orange?style=for-the-badge)](https://www.tcpdump.org/)
[![Build System](https://img.shields.io/badge/Build-CMake%203.20+-064F8C?style=for-the-badge&logo=cmake)](https://cmake.org)
[![CI Status](https://img.shields.io/badge/CI-Automated%20Passing-success?style=for-the-badge&logo=githubactions)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

<p align="center">
  <b>High-throughput Network Telemetry • Protocol Dissection • Stateful Behavioral Heuristics • Real-time Threat Mitigation</b>
</p>

</div>

---

## 📌 Executive Summary

**PacketSniffer** is a defensive cybersecurity framework engineered in modern C++20. Designed for deployment in Security Operations Centers (SOC), penetration test labs, and edge network gateways, it performs non-blocking ingestion of live promiscuous frames, multi-layer packet dissection, statistical metric aggregation, and stateful behavioral anomaly detection (mitigating stealth reconnaissance port scans and volumetric flood vectors).

---

## 🏛️ System Architecture

```text
       ┌───────────────────────────────────────────────────────────┐
       │             OPERATOR CONTROL CONSOLE (main.cpp)           │
       └─────────────────────────────┬─────────────────────────────┘
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ▼                                                   ▼
┌──────────────────────┐                           ┌───────────────────────┐
│ PacketCapture Engine │                           │  TrafficAnalyzer HUD  │
│ (libpcap Dispatcher) │                           │  (Real-Time Telemetry)│
└──────────┬───────────┘                           └───────────▲───────────┘
           │ Raw Frames (L2/L3/L4)                             │
           ▼                                                   │
┌──────────────────────┐                                       │
│  PacketParser Module │                                       │
│  (Eth / IP / L4)     │                                       │
└──────────┬───────────┘                                       │
           │ Strongly-Typed ParsedPacket                       │
           ▼                                                   │
┌──────────────────────┐      Matches Criteria                 │
│  PacketFilter Engine │ ──────────────────────────────────────┤
│  (Protocol & Subnet) │                                       │
└──────────────────────┘                                       │
           │ Filtered Stream                                   │
           ▼                                                   │
┌───────────────────────────────────────────┐                  │
│       STATEFUL ANOMALY DETECTION          │                  │
│ ┌──────────────────┐ ┌──────────────────┐ │                  │
│ │ Port Scan Sensor │ │ Volumetric Flood │ │ ─────────────────┘
│ │ (Sliding Window) │ │ (Rate Anomaly)   │ │
│ └────────┬─────────┘ └────────┬─────────┘ │
└──────────┼────────────────────┼───────────┘
           │ Threat Trigger     │ Threat Trigger
           ▼                    ▼
┌───────────────────────────────────────────┐
│     SECURITY ALERT REGISTRY & LOGGER      │
│  [HIGH] Volumetric Flood Detected         │
│  [MED]  Reconnaissance Port Scan Flagged  │
└─────────────────────┬─────────────────────┘
                      │
                      ▼
┌───────────────────────────────────────────┐
│     DIAGNOSTIC EXECUTIVE AUDIT REPORT     │
│       (reports/activity_report.txt)       │
└───────────────────────────────────────────┘
```

---

## ⚡ Core Detection Heuristics

| Detection Module | Target Threat Vector | Heuristic Trigger Model | Default Threshold | Severity Rating |
| :--- | :--- | :--- | :--- | :--- |
| **Port Scan Sensor** | Stealth Reconnaissance / Nmap Sweep | Unique ports contacted per source IP in sliding window | $\ge 10$ unique ports / 5s | `MEDIUM` ($\ge 20 \rightarrow$ `HIGH`) |
| **Volumetric Flood** | SYN Flood / UDP Amplification / DoS | Total packet frequency velocity per source IP | $> 200$ pkts / 5s window | `HIGH` |
| **Malformed Ingest** | Frame Truncation / Crafted Payloads | Header bounds check prior to dissection | Size $< 14$ bytes (Eth) | Discarded & Isolated |

---

## 📂 Repository Directory Layout

```text
PacketSniffer/
├── CMakeLists.txt                # C++20 & libpcap build orchestrator
├── README.md                     # Engineering & operations documentation
├── Dockerfile                    # Multi-stage Linux deployment container
├── run_demo.ps1                  # Native Windows Zero-Dependency Simulator
├── .github/workflows/ci.yml      # Continuous Integration pipeline
├── include/                      # Production header interfaces
│   ├── AlertManager.h            # Thread-safe alert collection & metrics
│   ├── AnomalyDetector.h         # Stateful heuristic sliding-window models
│   ├── Logger.h                  # Thread-safe ISO-timestamped activity log
│   ├── PacketCapture.h           # RAII libpcap wrapper with non-blocking loops
│   ├── PacketFilter.h            # High-velocity packet predicate evaluator
│   ├── PacketParser.h            # Zero-copy protocol dissecting engine
│   ├── ReportGenerator.h         # Executive security audit generator
│   └── TrafficAnalyzer.h         # Thread-safe packets/sec & Top-N talkers
├── src/                          # Implementations
│   ├── AlertManager.cpp
│   ├── AnomalyDetector.cpp
│   ├── Logger.cpp
│   ├── PacketCapture.cpp
│   ├── PacketFilter.cpp
│   ├── PacketParser.cpp
│   ├── ReportGenerator.cpp
│   ├── TrafficAnalyzer.cpp
│   └── main.cpp                  # ANSI-colored SOC console application
├── logs/                         # Historical alert archives
├── reports/                      # Diagnostic text audit archives
└── tests/
    └── test_suite.cpp            # Autonomous unit & boundary verification
```

---

## 🚀 Deployment & Operation

### 1. CyberSentinel Standalone Desktop Browser App (Windows `.exe`)
Anyone can run the CyberSentinel Browser without installing build tools or compilers:
- **Download/Open**: `PacketSniffer/desktop_app/CyberSentinelBrowser.exe` or extract `PacketSniffer/CyberSentinel_Browser_Standalone_Windows.zip`.
- **Quick Launch**: Double-click [launch_desktop_browser.bat](file:///c:/Users/hp/Documents/Antigravity%20project/PacketSniffer/launch_desktop_browser.bat).
- **Features**: Dedicated isolated browser window with multi-engine web search (DuckDuckGo, Google, Bing, Wikipedia), real-time L3/L4/L7 packet sniffer split view, sliding-window threat heuristics, and active endpoint quarantine.

### 2. Chrome & Edge Browser Extension (Manifest V3)
Inspect and protect normal daily browsing directly inside Google Chrome or Microsoft Edge:
- **Location**: `PacketSniffer/browser_extension/` or `PacketSniffer/CyberSentinel_Browser_Extension.zip`.
- **Setup**: Open `chrome://extensions`, enable **Developer mode**, click **Load unpacked**, and select `PacketSniffer/browser_extension`.

### 3. CyberSentinel Web SOC Dashboard
- Run [launch_app.bat](file:///c:/Users/hp/Documents/Antigravity%20project/PacketSniffer/launch_app.bat) to open the interactive cyber dashboard with live packet stream, canvas throughput chart, and JSON audit export.

### 4. Interactive Windows CLI Simulation (Zero Installation)
To test the engine logic and detection heuristics immediately in Windows PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File .\PacketSniffer\interactive_cli.ps1
```

### 5. Native Linux / Kali Linux Build
```bash
# 1. Install system prerequisites
sudo apt update && sudo apt install -y build-essential cmake pkg-config libpcap-dev

# 2. Build via CMake
cd PacketSniffer
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# 3. Execute Automated Unit Test Suite
./run_tests

# 4. Launch Live Sniffer Console
sudo ./packet_sniffer
```

### 6. Containerized Run (Docker)
```bash
# Build the production image
docker build -t packet-sniffer .

# Execute unit tests
docker run --rm packet-sniffer ./run_tests

# Launch with host interface capture privileges
docker run --rm -it --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN packet-sniffer ./packet_sniffer
```

---

## 🛡️ Telemetry HUD Preview

```text
  ╔═════════════════════ LIVE TELEMETRY HUD ════════════════════╗
  ║  Total Packets: 14,820         Total Bytes:   12,480,240    ║
  ║  TCP Packets:   12,100         UDP Packets:   2,650         ║
  ║  ICMP Packets:  70             Throughput:    1,420.5 pps   ║
  ╚═════════════════════════════════════════════════════════════╝
```

---

## 📜 License
This project is open-source under the [MIT License](LICENSE). Designed for defensive security research, network diagnostics, and cybersecurity telemetry.
