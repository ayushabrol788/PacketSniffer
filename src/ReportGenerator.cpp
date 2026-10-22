#include "ReportGenerator.h"
#include <sstream>
#include <fstream>
#include <iomanip>
#include <filesystem>

ReportGenerator::ReportGenerator(double durationSec,
                                 const TrafficStats& stats,
                                 const std::vector<std::pair<std::string, uint64_t>>& topSrcIps,
                                 const std::vector<std::pair<std::string, uint64_t>>& topDstIps,
                                 const std::vector<std::pair<uint16_t, uint64_t>>& topDstPorts,
                                 const std::vector<SecurityAlert>& alerts)
    : durationSec_(durationSec),
      stats_(stats),
      topSrcIps_(topSrcIps),
      topDstIps_(topDstIps),
      topDstPorts_(topDstPorts),
      alerts_(alerts) {}

std::string ReportGenerator::generateTextReport() const {
    std::ostringstream oss;
    oss << "╔═══════════════════════════════════════════════════════════════════════════════╗\n";
    oss << "║           DEFENSIVE NETWORK SECURITY & ANOMALY DETECTION AUDIT                ║\n";
    oss << "╚═══════════════════════════════════════════════════════════════════════════════╝\n\n";

    oss << "┌─ [1] SESSION OVERVIEW ────────────────────────────────────────────────────────┐\n";
    oss << "│  Capture Session Duration: " << std::fixed << std::setprecision(2) << durationSec_ << " seconds\n";
    oss << "│  Total Packets Ingested:   " << stats_.totalPackets << "\n";
    oss << "│  Total Volume Ingested:    " << stats_.totalBytes << " bytes (" << std::fixed << std::setprecision(2) 
        << (stats_.totalBytes / 1048576.0) << " MB)\n";
    oss << "│  Average Throughput:       " << std::fixed << std::setprecision(1) << stats_.packetsPerSecond << " pkts/sec\n";
    oss << "└───────────────────────────────────────────────────────────────────────────────┘\n\n";

    oss << "┌─ [2] PROTOCOL COMPOSITION ───────────────────────────────────────────────────┐\n";
    double tcpPct = stats_.totalPackets > 0 ? (stats_.tcpPackets * 100.0 / stats_.totalPackets) : 0.0;
    double udpPct = stats_.totalPackets > 0 ? (stats_.udpPackets * 100.0 / stats_.totalPackets) : 0.0;
    double icmpPct = stats_.totalPackets > 0 ? (stats_.icmpPackets * 100.0 / stats_.totalPackets) : 0.0;
    oss << "│  TCP Frames:   " << std::setw(10) << stats_.tcpPackets << "  (" << std::fixed << std::setprecision(1) << tcpPct << "%)\n";
    oss << "│  UDP Frames:   " << std::setw(10) << stats_.udpPackets << "  (" << std::fixed << std::setprecision(1) << udpPct << "%)\n";
    oss << "│  ICMP Frames:  " << std::setw(10) << stats_.icmpPackets << "  (" << std::fixed << std::setprecision(1) << icmpPct << "%)\n";
    oss << "└───────────────────────────────────────────────────────────────────────────────┘\n\n";

    oss << "┌─ [3] TOP SOURCE TALKERS ──────────────────────────────────────────────────────┐\n";
    if (topSrcIps_.empty()) {
        oss << "│  (No source IP records in active window)\n";
    } else {
        for (const auto& p : topSrcIps_) {
            oss << "│  • " << std::left << std::setw(25) << p.first << " : " << p.second << " pkts\n";
        }
    }
    oss << "└───────────────────────────────────────────────────────────────────────────────┘\n\n";

    oss << "┌─ [4] TOP TARGETED DESTINATIONS & PORTS ───────────────────────────────────────┐\n";
    oss << "│  Destination Hosts:\n";
    for (const auto& p : topDstIps_) {
        oss << "│    • " << std::left << std::setw(23) << p.first << " : " << p.second << " pkts\n";
    }
    oss << "│  Target Ports:\n";
    for (const auto& p : topDstPorts_) {
        oss << "│    • Port " << std::left << std::setw(18) << p.first << " : " << p.second << " pkts\n";
    }
    oss << "└───────────────────────────────────────────────────────────────────────────────┘\n\n";

    oss << "┌─ [5] DETECTED SECURITY ANOMALIES & RECOMMENDED DEFENSIVE ACTIONS (" << alerts_.size() << ") ───┐\n";
    if (alerts_.empty()) {
        oss << "│  ✔ Clean Baseline: Zero security anomalies registered.\n";
    } else {
        for (const auto& a : alerts_) {
            std::string sevTag = (a.severity == AlertSeverity::CRITICAL) ? "[CRIT]" :
                                 (a.severity == AlertSeverity::HIGH) ?     "[HIGH]" :
                                 (a.severity == AlertSeverity::MEDIUM) ?   "[MED] " : "[LOW] ";
            oss << "│  " << sevTag << " " << a.timestampStr << " | " << a.srcIp << " -> " << a.dstIp << "\n";
            oss << "│         Threat: " << a.reason << "\n";
            if (!a.recommendedAction.empty()) {
                oss << "│         Action: " << a.recommendedAction << "\n";
            }
            oss << "│  ─────────────────────────────────────────────────────────────────────────────\n";
        }
    }
    oss << "└───────────────────────────────────────────────────────────────────────────────┘\n";
    return oss.str();
}

bool ReportGenerator::saveReportToFile(const std::string& filePath) const {
    std::filesystem::path path(filePath);
    if (path.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
    }
    std::ofstream out(filePath);
    if (!out.is_open()) return false;
    out << generateTextReport();
    out.close();
    return true;
}
