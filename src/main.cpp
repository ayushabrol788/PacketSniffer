#include "PacketCapture.h"
#include "PacketParser.h"
#include "PacketFilter.h"
#include "TrafficAnalyzer.h"
#include "AnomalyDetector.h"
#include "AlertManager.h"
#include "Logger.h"
#include "ReportGenerator.h"

#include <iostream>
#include <iomanip>
#include <thread>
#include <memory>
#include <chrono>

namespace Colors {
    const std::string RESET       = "\033[0m";
    const std::string BOLD        = "\033[1m";
    const std::string DIM         = "\033[2m";
    const std::string RED         = "\033[31m";
    const std::string GREEN       = "\033[32m";
    const std::string YELLOW      = "\033[33m";
    const std::string BLUE        = "\033[34m";
    const std::string MAGENTA     = "\033[35m";
    const std::string CYAN        = "\033[36m";
    const std::string WHITE       = "\033[37m";
    const std::string BOLD_CYAN   = "\033[1;36m";
    const std::string BOLD_GREEN  = "\033[1;32m";
    const std::string BOLD_YELLOW = "\033[1;33m";
    const std::string BOLD_RED    = "\033[1;31m";
    const std::string BG_RED      = "\033[41;37m";
    const std::string BG_YELLOW   = "\033[43;30m";
    const std::string BG_BLUE     = "\033[44;37m";
}

void printBanner() {
    std::cout << Colors::BOLD_CYAN << R"(
  ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗███████╗██╗  ██╗
  ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔════╝██║  ██║
  ██████╔╝███████║██║     █████═╝ █████╗     ██║   ███████╗███████║
  ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   ╚════██║██╔══██║
  ██║     ██║  ██║╚██████╗██║ ╚██╗███████╗   ██║   ███████║██║  ██║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
)" << Colors::RESET;
    std::cout << Colors::DIM << "  [ DEFENSIVE NETWORK PACKET ANALYSIS & ANOMALY DETECTION ENGINE ]\n" << Colors::RESET;
    std::cout << Colors::CYAN << "  ──────────────────────────────────────────────────────────────────\n" << Colors::RESET;
}

void printMenu(size_t alertCount, bool isCapturing) {
    std::cout << "\n"
              << Colors::BOLD << "  CONTROL CONSOLE " << Colors::RESET;
    if (isCapturing) {
        std::cout << Colors::BOLD_GREEN << " [● CAPTURING ACTIVE]" << Colors::RESET << "\n";
    } else {
        std::cout << Colors::DIM << " [○ IDLE / STANDBY]" << Colors::RESET << "\n";
    }

    std::cout << Colors::DIM << "  ┌─────────────────────────────────────────────────────────────┐\n" << Colors::RESET;
    std::cout << "  │  " << Colors::BOLD_CYAN << "[1]" << Colors::RESET << "  List Network Interfaces                            │\n";
    std::cout << "  │  " << Colors::BOLD_GREEN << "[2]" << Colors::RESET << "  Start Live Capture Engine                          │\n";
    std::cout << "  │  " << Colors::BOLD_YELLOW << "[3]" << Colors::RESET << "  Configure Packet Filter (TCP Demo)                 │\n";
    std::cout << "  │  " << Colors::BOLD_CYAN << "[4]" << Colors::RESET << "  View Live Real-Time Telemetry                      │\n";
    
    std::cout << "  │  " << Colors::BOLD_RED << "[5]" << Colors::RESET << "  View Detected Security Anomalies (";
    if (alertCount > 0) {
        std::cout << Colors::BOLD_RED << alertCount << " ALERTS" << Colors::RESET;
    } else {
        std::cout << Colors::DIM << "0" << Colors::RESET;
    }
    std::cout << ")            │\n";

    std::cout << "  │  " << Colors::BOLD_CYAN << "[6]" << Colors::RESET << "  Generate Diagnostic Audit Report                   │\n";
    std::cout << "  │  " << Colors::DIM << "[7]" << Colors::RESET << "  View System Activity Log Location                  │\n";
    std::cout << "  │  " << Colors::DIM << "[8]" << Colors::RESET << "  Halt & Exit Engine                                 │\n";
    std::cout << Colors::DIM << "  └─────────────────────────────────────────────────────────────┘\n" << Colors::RESET;
    std::cout << Colors::BOLD << "  ▶ Select option [1-8]: " << Colors::RESET;
}

int main() {
    auto capture = std::make_unique<PacketCapture>();
    auto filter = std::make_unique<PacketFilter>();
    auto analyzer = std::make_unique<TrafficAnalyzer>();
    auto detector = std::make_unique<AnomalyDetector>();
    auto alertManager = std::make_unique<AlertManager>();
    auto logger = std::make_unique<Logger>("logs/sniffer_activity.log");

    std::thread captureThread;
    auto startTime = std::chrono::steady_clock::now();

    printBanner();

    while (true) {
        printMenu(alertManager->getAlerts().size(), capture->isCapturing());

        int choice = 0;
        if (!(std::cin >> choice)) break;

        if (choice == 1) {
            auto ifaces = capture->listInterfaces();
            std::cout << "\n" << Colors::BOLD_CYAN << "  [AVAILABLE NETWORK INTERFACES]" << Colors::RESET << "\n";
            if (ifaces.empty()) {
                std::cout << Colors::YELLOW << "  ⚠ No network interfaces detected or raw socket privileges required.\n" << Colors::RESET;
            } else {
                for (size_t i = 0; i < ifaces.size(); ++i) {
                    std::cout << "    " << Colors::CYAN << "[" << i << "]" << Colors::RESET 
                              << " " << Colors::BOLD << ifaces[i] << Colors::RESET << "\n";
                }
            }
        } else if (choice == 2) {
            if (capture->isCapturing()) {
                std::cout << Colors::YELLOW << "\n  ⚠ Capture engine is already active!\n" << Colors::RESET;
                continue;
            }
            auto ifaces = capture->listInterfaces();
            if (ifaces.empty()) {
                std::cout << Colors::RED << "\n  ✖ Error: No network interfaces found.\n" << Colors::RESET;
                continue;
            }
            std::cout << "\n" << Colors::BOLD_GREEN << "  ● Initializing packet capture on interface: " 
                      << Colors::WHITE << ifaces[0] << Colors::RESET << " ...\n";
            startTime = std::chrono::steady_clock::now();
            captureThread = std::thread([&, ifaces]() {
                capture->startCapture(ifaces[0], [&](const PacketRawData& raw) {
                    auto parsed = PacketParser::parse(raw);
                    if (parsed && filter->matches(*parsed)) {
                        analyzer->recordPacket(*parsed);
                        auto alerts = detector->analyze(*parsed);
                        for (const auto& a : alerts) {
                            alertManager->registerAlert(a);
                            std::cout << "\n" << Colors::BOLD_RED << "  [ANOMALY DETECTED] " 
                                      << Colors::YELLOW << "[" << a.srcIp << " -> " << a.dstIp << "] "
                                      << Colors::WHITE << a.reason << Colors::RESET << "\n";
                            logger->logEvent("ALERT", a.reason);
                        }
                    }
                });
            });
            captureThread.detach();
            std::cout << Colors::GREEN << "  ✔ Background capture thread dispatched successfully.\n" << Colors::RESET;
        } else if (choice == 3) {
            FilterCriteria fc;
            fc.protocol = NetworkProtocol::TCP;
            filter->setFilter(fc);
            std::cout << Colors::BOLD_YELLOW << "\n  ✔ Active Filter Applied: " 
                      << Colors::WHITE << "TCP Only (Discarding UDP/ICMP frames)\n" << Colors::RESET;
        } else if (choice == 4) {
            auto stats = analyzer->getStats();
            std::cout << "\n" << Colors::BOLD_CYAN << "  ╔═════════════════════ LIVE TELEMETRY HUD ════════════════════╗" << Colors::RESET << "\n";
            std::cout << "  ║  Total Packets: " << Colors::BOLD_GREEN << std::left << std::setw(15) << stats.totalPackets << Colors::RESET 
                      << "  Total Bytes:   " << Colors::BOLD_GREEN << std::setw(15) << stats.totalBytes << Colors::RESET << " ║\n";
            std::cout << "  ║  TCP Packets:   " << Colors::CYAN << std::setw(15) << stats.tcpPackets << Colors::RESET 
                      << "  UDP Packets:   " << Colors::CYAN << std::setw(15) << stats.udpPackets << Colors::RESET << " ║\n";
            std::cout << "  ║  ICMP Packets:  " << Colors::CYAN << std::setw(15) << stats.icmpPackets << Colors::RESET 
                      << "  Throughput:    " << Colors::BOLD_YELLOW << std::setw(11) << std::fixed << std::setprecision(1) << stats.packetsPerSecond << " pps" << Colors::RESET << " ║\n";
            std::cout << Colors::BOLD_CYAN << "  ╚═════════════════════════════════════════════════════════════╝" << Colors::RESET << "\n";
        } else if (choice == 5) {
            auto alerts = alertManager->getAlerts();
            std::cout << "\n" << Colors::BOLD_RED << "  [DETECTED SECURITY ANOMALIES (" << alerts.size() << ")]" << Colors::RESET << "\n";
            if (alerts.empty()) {
                std::cout << Colors::GREEN << "  ✔ Clean baseline: No security anomalies detected in current window.\n" << Colors::RESET;
            } else {
                for (const auto& a : alerts) {
                    std::string badge = (a.severity == AlertSeverity::HIGH) ? Colors::BG_RED + " HIGH " + Colors::RESET :
                                        (a.severity == AlertSeverity::MEDIUM) ? Colors::BG_YELLOW + " MED  " + Colors::RESET :
                                                                                Colors::BG_BLUE + " LOW  " + Colors::RESET;
                    std::cout << "  " << badge << " " << Colors::DIM << "[" << a.timestampStr << "]" << Colors::RESET
                              << " " << Colors::BOLD << a.srcIp << Colors::RESET << " ➜ " << a.dstIp
                              << " | " << Colors::YELLOW << a.reason << Colors::RESET << "\n";
                }
            }
        } else if (choice == 6) {
            double dur = std::chrono::duration<double>(std::chrono::steady_clock::now() - startTime).count();
            ReportGenerator rep(dur, analyzer->getStats(),
                                analyzer->getTopSourceIps(),
                                analyzer->getTopDestinationIps(),
                                analyzer->getTopDestinationPorts(),
                                alertManager->getAlerts());
            rep.saveReportToFile("reports/activity_report.txt");
            std::cout << "\n" << Colors::BOLD_GREEN << "  ✔ Diagnostic report generated and archived to: " 
                      << Colors::WHITE << "reports/activity_report.txt\n" << Colors::RESET;
        } else if (choice == 7) {
            std::cout << "\n" << Colors::DIM << "  Activity log path: " << Colors::RESET << Colors::CYAN << logger->getLogPath() << Colors::RESET << "\n";
        } else if (choice == 8) {
            std::cout << "\n" << Colors::YELLOW << "  Halt command received. Shutting down capture loop..." << Colors::RESET << "\n";
            capture->stopCapture();
            std::cout << Colors::GREEN << "  ✔ Engine stopped cleanly. Goodbye!\n\n" << Colors::RESET;
            break;
        }
    }
    return 0;
}
