#include "AnomalyDetector.h"
#include <iomanip>
#include <sstream>

AnomalyDetector::AnomalyDetector(DetectionConfig config) : config_(config) {}

std::string AnomalyDetector::getCurrentTimestampString() const {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void AnomalyDetector::blockIp(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    blockedIps_.insert(ip);
}

void AnomalyDetector::unblockIp(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    blockedIps_.erase(ip);
}

bool AnomalyDetector::isIpBlocked(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blockedIps_.find(ip) != blockedIps_.end();
}

std::vector<std::string> AnomalyDetector::getBlockedIps() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<std::string>(blockedIps_.begin(), blockedIps_.end());
}

std::vector<SecurityAlert> AnomalyDetector::analyze(const ParsedPacket& pkt) {
    std::vector<SecurityAlert> generatedAlerts;
    if (!pkt.hasIp || pkt.srcIp.empty()) return generatedAlerts;

    std::lock_guard<std::mutex> lock(mutex_);

    // Active Defense Check: Is host already quarantined?
    if (blockedIps_.find(pkt.srcIp) != blockedIps_.end()) {
        return generatedAlerts; // Silently drop traffic from quarantined IP
    }

    auto now = std::chrono::steady_clock::now();
    auto& entry = sourceMap_[pkt.srcIp];

    double elapsed = std::chrono::duration<double>(now - entry.firstSeen).count();
    if (entry.firstSeen.time_since_epoch().count() == 0 || elapsed > config_.portScanTimeWindowSeconds) {
        entry.firstSeen = now;
        entry.contactedPorts.clear();
        entry.packetCountInWindow = 0;
        entry.icmpCountInWindow = 0;
    }

    entry.packetCountInWindow++;
    if (pkt.dstPort > 0) {
        entry.contactedPorts[pkt.dstPort]++;
    }
    if (pkt.protocol == NetworkProtocol::ICMP) {
        entry.icmpCountInWindow++;
    }

    double alertDelta = std::chrono::duration<double>(now - entry.lastAlertTime).count();

    // Rule 1: Port Scan Detection (Reconnaissance)
    if (entry.contactedPorts.size() >= config_.portScanPortThreshold) {
        if (alertDelta > 3.0) {
            AlertSeverity sev = (entry.contactedPorts.size() > config_.portScanPortThreshold * 2) 
                                 ? AlertSeverity::CRITICAL : AlertSeverity::MEDIUM;
            generatedAlerts.push_back({
                getCurrentTimestampString(),
                pkt.srcIp,
                pkt.dstIp,
                "Reconnaissance port sweep detected: touched " + std::to_string(entry.contactedPorts.size()) + " ports",
                "Quarantine host: sudo iptables -A INPUT -s " + pkt.srcIp + " -j DROP",
                sev
            });
            entry.lastAlertTime = now;
        }
    }

    // Rule 2: High Burst Rate Activity (DoS / Flooding)
    if (entry.packetCountInWindow > config_.highBurstRateThreshold) {
        if (alertDelta > 3.0) {
            generatedAlerts.push_back({
                getCurrentTimestampString(),
                pkt.srcIp,
                pkt.dstIp,
                "Volumetric burst flood: " + std::to_string(entry.packetCountInWindow) + " pkts in 5s window",
                "Enable rate-limiting: iptables -A INPUT -p tcp -m limit --limit 25/minute -j ACCEPT",
                AlertSeverity::HIGH
            });
            entry.lastAlertTime = now;
        }
    }

    // Rule 3: ICMP Flood / Ping Sweep
    if (entry.icmpCountInWindow >= config_.icmpFloodThreshold) {
        if (alertDelta > 3.0) {
            generatedAlerts.push_back({
                getCurrentTimestampString(),
                pkt.srcIp,
                pkt.dstIp,
                "ICMP echo storm detected: " + std::to_string(entry.icmpCountInWindow) + " pings in window",
                "Disable ICMP responses: sysctl -w net.ipv4.icmp_echo_ignore_all=1",
                AlertSeverity::MEDIUM
            });
            entry.lastAlertTime = now;
        }
    }

    // Rule 4: Suspicious Insecure Cleartext / Critical Ports
    if (config_.alertOnSuspiciousPorts && pkt.dstPort == 23) { // Telnet (Cleartext)
        if (alertDelta > 5.0) {
            generatedAlerts.push_back({
                getCurrentTimestampString(),
                pkt.srcIp,
                pkt.dstIp,
                "Insecure Telnet connection attempt (Port 23 cleartext protocol)",
                "Decommission Telnet service and migrate to SSH (Port 22)",
                AlertSeverity::LOW
            });
            entry.lastAlertTime = now;
        }
    }

    return generatedAlerts;
}

void AnomalyDetector::updateConfig(const DetectionConfig& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
}
