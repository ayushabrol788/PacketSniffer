#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#include "PacketParser.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <mutex>
#include <cstdint>

enum class AlertSeverity { LOW, MEDIUM, HIGH, CRITICAL };

struct SecurityAlert {
    std::string timestampStr;
    std::string srcIp;
    std::string dstIp;
    std::string reason;
    std::string recommendedAction;
    AlertSeverity severity;
};

struct DetectionConfig {
    size_t portScanPortThreshold = 10;
    double portScanTimeWindowSeconds = 5.0;
    size_t highBurstRateThreshold = 200;
    size_t synFloodThreshold = 50;
    size_t icmpFloodThreshold = 30;
    bool alertOnSuspiciousPorts = true;
};

class AnomalyDetector {
public:
    AnomalyDetector(DetectionConfig config = DetectionConfig());
    std::vector<SecurityAlert> analyze(const ParsedPacket& pkt);
    void updateConfig(const DetectionConfig& cfg);
    DetectionConfig getConfig() const { return config_; }

    // Active defense controls
    void blockIp(const std::string& ip);
    void unblockIp(const std::string& ip);
    bool isIpBlocked(const std::string& ip) const;
    std::vector<std::string> getBlockedIps() const;

private:
    struct SourceActivity {
        std::chrono::steady_clock::time_point firstSeen;
        std::unordered_map<uint16_t, size_t> contactedPorts;
        uint64_t packetCountInWindow = 0;
        uint64_t icmpCountInWindow = 0;
        std::chrono::steady_clock::time_point lastAlertTime;
    };

    DetectionConfig config_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, SourceActivity> sourceMap_;
    std::unordered_set<std::string> blockedIps_;
    std::string getCurrentTimestampString() const;
};

#endif // ANOMALY_DETECTOR_H
