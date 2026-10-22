#ifndef TRAFFIC_ANALYZER_H
#define TRAFFIC_ANALYZER_H

#include "PacketParser.h"
#include <cstdint>
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <chrono>

struct TrafficStats {
    uint64_t totalPackets = 0;
    uint64_t totalBytes = 0;
    uint64_t tcpPackets = 0;
    uint64_t udpPackets = 0;
    uint64_t icmpPackets = 0;
    double packetsPerSecond = 0.0;
};

class TrafficAnalyzer {
public:
    TrafficAnalyzer();
    void recordPacket(const ParsedPacket& pkt);
    TrafficStats getStats() const;
    std::vector<std::pair<std::string, uint64_t>> getTopSourceIps(size_t limit = 5) const;
    std::vector<std::pair<std::string, uint64_t>> getTopDestinationIps(size_t limit = 5) const;
    std::vector<std::pair<uint16_t, uint64_t>> getTopDestinationPorts(size_t limit = 5) const;
    void reset();

private:
    mutable std::mutex mutex_;
    TrafficStats stats_;
    std::chrono::steady_clock::time_point startTime_;
    std::unordered_map<std::string, uint64_t> srcIpCounts_;
    std::unordered_map<std::string, uint64_t> dstIpCounts_;
    std::unordered_map<uint16_t, uint64_t> dstPortCounts_;
};

#endif // TRAFFIC_ANALYZER_H
