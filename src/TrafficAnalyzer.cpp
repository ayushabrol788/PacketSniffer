#include "TrafficAnalyzer.h"
#include <algorithm>

TrafficAnalyzer::TrafficAnalyzer() {
    startTime_ = std::chrono::steady_clock::now();
}

void TrafficAnalyzer::recordPacket(const ParsedPacket& pkt) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.totalPackets++;
    stats_.totalBytes += pkt.packetSize;

    if (pkt.protocol == NetworkProtocol::TCP) stats_.tcpPackets++;
    else if (pkt.protocol == NetworkProtocol::UDP) stats_.udpPackets++;
    else if (pkt.protocol == NetworkProtocol::ICMP) stats_.icmpPackets++;

    if (!pkt.srcIp.empty()) srcIpCounts_[pkt.srcIp]++;
    if (!pkt.dstIp.empty()) dstIpCounts_[pkt.dstIp]++;
    if (pkt.dstPort > 0) dstPortCounts_[pkt.dstPort]++;

    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - startTime_).count();
    if (elapsed > 0) {
        stats_.packetsPerSecond = static_cast<double>(stats_.totalPackets) / elapsed;
    }
}

TrafficStats TrafficAnalyzer::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

template <typename K>
std::vector<std::pair<K, uint64_t>> getTopN(const std::unordered_map<K, uint64_t>& m, size_t limit) {
    std::vector<std::pair<K, uint64_t>> vec(m.begin(), m.end());
    std::sort(vec.begin(), vec.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });
    if (vec.size() > limit) vec.resize(limit);
    return vec;
}

std::vector<std::pair<std::string, uint64_t>> TrafficAnalyzer::getTopSourceIps(size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return getTopN(srcIpCounts_, limit);
}

std::vector<std::pair<std::string, uint64_t>> TrafficAnalyzer::getTopDestinationIps(size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return getTopN(dstIpCounts_, limit);
}

std::vector<std::pair<uint16_t, uint64_t>> TrafficAnalyzer::getTopDestinationPorts(size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return getTopN(dstPortCounts_, limit);
}

void TrafficAnalyzer::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = TrafficStats{};
    srcIpCounts_.clear();
    dstIpCounts_.clear();
    dstPortCounts_.clear();
    startTime_ = std::chrono::steady_clock::now();
}
