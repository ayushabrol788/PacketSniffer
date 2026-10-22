#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H

#include "PacketParser.h"
#include <string>
#include <optional>

struct FilterCriteria {
    std::optional<NetworkProtocol> protocol;
    std::optional<std::string> srcIp;
    std::optional<std::string> dstIp;
    std::optional<uint16_t> srcPort;
    std::optional<uint16_t> dstPort;
};

class PacketFilter {
public:
    void setFilter(const FilterCriteria& criteria) { criteria_ = criteria; }
    void clearFilter() { criteria_ = FilterCriteria{}; }
    bool matches(const ParsedPacket& pkt) const;
    bool hasActiveFilter() const;
private:
    FilterCriteria criteria_;
};

#endif // PACKET_FILTER_H
