#include "PacketFilter.h"

bool PacketFilter::hasActiveFilter() const {
    return criteria_.protocol.has_value() ||
           criteria_.srcIp.has_value() ||
           criteria_.dstIp.has_value() ||
           criteria_.srcPort.has_value() ||
           criteria_.dstPort.has_value();
}

bool PacketFilter::matches(const ParsedPacket& pkt) const {
    if (!hasActiveFilter()) return true;

    if (criteria_.protocol.has_value() && pkt.protocol != criteria_.protocol.value()) {
        return false;
    }
    if (criteria_.srcIp.has_value() && pkt.srcIp != criteria_.srcIp.value()) {
        return false;
    }
    if (criteria_.dstIp.has_value() && pkt.dstIp != criteria_.dstIp.value()) {
        return false;
    }
    if (criteria_.srcPort.has_value() && pkt.srcPort != criteria_.srcPort.value()) {
        return false;
    }
    if (criteria_.dstPort.has_value() && pkt.dstPort != criteria_.dstPort.value()) {
        return false;
    }
    return true;
}
