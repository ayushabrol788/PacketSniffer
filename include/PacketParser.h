#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "PacketCapture.h"
#include <string>
#include <cstdint>
#include <optional>

enum class NetworkProtocol { UNKNOWN, TCP, UDP, ICMP };

struct ParsedPacket {
    struct timeval timestamp;
    uint32_t packetSize = 0;
    std::string srcMac;
    std::string dstMac;
    bool hasIp = false;
    std::string srcIp;
    std::string dstIp;
    bool isIpv6 = false;
    NetworkProtocol protocol = NetworkProtocol::UNKNOWN;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    bool isValid = false;
};

class PacketParser {
public:
    static std::optional<ParsedPacket> parse(const PacketRawData& raw);
private:
    static std::string macToString(const uint8_t* mac);
    static std::string ipToString(uint32_t ip);
};

#endif // PACKET_PARSER_H
