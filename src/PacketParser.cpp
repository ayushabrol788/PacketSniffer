#ifndef __FAVOR_BSD
#define __FAVOR_BSD 1
#endif

#include "PacketParser.h"
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

std::string PacketParser::macToString(const uint8_t* mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
        if (i < 5) oss << ":";
    }
    return oss.str();
}

std::string PacketParser::ipToString(uint32_t ip) {
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = ip;
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return std::string(buf);
    }
    return "0.0.0.0";
}

std::optional<ParsedPacket> PacketParser::parse(const PacketRawData& raw) {
    if (raw.payload.size() < sizeof(struct ether_header)) {
        return std::nullopt;
    }

    ParsedPacket pkt;
    pkt.timestamp = raw.timestamp;
    pkt.packetSize = raw.len;

    const auto* eth = reinterpret_cast<const struct ether_header*>(raw.payload.data());
    pkt.srcMac = macToString(eth->ether_shost);
    pkt.dstMac = macToString(eth->ether_dhost);

    uint16_t ethType = ntohs(eth->ether_type);
    size_t offset = sizeof(struct ether_header);

    if (ethType == ETHERTYPE_IP) {
        if (raw.payload.size() < offset + sizeof(struct ip)) return std::nullopt;
        const auto* ipHdr = reinterpret_cast<const struct ip*>(raw.payload.data() + offset);
        pkt.hasIp = true;
        pkt.isIpv6 = false;
        pkt.srcIp = ipToString(ipHdr->ip_src.s_addr);
        pkt.dstIp = ipToString(ipHdr->ip_dst.s_addr);
        uint8_t ipProto = ipHdr->ip_p;
        size_t ipLen = ipHdr->ip_hl * 4;
        offset += ipLen;

        if (ipProto == IPPROTO_TCP) {
            pkt.protocol = NetworkProtocol::TCP;
            if (raw.payload.size() >= offset + sizeof(struct tcphdr)) {
                const auto* tcpHdr = reinterpret_cast<const struct tcphdr*>(raw.payload.data() + offset);
                pkt.srcPort = ntohs(tcpHdr->th_sport);
                pkt.dstPort = ntohs(tcpHdr->th_dport);
            }
        } else if (ipProto == IPPROTO_UDP) {
            pkt.protocol = NetworkProtocol::UDP;
            if (raw.payload.size() >= offset + sizeof(struct udphdr)) {
                const auto* udpHdr = reinterpret_cast<const struct udphdr*>(raw.payload.data() + offset);
                pkt.srcPort = ntohs(udpHdr->uh_sport);
                pkt.dstPort = ntohs(udpHdr->uh_dport);
            }
        } else if (ipProto == IPPROTO_ICMP) {
            pkt.protocol = NetworkProtocol::ICMP;
        } else {
            pkt.protocol = NetworkProtocol::UNKNOWN;
        }
        pkt.isValid = true;
        return pkt;
    }
    return std::nullopt;
}
