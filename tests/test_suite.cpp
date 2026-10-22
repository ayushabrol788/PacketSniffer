#include "PacketParser.h"
#include "PacketFilter.h"
#include "TrafficAnalyzer.h"
#include "AnomalyDetector.h"
#include <cassert>
#include <iostream>

void testPacketParser() {
    // Malformed packet check
    PacketRawData raw;
    raw.payload = {0x00, 0x01}; // Too short for Ethernet header
    auto parsed = PacketParser::parse(raw);
    assert(!parsed.has_value());
    std::cout << "[PASS] Malformed packet safety check\n";
}

void testPacketFilter() {
    PacketFilter filter;
    FilterCriteria fc;
    fc.protocol = NetworkProtocol::TCP;
    filter.setFilter(fc);

    ParsedPacket p1;
    p1.protocol = NetworkProtocol::TCP;
    ParsedPacket p2;
    p2.protocol = NetworkProtocol::UDP;

    assert(filter.matches(p1));
    assert(!filter.matches(p2));
    std::cout << "[PASS] Protocol filter logic check\n";
}

void testTrafficAnalyzer() {
    TrafficAnalyzer analyzer;
    ParsedPacket p;
    p.protocol = NetworkProtocol::TCP;
    p.packetSize = 100;
    analyzer.recordPacket(p);
    auto stats = analyzer.getStats();
    assert(stats.totalPackets == 1);
    assert(stats.tcpPackets == 1);
    std::cout << "[PASS] Traffic statistics aggregation check\n";
}

void testPortScanDetection() {
    AnomalyDetector detector;
    ParsedPacket p;
    p.hasIp = true;
    p.srcIp = "192.168.1.55";
    p.dstIp = "10.0.0.1";

    bool triggered = false;
    for (int port = 1000; port < 1025; ++port) {
        p.dstPort = static_cast<uint16_t>(port);
        auto alerts = detector.analyze(p);
        if (!alerts.empty()) triggered = true;
    }
    assert(triggered);
    std::cout << "[PASS] Port scan detection rule check\n";
}

int main() {
    testPacketParser();
    testPacketFilter();
    testTrafficAnalyzer();
    testPortScanDetection();
    std::cout << "\nALL UNIT TESTS PASSED SUCCESSFULLY!\n";
    return 0;
}
