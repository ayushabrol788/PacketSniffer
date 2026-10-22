#include "PacketCapture.h"
#include <iostream>
#include <cstring>

PacketCapture::~PacketCapture() {
    stopCapture();
}

std::vector<std::string> PacketCapture::listInterfaces() const {
    std::vector<std::string> ifaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs != nullptr) {
        for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
            if (dev->name) {
                ifaces.push_back(std::string(dev->name));
            }
        }
        pcap_freealldevs(alldevs);
    }
    return ifaces;
}

void PacketCapture::pcapDispatchCallback(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    auto* callbackPtr = reinterpret_cast<PacketCallback*>(userData);
    if (!callbackPtr || !pkthdr || !packet) return;

    PacketRawData raw;
    raw.timestamp = pkthdr->ts;
    raw.caplen = pkthdr->caplen;
    raw.len = pkthdr->len;
    raw.payload.assign(packet, packet + pkthdr->caplen);

    (*callbackPtr)(raw);
}

bool PacketCapture::startCapture(const std::string& interfaceName, PacketCallback callback) {
    if (capturing_) stopCapture();

    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle_) {
        lastError_ = errbuf;
        return false;
    }

    capturing_ = true;
    static PacketCallback activeCallback;
    activeCallback = callback;

    while (capturing_) {
        int res = pcap_dispatch(handle_, 10, pcapDispatchCallback, reinterpret_cast<u_char*>(&activeCallback));
        if (res < 0) {
            lastError_ = "pcap_dispatch error or interface closed.";
            capturing_ = false;
            break;
        }
    }
    return true;
}

void PacketCapture::stopCapture() {
    capturing_ = false;
    if (handle_) {
        pcap_breakloop(handle_);
        pcap_close(handle_);
        handle_ = nullptr;
    }
}
