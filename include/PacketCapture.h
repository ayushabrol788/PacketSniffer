#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstdint>
#include <sys/time.h>
#include <pcap.h>

struct PacketRawData {
    struct timeval timestamp;
    uint32_t caplen;
    uint32_t len;
    std::vector<uint8_t> payload;
};

using PacketCallback = std::function<void(const PacketRawData&)>;

class PacketCapture {
public:
    PacketCapture() = default;
    ~PacketCapture();

    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    std::vector<std::string> listInterfaces() const;
    bool startCapture(const std::string& interfaceName, PacketCallback callback);
    void stopCapture();
    bool isCapturing() const { return capturing_; }
    std::string getLastError() const { return lastError_; }

private:
    pcap_t* handle_ = nullptr;
    bool capturing_ = false;
    std::string lastError_;
    static void pcapDispatchCallback(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
};

#endif // PACKET_CAPTURE_H
