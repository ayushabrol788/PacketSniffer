#ifndef REPORT_GENERATOR_H
#define REPORT_GENERATOR_H

#include "TrafficAnalyzer.h"
#include "AnomalyDetector.h"
#include <string>
#include <vector>
#include <cstdint>

class ReportGenerator {
public:
    ReportGenerator(double durationSec,
                    const TrafficStats& stats,
                    const std::vector<std::pair<std::string, uint64_t>>& topSrcIps,
                    const std::vector<std::pair<std::string, uint64_t>>& topDstIps,
                    const std::vector<std::pair<uint16_t, uint64_t>>& topDstPorts,
                    const std::vector<SecurityAlert>& alerts);

    std::string generateTextReport() const;
    bool saveReportToFile(const std::string& filePath) const;

private:
    double durationSec_;
    TrafficStats stats_;
    std::vector<std::pair<std::string, uint64_t>> topSrcIps_;
    std::vector<std::pair<std::string, uint64_t>> topDstIps_;
    std::vector<std::pair<uint16_t, uint64_t>> topDstPorts_;
    std::vector<SecurityAlert> alerts_;
};

#endif // REPORT_GENERATOR_H
