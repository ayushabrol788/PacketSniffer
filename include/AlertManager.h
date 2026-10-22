#ifndef ALERT_MANAGER_H
#define ALERT_MANAGER_H

#include "AnomalyDetector.h"
#include <vector>
#include <mutex>
#include <unordered_map>
#include <string>

class AlertManager {
public:
    void registerAlert(const SecurityAlert& alert);
    std::vector<SecurityAlert> getAlerts() const;
    std::unordered_map<std::string, size_t> getSeverityCounts() const;
    void clearAlerts();

private:
    mutable std::mutex mutex_;
    std::vector<SecurityAlert> alerts_;
};

#endif // ALERT_MANAGER_H
