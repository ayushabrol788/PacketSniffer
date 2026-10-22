#include "AlertManager.h"

void AlertManager::registerAlert(const SecurityAlert& alert) {
    std::lock_guard<std::mutex> lock(mutex_);
    alerts_.push_back(alert);
}

std::vector<SecurityAlert> AlertManager::getAlerts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return alerts_;
}

std::unordered_map<std::string, size_t> AlertManager::getSeverityCounts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_map<std::string, size_t> counts = {{"LOW", 0}, {"MEDIUM", 0}, {"HIGH", 0}, {"CRITICAL", 0}};
    for (const auto& a : alerts_) {
        if (a.severity == AlertSeverity::LOW) counts["LOW"]++;
        else if (a.severity == AlertSeverity::MEDIUM) counts["MEDIUM"]++;
        else if (a.severity == AlertSeverity::HIGH) counts["HIGH"]++;
        else if (a.severity == AlertSeverity::CRITICAL) counts["CRITICAL"]++;
    }
    return counts;
}

void AlertManager::clearAlerts() {
    std::lock_guard<std::mutex> lock(mutex_);
    alerts_.clear();
}
