#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <mutex>

class Logger {
public:
    explicit Logger(const std::string& logFilePath);
    ~Logger();
    void logEvent(const std::string& level, const std::string& message);
    std::string getLogPath() const { return logFilePath_; }

private:
    std::string logFilePath_;
    std::ofstream fileStream_;
    mutable std::mutex mutex_;
};

#endif // LOGGER_H
