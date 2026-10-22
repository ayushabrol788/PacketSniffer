#include "Logger.h"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>

Logger::Logger(const std::string& logFilePath) : logFilePath_(logFilePath) {
    std::filesystem::path path(logFilePath_);
    if (path.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
    }
    fileStream_.open(logFilePath_, std::ios::app);
}

Logger::~Logger() {
    if (fileStream_.is_open()) fileStream_.close();
}

void Logger::logEvent(const std::string& level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << "[" << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S")
        << "] [" << level << "] " << message << "\n";
    if (fileStream_.is_open()) {
        fileStream_ << oss.str();
        fileStream_.flush();
    }
}
