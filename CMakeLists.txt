cmake_minimum_required(VERSION 3.20)
project(PacketSniffer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${PCAP_INCLUDE_DIRS})

add_library(sniffer_core
    src/PacketCapture.cpp
    src/PacketParser.cpp
    src/PacketFilter.cpp
    src/TrafficAnalyzer.cpp
    src/AnomalyDetector.cpp
    src/AlertManager.cpp
    src/Logger.cpp
    src/ReportGenerator.cpp
)
target_link_libraries(sniffer_core PUBLIC ${PCAP_LIBRARIES} pthread)

add_executable(packet_sniffer src/main.cpp)
target_link_libraries(packet_sniffer PRIVATE sniffer_core)

enable_testing()
add_executable(run_tests tests/test_suite.cpp)
target_link_libraries(run_tests PRIVATE sniffer_core)
add_test(NAME SnifferTestSuite COMMAND run_tests)
