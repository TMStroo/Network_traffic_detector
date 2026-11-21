cmake_minimum_required(VERSION 3.20)

project(NetworkTrafficAnalyzer
    VERSION 1.1.0
    DESCRIPTION "Reads PCAP captures and finds unusual network activity"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SQLite3 REQUIRED)

add_executable(nta
    src/main.cpp
    src/cli.cpp
    src/pcap.cpp
    src/packet.cpp
    src/conversation.cpp
    src/storage.cpp
    src/detector.cpp
    src/timeline.cpp
    src/python_stats.cpp
    src/correlator.cpp
)

target_include_directories(nta PRIVATE src)
target_link_libraries(nta PRIVATE SQLite::SQLite3)

if(MSVC)
    target_compile_options(nta PRIVATE /W4)
else()
    target_compile_options(nta PRIVATE -Wall -Wextra)
endif()

install(TARGETS nta RUNTIME DESTINATION bin)

enable_testing()

add_executable(nta_packet_tests
    tests/test_packet.cpp
    src/packet.cpp
)
target_include_directories(nta_packet_tests PRIVATE src)
add_test(NAME packet_parser_tests COMMAND nta_packet_tests)

add_executable(nta_pcap_tests
    tests/test_pcap.cpp
    src/pcap.cpp
)
target_include_directories(nta_pcap_tests PRIVATE src)
add_test(NAME pcap_reader_tests COMMAND nta_pcap_tests)
