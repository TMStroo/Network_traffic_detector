cmake_minimum_required(VERSION 3.20)

project(NetworkTrafficAnalyzer
    VERSION 1.0.0
    DESCRIPTION "Reads PCAP captures and finds unusual network activity"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)

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

# libsqlite3 is installed as a shared library without the dev symlink here.
target_link_libraries(nta PRIVATE /usr/lib/x86_64-linux-gnu/libsqlite3.so.0)

install(TARGETS nta RUNTIME DESTINATION bin)
