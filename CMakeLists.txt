cmake_minimum_required(VERSION 3.16)
project(snifftags)

set(CMAKE_CXX_STANDARD 20)

SET(CMAKE_CXX_FLAGS "-pthread")

include(FindPCAP.cmake)

add_executable(snifftags main.cpp)

target_link_libraries(snifftags ${PCAP_LIBRARY})