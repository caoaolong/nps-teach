cmake_minimum_required(VERSION 3.30)
project(nps_teach C)

set(CMAKE_C_STANDARD 23)
set(NPCAP_DIR ${PROJECT_SOURCE_DIR}/npcap)

include_directories(${NPCAP_DIR}/Include)
link_directories(${NPCAP_DIR}/Lib/x64)

add_executable(nps_teach main.c)

target_link_libraries(nps_teach Packet.lib wpcap.lib)