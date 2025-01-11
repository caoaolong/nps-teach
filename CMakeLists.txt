cmake_minimum_required(VERSION 3.30)
project(nps_teach C)

set(CMAKE_C_STANDARD 23)
set(NPCAP_DIR ${PROJECT_SOURCE_DIR}/npcap)

include_directories(${NPCAP_DIR}/Include src/inc)
link_directories(${NPCAP_DIR}/Lib/x64)

add_executable(nps_teach src/nps.c src/device.c
        src/prtc/ethii.c
        src/prtc/arp.c
        src/prtc/ip.c
        src/prtc/icmp.c
        src/utils/stack.c
        src/prtc/udp.c)

target_link_libraries(nps_teach ws2_32 Packet.lib wpcap.lib)