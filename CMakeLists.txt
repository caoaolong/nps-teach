cmake_minimum_required(VERSION 3.10.2)
project(nps_teach C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")

include_directories(${PROJECT_SOURCE_DIR}/src/inc)

add_executable(nps_teach src/nps.c src/device.c src/sock2.c
        src/prtc/ethii.c
        src/prtc/arp.c
        src/prtc/ip.c
        src/prtc/icmp.c
        src/utils/stack.c
        src/prtc/udp.c
        src/prtc/tcp.c
        src/nps_main.c
        src/nps_view.c
        src/utils/tcputil.c)

target_link_libraries(nps_teach ncurses pcap pthread)