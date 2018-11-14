cmake_minimum_required(VERSION 2.8)

project(collect C)

set(CMAKE_C_STANDARD 11)

#add_executable(testc test.c)

add_executable(collect
        collect.c
        sbuf.c
        sbuf.h )

target_include_directories(collect PUBLIC /home/tsf/dpdk-16.07/x86_64-native-linuxapp-gcc/include)
link_directories(/home/tsf/dpdk-16.07/x86_64-native-linuxapp-gcc/lib)
find_library(DPDK libdpdk.a /home/tsf/dpdk-16.07/x86_64-native-linuxapp-gcc/lib)
target_link_libraries(collect pthread dl pcap )
add_definitions(-UDDEBUG -UDTEST -O3 -W -g -Wall)

#
#add_executable(main test/l2fwd/main.c)
#target_include_directories(collect PUBLIC /home/niubin/dpdk-18.08/x86_64-native-linuxapp-gcc/include)
#
#
#target_link_libraries(main ${DPDK} pthread numa dl)
