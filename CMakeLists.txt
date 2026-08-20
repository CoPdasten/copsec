cmake_minimum_required(VERSION 3.16)
project(copsec VERSION 1.0.0 LANGUAGES CXX)

option(BUILD_TESTS "Build CoPSeC test suite" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

add_compile_options(-Wall -Wextra -Wpedantic -O3)

find_package(PkgConfig REQUIRED)
pkg_check_modules(NFTABLES REQUIRED libnftables)

find_package(nlohmann_json REQUIRED)
find_package(Threads REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

if(BUILD_TESTS)
    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()
endif()

find_package(LibMaxMindDB QUIET)
if (LibMaxMindDB_FOUND)
    set(COPSEC_MAXMINDDB_LIBS ${LibMaxMindDB_LIBRARIES})
    set(COPSEC_MAXMINDDB_INCLUDE ${LibMaxMindDB_INCLUDE_DIRS})
else()
    set(COPSEC_MAXMINDDB_LIBS "")
    set(COPSEC_MAXMINDDB_INCLUDE "")
endif()

pkg_check_modules(PCAP QUIET libpcap)
if (PCAP_FOUND)
    set(COPSEC_PCAP_LIBS ${PCAP_LIBRARIES})
    set(COPSEC_PCAP_INCLUDE ${PCAP_INCLUDE_DIRS})
    add_compile_definitions(COPSEC_HAS_PCAP)
else()
    set(COPSEC_PCAP_LIBS "")
    set(COPSEC_PCAP_INCLUDE "")
endif()

pkg_check_modules(LIBBPF QUIET libbpf)
find_program(CLANG_EXECUTABLE clang)
if (LIBBPF_FOUND AND CLANG_EXECUTABLE)
    add_compile_definitions(COPSEC_HAS_LIBBPF)

    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bpf)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/bpf/copsec_xdp.bpf.o
        COMMAND ${CLANG_EXECUTABLE} -target bpf -O2 -g
                -I${LIBBPF_INCLUDE_DIRS}
                -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/copsec_xdp.bpf.c
                -o ${CMAKE_CURRENT_BINARY_DIR}/bpf/copsec_xdp.bpf.o
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bpf/copsec_xdp.bpf.c
    )
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/bpf/copsec_kprobe.bpf.o
        COMMAND ${CLANG_EXECUTABLE} -target bpf -O2 -g
                -I${LIBBPF_INCLUDE_DIRS}
                -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/copsec_kprobe.bpf.c
                -o ${CMAKE_CURRENT_BINARY_DIR}/bpf/copsec_kprobe.bpf.o
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bpf/copsec_kprobe.bpf.c
    )
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/bpf/copsec_ringbuf.bpf.o
        COMMAND ${CLANG_EXECUTABLE} -target bpf -O2 -g
                -I${LIBBPF_INCLUDE_DIRS}
                -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/copsec_ringbuf.bpf.c
                -o ${CMAKE_CURRENT_BINARY_DIR}/bpf/copsec_ringbuf.bpf.o
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bpf/copsec_ringbuf.bpf.c
    )
    add_custom_target(copsec_bpf_objects DEPENDS
        ${CMAKE_CURRENT_BINARY_DIR}/bpf/copsec_xdp.bpf.o
        ${CMAKE_CURRENT_BINARY_DIR}/bpf/copsec_kprobe.bpf.o
        ${CMAKE_CURRENT_BINARY_DIR}/bpf/copsec_ringbuf.bpf.o
    )
    add_dependencies(copsec copsec_bpf_objects)
endif()

add_executable(copsec
    src/main.cpp
    src/bouncer.cpp
    src/logger.cpp
    src/parser.cpp
    src/detection_engine.cpp
    src/mitre.cpp
    src/xdp_bouncer.cpp
    src/ebpf_monitor.cpp
    src/soar_worker.cpp
    src/anti_evasion.cpp
    src/pcap_manager.cpp
    src/rate_limiter.cpp
    src/shm_guard.cpp
    src/db_manager.cpp
    src/mitre_engine.cpp
    src/suricata_watcher.cpp
)

add_executable(copsec-cli
    src/copsec_cli.cpp
    src/xdp_bouncer.cpp
    src/logger.cpp
    src/shm_guard.cpp
    src/db_manager.cpp
    src/mitre.cpp
    src/mitre_engine.cpp
    src/pcap_manager.cpp
)

# include directories
foreach(target copsec copsec-cli)
    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${NFTABLES_INCLUDE_DIRS}
        ${CURL_INCLUDE_DIRS}
        ${COPSEC_MAXMINDDB_INCLUDE}
        ${COPSEC_PCAP_INCLUDE}
        ${LIBBPF_INCLUDE_DIRS}
    )
endforeach()

# link libraries
target_link_libraries(copsec PRIVATE
    ${NFTABLES_LIBRARIES}
    ${COPSEC_MAXMINDDB_LIBS}
    ${COPSEC_PCAP_LIBS}
    nlohmann_json::nlohmann_json
    Threads::Threads
    CURL::libcurl
    ${LIBBPF_LIBRARIES}
    OpenSSL::Crypto
    SQLite::SQLite3
)

target_link_libraries(copsec-cli PRIVATE
    Threads::Threads
    ${COPSEC_PCAP_LIBS}
    CURL::libcurl
    OpenSSL::Crypto
    SQLite::SQLite3
)

if(BUILD_TESTS)
    enable_testing()

    add_executable(test_bouncer
        tests/test_bouncer.cpp
        src/bouncer.cpp
        src/db_manager.cpp
        src/logger.cpp
        src/mitre.cpp
        src/mitre_engine.cpp
        src/pcap_manager.cpp
        src/shm_guard.cpp
        src/sync.cpp
        src/xdp_bouncer.cpp
    )

    target_include_directories(test_bouncer PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${NFTABLES_INCLUDE_DIRS}
        ${CURL_INCLUDE_DIRS}
        ${COPSEC_MAXMINDDB_INCLUDE}
        ${COPSEC_PCAP_INCLUDE}
        ${LIBBPF_INCLUDE_DIRS}
    )

    target_link_libraries(test_bouncer PRIVATE
        GTest::gtest_main
        ${NFTABLES_LIBRARIES}
        ${COPSEC_MAXMINDDB_LIBS}
        ${COPSEC_PCAP_LIBS}
        Threads::Threads
        CURL::libcurl
        OpenSSL::Crypto
        SQLite::SQLite3
    )

    include(GoogleTest)
    gtest_discover_tests(test_bouncer)
endif()