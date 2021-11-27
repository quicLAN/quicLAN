
cmake_minimum_required(VERSION 3.17)

project(quiclan)

# Necessary to include msquic headers
if ("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Windows")
    set(QUIC_PLATFORM "windows")
    set(QUICLAN_C_FLAGS "-DWIN32_LEAN_AND_MEAN -DSECURITY_WIN32 /MP")
else()
    set(QUIC_PLATFORM "linux")
    set(QUICLAN_COMMON_FLAGS "-DCX_PLATFORM_LINUX -fms-extensions -fPIC -pthread -Wl,--no-as-needed -ldl")

    set(QUICLAN_C_FLAGS "${QUICLAN_COMMON_FLAGS}")
    set(QUICLAN_CXX_FLAGS "${QUICLAN_COMMON_FLAGS} --std=c++17 -g -Wno-reorder -Wno-sign-compare -Wno-format")
endif()

include_directories(${CMAKE_SOURCE_DIR}/submodules/msquic/src/inc)
include_directories(${CMAKE_SOURCE_DIR}/src/inc)

set(QUIC_TLS "openssl")
set(QUIC_BUILD_TOOLS CACHE BOOL OFF)
set(QUIC_BUILD_TEST CACHE BOOL OFF)
set(QUIC_BUILD_PERF CACHE BOOL OFF)
set(QUIC_BUILD_SHARED CACHE BOOL OFF)
add_subdirectory(submodules/msquic)
#find_package(msquic PATHS submodules/msquic)
add_subdirectory(src/core)
add_subdirectory(src/test)
add_subdirectory(src/linux)
