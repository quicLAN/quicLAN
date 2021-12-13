
project(quiclan)
cmake_minimum_required(VERSION 3.17)

# Necessary to include msquic headers
if ("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Windows")
    set(QUIC_PLATFORM "windows")
    set(QUICLAN_C_FLAGS "-DWIN32_LEAN_AND_MEAN -DSECURITY_WIN32 /MP")
else()
    set(QUIC_PLATFORM "linux")
    set(QUICLAN_COMMON_FLAGS "-DCX_PLATFORM_LINUX -fms-extensions -fPIC -pthread -Wl,--no-as-needed -ldl")

    set(QUICLAN_C_FLAGS "${QUICLAN_COMMON_FLAGS}")
    set(QUICLAN_CXX_FLAGS "${QUICLAN_COMMON_FLAGS} --std=c++20 -g -Wno-reorder -Wno-sign-compare -Wno-format")
endif()


set(QUICLAN_FOLDER_PREFIX "" CACHE STRING "Optional prefix for source group folders when using an IDE generator")
set(QUICLAN_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/inc)

#include_directories(${CMAKE_SOURCE_DIR}/submodules/msquic/src/inc)
# Use the same OpenSSL version as MsQuic
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/submodules/msquic/submodules/openssl/include)
# include_directories(${CMAKE_SOURCE_DIR}/submodules/msquic/submodules/googletest/googletest/include)
#include_directories(${CMAKE_SOURCE_DIR}/src/inc)

set(QUIC_TLS "openssl")
set(QUIC_BUILD_TOOLS OFF CACHE BOOL "Don't use the tools")
set(QUIC_BUILD_TEST OFF CACHE BOOL "Don't need the tests")
set(QUIC_BUILD_PERF OFF CACHE BOOL "Don't need perf")
set(QUIC_ENABLE_LOGGING ON CACHE BOOL "Enable MsQuic logging")
set(QUIC_BUILD_SHARED OFF CACHE BOOL "Statically linking")
set(CMAKE_BUILD_TYPE "Debug")
add_subdirectory(submodules/msquic)
target_compile_features(inc INTERFACE cxx_std_20)
#set_property(TARGET msquic PROPERTY QUIC_ENABLE_LOGGING ON)
#find_package(msquic PATHS submodules/msquic)
# add_subdirectory(src/inc)
add_subdirectory(src/core)
add_subdirectory(src/linux)


include(FetchContent)
enable_testing()
set(PREV_BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS} CACHE INTERNAL "")
set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
set(BUILD_GMOCK OFF CACHE BOOL "Builds the googlemock subproject")
set(INSTALL_GTEST OFF CACHE BOOL "Enable installation of googletest. (Projects embedding googletest may want to turn this OFF.)")
if(WIN32 AND QUIC_STATIC_LINK_CRT)
    option(gtest_force_shared_crt "Use shared (DLL) run-time lib even when Google Test is built as static lib." ON)
endif()
FetchContent_Declare(
    googletest
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/submodules/msquic/submodules/googletest
)
FetchContent_MakeAvailable(googletest)
set(BUILD_SHARED_LIBS ${PREV_BUILD_SHARED_LIBS} CACHE INTERNAL "")

set_property(TARGET gtest PROPERTY CXX_STANDARD 20)
set_property(TARGET gtest PROPERTY FOLDER "${QUICLAN_FOLDER_PREFIX}tests")

set_property(TARGET gtest_main PROPERTY CXX_STANDARD 20)
set_property(TARGET gtest_main PROPERTY FOLDER "${QUICLAN_FOLDER_PREFIX}tests")
set_property(TARGET gtest_main PROPERTY EXCLUDE_FROM_ALL ON)
set_property(TARGET gtest_main PROPERTY EXCLUDE_FROM_DEFAULT_BUILD ON)

add_subdirectory(src/test)
