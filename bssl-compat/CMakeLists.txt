cmake_minimum_required(VERSION 3.22 FATAL_ERROR)
include(ExternalProject)

set(OPENSSL_URL      https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1m.tar.gz)
set(OPENSSL_URL_HASH 36ae24ad7cf0a824d0b76ac08861262e47ec541e5d0f20e6d94bab90b2dab360 )

SET (CMAKE_C_COMPILER             "/usr/bin/clang")
SET (CMAKE_C_FLAGS                "-Wall -std=c99")
SET (CMAKE_C_FLAGS_DEBUG          "-g")

SET (CMAKE_CXX_COMPILER           "/usr/bin/clang++")
SET (CMAKE_CXX_FLAGS              "-Wall")
SET (CMAKE_CXX_FLAGS_DEBUG        "-g")

include(CMakePrintHelpers)
include(FetchContent)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libstdc++")
set(CMAKE_CXX_STANDARD 17)
set(USING_OPENSSL true)
set(CMAKE_BUILD_TYPE Debug)

project(bssl-compat
        VERSION 0.1
        LANGUAGES C CXX)

find_package(Threads)

include(openssl.cmake)

add_definitions(
    -DHTTP_MAX_HEADER_SIZE=0x2000000
    -DHAVE_ZLIB
    -D__CLANG_SUPPORT_DYN_ANNOTATION__
    -DENVOY_PERF_ANNOTATION
    -DCARES_STATICLIB
    -DENVOY_GOOGLE_GRPC
    -DHAVE_PTHREAD
    -DHAVE_LONG_LONG
    -DNOIME
    )

add_library(bssl-compat
    SHARED
    source/internal.h
    source/digest.c
    source/cbs.c
    source/cbb.c
    source/bn.c
    source/asn1_a_int.c
    source/bssl_openssl.c
    source/rand.c
    source/ssl.c
    )

add_dependencies(bssl-compat
        OpenSSL::SSL
        OpenSSL::Crypto)

target_link_libraries(bssl-compat PRIVATE OpenSSL::Crypto)
target_include_directories(bssl-compat PUBLIC
        # needed for ssl includes
        ${OPENSSL_INCLUDE_DIR}
        include
#       needed only if ssl/ssl.h is used.
#       ${openssl_SOURCE_DIR}
        )

add_executable(test_rand)
target_sources(test_rand PRIVATE source/test/test_rand.c)
target_link_libraries(test_rand PRIVATE bssl-compat)

install(TARGETS bssl-compat LIBRARY DESTINATION lib)
