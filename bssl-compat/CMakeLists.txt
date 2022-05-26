cmake_minimum_required(VERSION 3.21 FATAL_ERROR)
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

# NOTE: If use GIT_REPOSITORY, there is a hidden passwd prompt that causes
# CMake init to block stopping messages from being displayed
# full cmake trace can be obtained with --trace-expand option
FetchContent_Declare(
    openssl
    URL "https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1m.tar.gz"
    URL_HASH SHA256=36ae24ad7cf0a824d0b76ac08861262e47ec541e5d0f20e6d94bab90b2dab360
)
FetchContent_MakeAvailable(openssl)

#message("XXXX ${openssl_SOURCE_DIR}")

add_definitions(
    -DHTTP_MAX_HEADER_SIZE=0x2000000
    -DHAVE_ZLIB
    -D__CLANG_SUPPORT_DYN_ANNOTATION__
    -DENVOY_PERF_ANNOTATION
    -DCARES_STATICLIB
    -DENVOY_GOOGLE_GRPC
    -DHAVE_PTHREAD
    -DHAVE_LONG_LONG
    -DNOIME)

# for simplicity, only defining one target, even though in test mode
# several binaries are created.  CMake is not used for build only for IDE
add_library(bssl-compat
        SHARED
        source/internal.h
        source/digest.c
        source/cbs.c
        source/cbb.c
        source/bn.c
        source/asn1_a_int.c
#        include/bssl_compat/bssl_compat.h
#        include/bssl_compat/openssl/bn.h
#        include/bssl_compat/openssl/digest.h
#        include/openssl/bytestring.h
#        include/openssl/span.h
        )

target_include_directories(bssl-compat PRIVATE
        # needed for ssl includes
        ${openssl_SOURCE_DIR}/include
        include
#       needed only if ssl/ssl.h is used.
#       ${openssl_SOURCE_DIR}
        )
