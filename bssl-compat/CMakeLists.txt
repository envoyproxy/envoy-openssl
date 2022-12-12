cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

set(OPENSSL_URL      https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1m.tar.gz)
set(OPENSSL_URL_HASH 36ae24ad7cf0a824d0b76ac08861262e47ec541e5d0f20e6d94bab90b2dab360 )

#set(OPENSSL_URL      https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.7.tar.gz)
#set(OPENSSL_URL_HASH e8f73590815846db286d215950fdef9b882bb6b886d50acb431c0285782fe35b )

SET (CMAKE_C_COMPILER             "/usr/bin/clang")
SET (CMAKE_C_FLAGS                "-Wall -std=c99")
SET (CMAKE_C_FLAGS_DEBUG          "-g")

SET (CMAKE_CXX_COMPILER           "/usr/bin/clang++")
SET (CMAKE_CXX_FLAGS              "-Wall")
SET (CMAKE_CXX_FLAGS_DEBUG        "-g")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Debug)

project(bssl-compat
        VERSION 0.1
        LANGUAGES C CXX)

include(boringssl.cmake)
include(openssl.cmake)

add_subdirectory(prefixer)
add_custom_command(DEPENDS prefixer
                   OUTPUT ossl.c include/ossl.h include/ossl/
                   COMMAND prefixer --src-path "${SRC_OPENSSL_HEADERS1}"
                                    --src-path "${SRC_OPENSSL_HEADERS2}"
                                    --src-incl "openssl/*.h"
                                    --src-skip "openssl/asn1_mac.h"
                                    --src-skip "openssl/opensslconf-*.h"
                                    --output "${CMAKE_CURRENT_BINARY_DIR}"
                                    --prefix ossl --force)

add_library(bssl-compat
    STATIC
    ossl.c
    source/internal.h
    source/bytestring/cbs.c
    source/bytestring/cbb.c
    source/bytestring/internal.h
    source/bn.c
    source/asn1_a_int.c
    source/rand.c
    source/bio.cpp
    source/log.h
    source/log.c
)
target_include_directories(bssl-compat PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include)
target_include_directories(bssl-compat PUBLIC include)
target_link_libraries(bssl-compat INTERFACE ${CMAKE_DL_LIBS})


add_executable(test_rand)
target_sources(test_rand PRIVATE source/test/test_rand.c)
target_link_libraries(test_rand PRIVATE bssl-compat)

install(TARGETS bssl-compat LIBRARY DESTINATION lib)
