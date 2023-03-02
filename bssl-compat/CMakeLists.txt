cmake_minimum_required(VERSION 3.21 FATAL_ERROR)

include(FetchContent)
include(GoogleTest)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

set(OPENSSL_URL      https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1m.tar.gz)
set(OPENSSL_URL_HASH 36ae24ad7cf0a824d0b76ac08861262e47ec541e5d0f20e6d94bab90b2dab360 )

#set(OPENSSL_URL      https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.7.tar.gz)
#set(OPENSSL_URL_HASH e8f73590815846db286d215950fdef9b882bb6b886d50acb431c0285782fe35b )

SET (CMAKE_C_COMPILER             "/usr/bin/clang")
SET (CMAKE_C_FLAGS                "-Wall")
SET (CMAKE_C_FLAGS_DEBUG          "-g")

SET (CMAKE_CXX_COMPILER           "/usr/bin/clang++")
SET (CMAKE_CXX_FLAGS              "-Wall")
SET (CMAKE_CXX_FLAGS_DEBUG        "-g")

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Debug)

project(bssl-compat
        VERSION 0.1
        LANGUAGES C CXX)

include(boringssl.cmake)
include(openssl.cmake)

add_subdirectory(prefixer)
add_custom_command(DEPENDS prefixer
                   COMMENT "Prefixing OpenSSL files"
                   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/source/ossl.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/include/ossl.h
                          ${CMAKE_CURRENT_SOURCE_DIR}/include/ossl/
                   COMMAND prefixer --src-path "${SRC_OPENSSL_HEADERS1}"
                                    --src-path "${SRC_OPENSSL_HEADERS2}"
                                    --src-incl "openssl/*.h"
                                    --src-skip "openssl/asn1_mac.h"
                                    --src-skip "openssl/opensslconf-*.h"
                                    --output "${CMAKE_CURRENT_SOURCE_DIR}"
                                    --prefix ossl)

add_custom_command(DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_ERR_GET_LIB.py
                           ${CMAKE_CURRENT_SOURCE_DIR}/include/openssl/err.h
                           ${CMAKE_CURRENT_SOURCE_DIR}/include/ossl/openssl/err.h
                   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/source/ERR_GET_LIB.c
                   COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_ERR_GET_LIB.py)

add_custom_command(DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_ERR_GET_REASON.py
                           ${CMAKE_CURRENT_SOURCE_DIR}/include/openssl/err.h
                           ${CMAKE_CURRENT_SOURCE_DIR}/include/ossl/openssl/err.h
                   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/source/ERR_GET_REASON.c
                   COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_ERR_GET_REASON.py)


add_library(bssl-compat
    STATIC
    source/ossl.c
    source/ossl_ERR_set_error.c
    source/crypto/bytestring/cbs.c
    source/crypto/bytestring/cbb.c
    source/crypto/asn1/a_int.c
    source/rand.c
    source/bio.cpp
    source/log.h
    source/log.c
    source/ssl.c
    source/ERR_GET_LIB.c
    source/ERR_GET_REASON.c
    source/bn.c
    source/err.c
    source/mem.c
    source/evp.c
    source/digest.c
    source/cipher.c
    source/crypto.c
)
set_source_files_properties(source/evp.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
target_include_directories(bssl-compat PUBLIC include)
target_link_libraries(bssl-compat INTERFACE ${CMAKE_DL_LIBS})


install(TARGETS bssl-compat LIBRARY DESTINATION lib)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/openssl DESTINATION include)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ext DESTINATION include)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ossl DESTINATION include)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/ossl.h DESTINATION include)

################################################################################
# Unit Tests
################################################################################

FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/5376968f6948923e2411081fd9372e71a59d8e77.zip)
FetchContent_MakeAvailable(googletest)
enable_testing()

add_executable(utests
  # Tests copied from BoringSSL
  source/crypto/err/err_test.cc
  source/crypto/rand_extra/rand_test.cc
  source/crypto/bio/bio_test.cc
  source/crypto/test/test_util.cc
  source/crypto/digest_extra/digest_test.cc
  # "Our" bssl-compat tests
  source/test/test_bn.cc
  source/test/test_cipher.cc
  source/test/test_evp.cc
  # Functions to support tests
  source/extra/bio_extra.c
  source/extra/mem_extra.c
  source/extra/err_extra.c
)
set_source_files_properties(source/extra/err_extra.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
target_link_libraries(utests PRIVATE GTest::gtest_main bssl-compat)
target_link_options(utests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/source/extra/digest_extra.ld)
target_link_options(utests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/source/extra/cipher_extra.ld)
gtest_discover_tests(utests)
