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
    source/crypto/fipsmodule/bn/cmp.c
    source/crypto/asn1/a_int.c
    source/rand.c
    source/bio.cpp
    source/log.h
    source/log.c
    source/ssl.c
    source/ERR_GET_LIB.c
    source/ERR_GET_REASON.c
)
target_include_directories(bssl-compat PUBLIC include)
target_link_libraries(bssl-compat INTERFACE ${CMAKE_DL_LIBS})


add_executable(test_rand)
target_sources(test_rand PRIVATE source/test/test_rand.c)
target_link_libraries(test_rand PRIVATE bssl-compat)

install(TARGETS bssl-compat LIBRARY DESTINATION lib)

################################################################################
# The bssl-compat-extra library contains implementations of BorinsSSL functions
# that are required just for building tests, but not for building Envoy.
################################################################################
add_library(bssl-compat-extra
	source/extra/BIO_ctrl_get_read_request.c
	source/extra/BIO_ctrl_get_write_guarantee.c
	source/extra/BIO_new_connect.c
	source/extra/BIO_printf.c
	source/extra/BIO_read.c
	source/extra/BIO_read_asn1.c
	source/extra/BIO_reset.c
	source/extra/BIO_snprintf.c
	source/extra/BIO_should_read.c
	source/extra/BIO_should_write.c
	source/extra/BIO_shutdown_wr.c
	source/extra/BIO_write.c
	source/extra/ERR_get_error.c
	source/extra/ERR_put_error.c
	source/extra/OPENSSL_free.c
	source/extra/OPENSSL_malloc.c
	source/extra/OPENSSL_realloc.c
)
target_include_directories(bssl-compat-extra PUBLIC include)


FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/5376968f6948923e2411081fd9372e71a59d8e77.zip)
FetchContent_MakeAvailable(googletest)
enable_testing()

################################################################################
# bio_test
################################################################################
add_executable(bio_test
  "${CMAKE_CURRENT_SOURCE_DIR}/source/crypto/bio/bio_test.cc"
  "${CMAKE_CURRENT_SOURCE_DIR}/source/crypto/test/test_util.cc"
)
target_link_libraries(bio_test PRIVATE GTest::gtest_main bssl-compat-extra bssl-compat)
gtest_discover_tests(bio_test)
