include(CheckIncludeFile)

check_include_file ("openssl/ssl.h" OS_OPENSSL_HEADERS)
find_library (OS_SSL_LIBRARY ssl)
find_library (OS_CRYPTO_LIBRARY crypto)

if (OS_OPENSSL_HEADERS AND  OS_SSL_LIBRARY AND OS_CRYPTO_LIBRARY)
    MESSAGE (STATUS "OpenSSL is already installed")

    set(OPENSSL_INCLUDE_DIR "")

    add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::SSL PROPERTY IMPORTED_LOCATION "${OS_SSL_LIBRARY}")
    add_dependencies(OpenSSL::SSL OpenSSL)

    add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION "${OS_CRYPTO_LIBRARY}")
    add_dependencies(OpenSSL::Crypto OpenSSL)

else (OS_OPENSSL_HEADERS AND  OS_SSL_LIBRARY AND OS_CRYPTO_LIBRARY)
    MESSAGE (STATUS "Installing OpenSSL as external project")

    #  Load OpenSSL as an external project and set up properties to enable build.
    set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-src) # default path by CMake
    set(OPENSSL_BUILD_LOG_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-build-log})
    set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
    set(OPENSSL_CONFIGURE_COMMAND ${OPENSSL_SOURCE_DIR}/config)
    set(OPENSSL_LIBRARY_SUFFIX so)
    ExternalProject_Add(
        OpenSSL
        SOURCE_DIR ${OPENSSL_SOURCE_DIR}
        URL ${OPENSSL_URL}
        URL_HASH SHA256=${OPENSSL_URL_HASH}
        USES_TERMINAL_DOWNLOAD TRUE
        CONFIGURE_COMMAND ${OPENSSL_SOURCE_DIR}/config
        --prefix=${OPENSSL_INSTALL_DIR}
        --openssldir=${OPENSSL_INSTALL_DIR}
        BUILD_COMMAND make
        LOG ${OPENSSL_BUILD_LOG_DIR}
        LOG_BUILD TRUE
        TEST_COMMAND ""
        INSTALL_COMMAND make install
        INSTALL_DIR ${OPENSSL_INSTALL_DIR}
    )

    add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::SSL PROPERTY IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib/libssl.${OPENSSL_LIBRARY_SUFFIX})
    set_property(TARGET OpenSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
    add_dependencies(OpenSSL::SSL OpenSSL)

    add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib/libcrypto.${OPENSSL_LIBRARY_SUFFIX})
    set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
    add_dependencies(OpenSSL::Crypto OpenSSL)

endif (OS_OPENSSL_HEADERS AND  OS_SSL_LIBRARY AND OS_CRYPTO_LIBRARY)

