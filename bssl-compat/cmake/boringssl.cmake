include(ExternalProject)

ExternalProject_Add(BoringSSL
  PREFIX      "${CMAKE_CURRENT_BINARY_DIR}/external/boringssl"
  SOURCE_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/external/boringssl"
  CMAKE_ARGS  -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
              -DCMAKE_INSTALL_LIBDIR=lib
)

ExternalProject_Get_Property(BoringSSL INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(BoringSSL::SSL STATIC IMPORTED GLOBAL)
set_property(TARGET BoringSSL::SSL PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libssl.a)
set_property(TARGET BoringSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
add_dependencies(BoringSSL::SSL BoringSSL)

add_library(BoringSSL::Crypto STATIC IMPORTED GLOBAL)
set_property(TARGET BoringSSL::Crypto PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libcrypto.a)
set_property(TARGET BoringSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
add_dependencies(BoringSSL::Crypto BoringSSL)


function(_target_add_bssl_file target src-file dst-file)
  set(generate-cmd "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate.sh"
                      "${CMAKE_CURRENT_SOURCE_DIR}"
                      "${CMAKE_CURRENT_BINARY_DIR}"
                      "${src-file}" "${dst-file}")
  execute_process(COMMAND ${generate-cmd})
  target_sources(${target} PRIVATE ${dst-file})
  string(MAKE_C_IDENTIFIER ${dst-file} dst-file-target)
  add_custom_target(${dst-file-target} COMMAND ${generate-cmd})
  add_dependencies(${target} ${dst-file-target})
endfunction()

function(target_add_bssl_include target)
  foreach(src-file ${ARGN})
    _target_add_bssl_file(${target} "${src-file}" "${src-file}")
  endforeach()
endfunction()

function(target_add_bssl_source target)
  foreach(dst-file ${ARGN})
    cmake_path(RELATIVE_PATH dst-file BASE_DIRECTORY "source" OUTPUT_VARIABLE src-file)
    _target_add_bssl_file(${target} "${src-file}" "${dst-file}")
  endforeach()
endfunction()

add_custom_command(OUTPUT source/crypto/test/crypto_test_data.cc
                   DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/src/BoringSSL-build/crypto_test_data.cc
                   COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/src/BoringSSL-build/crypto_test_data.cc
                                                    source/crypto/test/crypto_test_data.cc
)