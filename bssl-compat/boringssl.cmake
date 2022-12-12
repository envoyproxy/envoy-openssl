
set(BSSL_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/boringssl/src")

add_custom_command(
  COMMENT "Copying BoringSSL files"
  OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/include/openssl
         ${CMAKE_CURRENT_SOURCE_DIR}/source/bytestring/cbb.c
         ${CMAKE_CURRENT_SOURCE_DIR}/source/bytestring/cbs.c
  COMMAND ${CMAKE_COMMAND} -E copy_directory "${BSSL_SOURCE_DIR}/include/openssl" "${CMAKE_CURRENT_SOURCE_DIR}/include/openssl"
  COMMAND ${CMAKE_COMMAND} -E copy "${BSSL_SOURCE_DIR}/crypto/bytestring/cbb.c" "${CMAKE_CURRENT_SOURCE_DIR}/source/bytestring/cbb.c"
  COMMAND ${CMAKE_COMMAND} -E copy "${BSSL_SOURCE_DIR}/crypto/bytestring/cbs.c" "${CMAKE_CURRENT_SOURCE_DIR}/source/bytestring/cbs.c"
)
