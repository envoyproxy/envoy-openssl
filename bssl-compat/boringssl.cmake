

# Copy, and optionally patch, the openssl/*.h headers from the ${CMAKE_CURRENT_SOURCE_DIR}/boringssl
# directory into the ${CMAKE_CURRENT_SOURCE_DIR}/include directory, to form our public interface.
file(GLOB bsslheaders RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/boringssl/src/include/" "${CMAKE_CURRENT_SOURCE_DIR}/boringssl/src/include/openssl/*.h")
foreach(bsslheader ${bsslheaders})
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/boringssl/src/include/${bsslheader}" "${CMAKE_CURRENT_SOURCE_DIR}/include/${bsslheader}" COPYONLY)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/patch/include/${bsslheader}.patch")
    execute_process(COMMAND patch -s "${CMAKE_CURRENT_SOURCE_DIR}/include/${bsslheader}" "${CMAKE_CURRENT_SOURCE_DIR}/patch/include/${bsslheader}.patch")
    message("Copied ${bsslheader} (patched)")
  else()
    message("Copied ${bsslheader}")
  endif()
endforeach()


# Copy the specified file from the BoringSSL source tree into our build
# directory, and patch it if a corresponding patch file exists.
function(copy_bssl_src bsslfile)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/boringssl/src/${bsslfile}" "${CMAKE_CURRENT_SOURCE_DIR}/source/${bsslfile}" COPYONLY)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/patch/source/${bsslfile}.patch")
    execute_process(COMMAND patch -s "${CMAKE_CURRENT_SOURCE_DIR}/source/${bsslfile}" "${CMAKE_CURRENT_SOURCE_DIR}/patch/source/${bsslfile}.patch")
    message("Copied ${bsslfile} (patched)")
  else()
    message("Copied ${bsslfile}")
  endif()
endfunction()


copy_bssl_src(crypto/bytestring/cbs.c)
copy_bssl_src(crypto/bytestring/cbb.c)
copy_bssl_src(crypto/bytestring/internal.h)
copy_bssl_src(crypto/fipsmodule/bn/cmp.c)
copy_bssl_src(crypto/asn1/a_int.c)
copy_bssl_src(crypto/internal.h)

copy_bssl_src(crypto/test/test_util.h)
copy_bssl_src(crypto/test/test_util.cc)
copy_bssl_src(crypto/bio/bio_test.cc)
