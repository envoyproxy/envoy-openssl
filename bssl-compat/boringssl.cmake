
function(add_gitignore ignorefile)
  # Bazel build does not allow changing original source files, temporarily commented the call to execute_process()
  # TODO: find another solution for updating .gitignore
  # execute_process(COMMAND echo "${ignorefile}" COMMAND sort -u -o "${CMAKE_CURRENT_SOURCE_DIR}/.gitignore" - "${CMAKE_CURRENT_SOURCE_DIR}/.gitignore")
endfunction()

# Copy, and optionally patch, the openssl/*.h headers from the ${CMAKE_CURRENT_SOURCE_DIR}/boringssl
# directory into the ${CMAKE_CURRENT_SOURCE_DIR}/include directory, to form our public interface.
file(GLOB bsslheaders RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include/" "${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include/openssl/*.h")
foreach(bsslheader ${bsslheaders})
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include/${bsslheader}" "${CMAKE_CURRENT_SOURCE_DIR}/include/${bsslheader}" COPYONLY)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/patch/include/${bsslheader}.patch")
    execute_process(COMMAND patch -s "${CMAKE_CURRENT_SOURCE_DIR}/include/${bsslheader}" "${CMAKE_CURRENT_SOURCE_DIR}/patch/include/${bsslheader}.patch")
    message("Copied ${bsslheader} (patched)")
  else()
    message("Copied ${bsslheader}")
  endif()
  set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/${bsslheader}")
  add_gitignore("include/${bsslheader} # Copied from boringssl/include/${bsslheader}")
endforeach()


# Copy the specified file from the BoringSSL source tree into our build
# directory, and patch it if a corresponding patch file exists.
function(copy_bssl_src bsslfile)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/boringssl/${bsslfile}" "${CMAKE_CURRENT_SOURCE_DIR}/source/${bsslfile}" COPYONLY)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/patch/source/${bsslfile}.patch")
    execute_process(COMMAND patch -s "${CMAKE_CURRENT_SOURCE_DIR}/source/${bsslfile}" "${CMAKE_CURRENT_SOURCE_DIR}/patch/source/${bsslfile}.patch")
    message("Copied ${bsslfile} (patched)")
  else()
    message("Copied ${bsslfile}")
  endif()
  set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES "${CMAKE_CURRENT_SOURCE_DIR}/source/${bsslfile}")
  add_gitignore("source/${bsslfile} # Copied from boringssl/${bsslfile}")
endfunction()


copy_bssl_src(crypto/bytestring/cbs.c)
copy_bssl_src(crypto/bytestring/cbb.c)
copy_bssl_src(crypto/bytestring/internal.h)
copy_bssl_src(crypto/internal.h)
copy_bssl_src(crypto/test/test_util.h)
copy_bssl_src(crypto/test/test_util.cc)
copy_bssl_src(crypto/bio/bio_test.cc)
copy_bssl_src(crypto/rand_extra/rand_test.cc)
copy_bssl_src(crypto/err/err_test.cc)
copy_bssl_src(crypto/digest_extra/digest_test.cc)
