set(bssl-gen-targets "")

function(bssl_add_gitignore dir ignorefile)
  file(READ "${dir}/.gitignore" GITIGNORE)
  string(FIND "${GITIGNORE}" "${ignorefile}" match)
  if(${match} EQUAL -1)
    message(WARNING "Please add ${ignorefile} to bssl-compat/.gitignore")
    # Bazel build does not allow changing original source files,
    # so temporarily commented the call to execute_process()
    # execute_process(
    #   COMMAND echo "${ignorefile} # Copied"
    #   COMMAND sort -u -o "${dir}/.gitignore" - "${dir}/.gitignore"
    # )
  endif ()
endfunction()

function(bssl_copy_and_patch src dst)
  set(depends ${src})
  set(commands COMMAND ${CMAKE_COMMAND} -E copy ${src} ${CMAKE_CURRENT_SOURCE_DIR}/${dst})
  file(GLOB patches RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/patch" "${CMAKE_CURRENT_SOURCE_DIR}/patch/${dst}.*")
  foreach(patch ${patches})
    list(APPEND depends patch/${patch})
    list(APPEND commands COMMAND echo " - Applying patch/${patch}")
    if("${patch}" MATCHES ".*\.patch")
      list(APPEND commands COMMAND patch -s ${CMAKE_CURRENT_SOURCE_DIR}/${dst} ${CMAKE_CURRENT_SOURCE_DIR}/patch/${patch})
    elseif("${patch}" MATCHES ".*\.sh")
      list(APPEND commands COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/patch/${patch} ${CMAKE_CURRENT_SOURCE_DIR}/${dst})
    endif()
  endforeach()
  add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/${dst}
    DEPENDS ${depends}
    ${commands}
  )
  list(APPEND bssl-gen-targets ${CMAKE_CURRENT_SOURCE_DIR}/${dst})
  set (bssl-gen-targets  ${bssl-gen-targets} PARENT_SCOPE)
  set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES "${CMAKE_CURRENT_SOURCE_DIR}/${dst}")
  bssl_add_gitignore("${CMAKE_CURRENT_SOURCE_DIR}" "${dst}")
endfunction()

function(bssl_copy_src src)
  bssl_copy_and_patch("${CMAKE_CURRENT_SOURCE_DIR}/boringssl/${src}" "source/${src}")
  set (bssl-gen-targets  ${bssl-gen-targets} PARENT_SCOPE)
endfunction()

function(bssl_copy_hdr hdr)
  bssl_copy_and_patch("${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include/${hdr}" "include/${hdr}")
  set (bssl-gen-targets  ${bssl-gen-targets} PARENT_SCOPE)
endfunction()

function(bssl_copy_files)
  file(GLOB headers RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include/" "${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include/openssl/*.h")

  foreach(hdr ${headers})
    bssl_copy_hdr(${hdr})
  endforeach()

  bssl_copy_src(crypto/bytestring/cbs.c)
  bssl_copy_src(crypto/bytestring/cbb.c)
  bssl_copy_src(crypto/bytestring/internal.h)
  bssl_copy_src(crypto/internal.h)
  bssl_copy_src(crypto/test/test_util.h)
  bssl_copy_src(crypto/test/test_util.cc)
  bssl_copy_src(crypto/bio/bio_test.cc)
  bssl_copy_src(crypto/rand_extra/rand_test.cc)
  bssl_copy_src(crypto/err/err_test.cc)
  bssl_copy_src(crypto/digest_extra/digest_test.cc)
  bssl_copy_src(crypto/stack/stack_test.cc)

  bssl_copy_src(ssl/ssl_test.cc)
  bssl_copy_src(ssl/internal.h)
  bssl_copy_src(crypto/err/internal.h)
  bssl_copy_src(crypto/lhash/internal.h)

  set (bssl-gen-targets  ${bssl-gen-targets} PARENT_SCOPE)
endfunction()

bssl_copy_files()
add_custom_target(bssl-gen DEPENDS ${bssl-gen-targets})
