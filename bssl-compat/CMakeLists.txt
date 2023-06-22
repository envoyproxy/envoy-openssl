cmake_minimum_required(VERSION 3.24 FATAL_ERROR)

include(FetchContent)
include(GoogleTest)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

set(OPENSSL_URL      https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.8.tar.gz)
set(OPENSSL_URL_HASH 6933e2f1da6f23a50ea226eec6e91b543d277d2098025763b5931cf6a7e099c7)

SET (CMAKE_C_COMPILER             "clang")
SET (CMAKE_C_FLAGS                "-Wall")
SET (CMAKE_C_FLAGS_DEBUG          "-g")

SET (CMAKE_CXX_COMPILER           "clang++")
SET (CMAKE_CXX_FLAGS              "-Wall")
SET (CMAKE_CXX_FLAGS_DEBUG        "-g")

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Debug)

project(bssl-compat VERSION 0.1 LANGUAGES C CXX)

include(cmake/boringssl.cmake)
include(cmake/openssl.cmake)

add_subdirectory(prefixer)
add_custom_command(DEPENDS prefixer
                   COMMENT "Prefixing OpenSSL files"
                   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/source/ossl.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/include/ossl.h
                          ${CMAKE_CURRENT_SOURCE_DIR}/include/ossl/openssl/err.h
                   COMMAND prefixer --src-path "${SRC_OPENSSL_HEADERS1}"
                                    --src-path "${SRC_OPENSSL_HEADERS2}"
                                    --src-incl "openssl/*.h"
                                    --src-skip "openssl/asn1_mac.h"
                                    --src-skip "openssl/opensslconf-*.h"
                                    --output "${CMAKE_CURRENT_SOURCE_DIR}"
                                    --prefix ossl)

add_custom_target(ossl-gen DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/include/ossl.h)

add_library(bssl-compat STATIC
  source/asn1.c
  source/ASN1_TIME_adj.cc
  source/BASIC_CONSTRAINTS_free.cc
  source/BASIC_CONSTRAINTS_new.cc
  source/bio.cpp
  source/BIO_up_ref.cc
  source/bn.c
  source/BN_hex2bn.cc
  source/BN_set_word.cc
  source/cipher.c
  source/CRYPTO_BUFFER_free.c
  source/CRYPTO_BUFFER.h
  source/CRYPTO_BUFFER_new.c
  source/crypto.c
  source/d2i_GENERAL_NAME.cc
  source/d2i_PKCS12_bio.cc
  source/d2i_SSL_SESSION.c
  source/digest.c
  source/DTLS_method.cc
  source/ECDSA_sign.cc
  source/ECDSA_size.cc
  source/EC_GROUP_get0_order.cc
  source/EC_GROUP_get_curve_name.cc
  source/EC_GROUP_get_degree.cc
  source/EC_KEY_free.cc
  source/EC_KEY_get0_group.cc
  source/EC_KEY_parse_private_key.cc
  source/err.c
  source/evp.c
  source/EVP_DecodeBase64.c
  source/EVP_DecodedLength.c
  source/EVP_PKEY_cmp.cc
  source/GENERAL_NAME_cmp.cc
  source/GENERAL_NAME_free.cc
  source/GENERAL_NAME_new.cc
  source/GENERAL_NAME_set0_value.cc
  source/GENERAL_NAMES_new.cc
  source/GENERAL_SUBTREE_free.cc
  source/GENERAL_SUBTREE_new.cc
  source/HMAC.cc
  source/HMAC_CTX_free.cc
  source/HMAC_CTX_new.cc
  source/HMAC_Final.cc
  source/HMAC_Init_ex.cc
  source/HMAC_Update.cc
  source/i2d_SSL_SESSION.c
  source/internal.h
  source/log.c
  source/log.h
  source/MD5.cc
  source/mem.c
  source/NAME_CONSTRAINTS_free.cc
  source/NAME_CONSTRAINTS_new.cc
  source/OBJ_txt2obj.cc
  source/ossl.c
  source/ossl_ERR_set_error.c
  source/PEM_bytes_read_bio.c
  source/PEM_read_bio_PrivateKey.cc
  source/PEM_read_bio_RSAPrivateKey.c
  source/PEM_read_bio_X509_CRL.cc
  source/PEM_X509_INFO_read_bio.cc
  source/PKCS12_free.cc
  source/PKCS12_get_key_and_certs.cc
  source/PKCS12_parse.cc
  source/PKCS12_verify_mac.cc
  source/rand.c
  source/RSA_bits.cc
  source/RSA_check_key.cc
  source/RSA_decrypt.cc
  source/RSA_encrypt.cc
  source/RSA_free.c
  source/RSA_generate_key_ex.cc
  source/RSA_get0_crt_params.cc
  source/RSA_get0_factors.cc
  source/RSA_get0_key.cc
  source/RSA_new.cc
  source/RSA_private_key_from_bytes.cc
  source/RSA_public_key_from_bytes.cc
  source/RSA_set0_crt_params.cc
  source/RSA_set0_factors.cc
  source/RSA_set0_key.cc
  source/RSA_sign.cc
  source/RSA_size.cc
  source/RSA_verify.cc
  source/ssl.c
  source/ssl_cipher.c
  source/SSL_CIPHER_get_auth_nid.cc
  source/SSL_CIPHER_get_cipher_nid.cc
  source/SSL_CIPHER_get_digest_nid.cc
  source/SSL_CIPHER_get_id.cc
  source/SSL_CIPHER_get_kx_nid.cc
  source/SSL_CIPHER_get_prf_nid.cc
  source/SSL_CIPHER_get_rfc_name.cc
  source/SSL_CIPHER_standard_name.cc
  source/SSL_CTX_add_extra_chain_cert.cc
  source/ssl_ctx.c
  source/ssl_ctx.cc
  source/SSL_CTX_free.cc
  source/SSL_CTX_get0_param.cc
  source/SSL_CTX_get_cert_store.cc
  source/SSL_CTX_get_client_CA_list.cc
  source/SSL_CTX_get_max_proto_version.cc
  source/SSL_CTX_get_min_proto_version.cc
  source/SSL_CTX_get_options.cc
  source/SSL_CTX_get_verify_mode.cc
  source/SSL_CTX_new.cc
  source/SSL_CTX_sess_set_new_cb.cc
  source/SSL_CTX_set1_curves_list.c
  source/SSL_CTX_set1_sigalgs_list.c
  source/SSL_CTX_set_alpn_protos.cc
  source/SSL_CTX_set_alpn_select_cb.cc
  source/SSL_CTX_set_cert_verify_callback.cc
  source/SSL_CTX_set_max_proto_version.cc
  source/SSL_CTX_set_options.cc
  source/SSL_CTX_set_session_cache_mode.cc
  source/SSL_CTX_set_session_id_context.cc
  source/SSL_CTX_set_timeout.cc
  source/SSL_CTX_set_tlsext_servername_arg.cc
  source/SSL_CTX_set_tlsext_servername_callback.cc
  source/SSL_CTX_set_tlsext_status_cb.c
  source/SSL_CTX_set_tlsext_ticket_key_cb.cc
  source/SSL_CTX_set_tlsext_ticket_keys.cc
  source/SSL_CTX_set_verify_depth.cc
  source/SSL_CTX_use_certificate_file.cc
  source/SSL_CTX_use_PrivateKey.cc
  source/SSL_CTX_use_PrivateKey_file.cc
  source/SSL_early_callback_ctx_extension_get.c
  source/ssl_ext.c
  source/SSL_get0_alpn_selected.cc
  source/SSL_get0_ocsp_response.c
  source/SSL_get1_session.c
  source/SSL_get_cipher_by_value.c
  source/SSL_get_client_CA_list.cc
  source/SSL_get_current_cipher.cc
  source/SSL_get_curve_id.c
  source/SSL_get_curve_name.c
  source/SSL_get_ex_data.cc
  source/SSL_get_ex_data_X509_STORE_CTX_idx.cc
  source/SSL_get_ex_new_index.cc
  source/SSL_get_peer_cert_chain.cc
  source/SSL_get_peer_certificate.cc
  source/SSL_get_peer_signature_algorithm.c
  source/SSL_get_servername.cc
  source/SSL_get_session.cc
  source/SSL_get_signature_algorithm_digest.cc
  source/SSL_get_signature_algorithm_key_type.cc
  source/SSL_get_signature_algorithm_name.c
  source/SSL_get_SSL_CTX.cc
  source/SSL_get_version.cc
  source/SSL_get_wbio.cc
  source/SSL_is_signature_algorithm_rsa_pss.cc
  source/SSL_new.cc
  source/SSL_read.cc
  source/SSL_select_next_proto.cc
  source/SSL_SESSION_free.cc
  source/SSL_SESSION_from_bytes.c
  source/SSL_SESSION_get_id.c
  source/SSL_SESSION_get_ticket_lifetime_hint.cc
  source/SSL_SESSION_get_version.cc
  source/SSL_SESSION_is_resumable.c
  source/SSL_session_reused.cc
  source/SSL_SESSION_to_bytes.c
  source/SSL_set1_curves_list.cc
  source/SSL_set_accept_state.cc
  source/SSL_set_alpn_protos.cc
  source/SSL_set_bio.cc
  source/SSL_set_cert_cb.cc
  source/SSL_set_chain_and_key.cc
  source/SSL_set_cipher_list.cc
  source/SSL_set_client_CA_list.cc
  source/SSL_set_connect_state.cc
  source/SSL_set_ex_data.cc
  source/SSL_set_fd.cc
  source/SSL_set_quiet_shutdown.cc
  source/SSL_set_session.cc
  source/SSL_set_session_id_context.cc
  source/SSL_set_tlsext_host_name.c
  source/SSL_set_verify.cc
  source/SSL_shutdown.cc
  source/SSL_version.cc
  source/SSL_write.cc
  source/stack.c
  source/TLS_method.cc
  source/TLS_VERSION_to_string.cc
  source/X509_add1_ext_i2d.cc
  source/X509_alias_get0.cc
  source/X509_CRL_cmp.cc
  source/X509_CRL_free.cc
  source/X509_CRL_up_ref.cc
  source/X509_get_extension_flags.cc
  source/X509_get_issuer_name.cc
  source/X509_getm_notAfter.cc
  source/X509_getm_notBefore.cc
  source/X509_get_pathlen.cc
  source/X509_get_pubkey.cc
  source/X509_get_subject_name.cc
  source/X509_INFO_free.cc
  source/X509_NAME_add_entry_by_txt.cc
  source/X509_NAME_cmp.cc
  source/X509_NAME_dup.cc
  source/X509_NAME_free.cc
  source/X509_NAME_new.cc
  source/X509_new.cc
  source/X509_set_pubkey.cc
  source/X509_set_version.cc
  source/X509_sign.cc
  source/X509_STORE_CTX_free.cc
  source/X509_STORE_CTX_get0_param.cc
  source/X509_STORE_CTX_get0_untrusted.cc
  source/X509_STORE_CTX_get_error.cc
  source/X509_STORE_CTX_init.cc
  source/X509_STORE_CTX_new.cc
  source/X509_STORE_CTX_set0_crls.cc
  source/X509_STORE_CTX_set_default.cc
  source/X509_STORE_CTX_set_error.cc
  source/X509_STORE_CTX_set_verify_cb.cc
  source/X509_STORE_CTX_trusted_stack.cc
  source/X509_STORE_free.cc
  source/X509_STORE_new.cc
  source/X509_STORE_set_flags.cc
  source/X509_STORE_set_verify_cb.cc
  source/X509_up_ref.cc
  source/X509_verify.cc
  source/X509_verify_cert.cc
  source/X509_verify_cert_error_string.cc
  source/X509_VERIFY_PARAM_clear_flags.cc
  source/X509_VERIFY_PARAM_set1.cc
  source/X509_VERIFY_PARAM_set_flags.cc
  source/X509_VERIFY_PARAM_set_time.cc
)

target_add_bssl_function(bssl-compat
  X509_STORE_CTX_get_error_depth
  X509_STORE_CTX_get_ex_data
)

target_add_bssl_source(bssl-compat
  source/crypto/internal.h
  source/crypto/bytestring/cbs.c
  source/crypto/bytestring/cbb.c
)

target_add_bssl_include(bssl-compat
  include/openssl/aead.h
  include/openssl/aes.h
  include/openssl/arm_arch.h
  include/openssl/asn1.h
  include/openssl/asn1_mac.h
  include/openssl/asn1t.h
  include/openssl/base64.h
  include/openssl/base.h
  include/openssl/bio.h
  include/openssl/blake2.h
  include/openssl/blowfish.h
  include/openssl/bn.h
  include/openssl/buffer.h
  include/openssl/buf.h
  include/openssl/bytestring.h
  include/openssl/cast.h
  include/openssl/chacha.h
  include/openssl/cipher.h
  include/openssl/cmac.h
  include/openssl/conf.h
  include/openssl/cpu.h
  include/openssl/crypto.h
  include/openssl/curve25519.h
  include/openssl/des.h
  include/openssl/dh.h
  include/openssl/digest.h
  include/openssl/dsa.h
  include/openssl/dtls1.h
  include/openssl/ecdh.h
  include/openssl/ecdsa.h
  include/openssl/ec.h
  include/openssl/ec_key.h
  include/openssl/engine.h
  include/openssl/e_os2.h
  include/openssl/err.h
  include/openssl/evp_errors.h
  include/openssl/evp.h
  include/openssl/ex_data.h
  include/openssl/hkdf.h
  include/openssl/hmac.h
  include/openssl/hpke.h
  include/openssl/hrss.h
  include/openssl/is_boringssl.h
  include/openssl/kdf.h
  include/openssl/lhash.h
  include/openssl/md4.h
  include/openssl/md5.h
  include/openssl/mem.h
  include/openssl/nid.h
  include/openssl/objects.h
  include/openssl/obj.h
  include/openssl/obj_mac.h
  include/openssl/opensslconf.h
  include/openssl/opensslv.h
  include/openssl/ossl_typ.h
  include/openssl/pem.h
  include/openssl/pkcs12.h
  include/openssl/pkcs7.h
  include/openssl/pkcs8.h
  include/openssl/poly1305.h
  include/openssl/pool.h
  include/openssl/rand.h
  include/openssl/rc4.h
  include/openssl/ripemd.h
  include/openssl/rsa.h
  include/openssl/safestack.h
  include/openssl/service_indicator.h
  include/openssl/sha.h
  include/openssl/siphash.h
  include/openssl/span.h
  include/openssl/srtp.h
  include/openssl/ssl3.h
  include/openssl/ssl.h
  include/openssl/stack.h
  include/openssl/thread.h
  include/openssl/tls1.h
  include/openssl/trust_token.h
  include/openssl/type_check.h
  include/openssl/x509.h
  include/openssl/x509v3.h
  include/openssl/x509_vfy.h
)
set_source_files_properties(source/evp.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
set_source_files_properties(source/RSA_free.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
set_source_files_properties(source/PEM_read_bio_RSAPrivateKey.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
target_include_directories(bssl-compat PUBLIC include)
target_link_libraries(bssl-compat INTERFACE ${CMAKE_DL_LIBS})


################################################################################
# Intallation
################################################################################

install(TARGETS bssl-compat LIBRARY DESTINATION lib)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include DESTINATION include)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ext DESTINATION include)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ossl DESTINATION include)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/ossl.h DESTINATION include)

################################################################################
# Unit Tests
################################################################################

FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/5376968f6948923e2411081fd9372e71a59d8e77.zip)
FetchContent_MakeAvailable(googletest)
enable_testing()

set(utests-bssl-source-list
  # Tests copied/patched from BoringSSL
  source/crypto/bio/bio_test.cc
  source/crypto/digest_extra/digest_test.cc
  source/crypto/err/err_test.cc
  source/crypto/hmac_extra/hmac_test.cc
  source/crypto/pkcs8/pkcs12_test.cc
  source/crypto/rand_extra/rand_test.cc
  source/crypto/rsa_extra/rsa_test.cc
  source/crypto/stack/stack_test.cc
  source/crypto/test/file_test_gtest.cc
  source/crypto/test/file_test.cc
  source/crypto/test/file_test.h
  source/crypto/test/test_util.cc
  source/crypto/test/test_util.h
  source/crypto/x509/x509_test.cc
  source/crypto/x509v3/internal.h
  source/ssl/ssl_c_test.c
  source/ssl/ssl_test.cc
)

set(utests-source-list
  # Our hand written bssl-compat tests
  source/test/test_asn1.cc
  source/test/test_bn.cc
  source/test/test_cipher.cc
  source/test/test_crypto.cc
  source/test/test_ec_key.cc
  source/test/test_evp.cc
  source/test/test_hmac.cc
  source/test/test_rsa.cc
  source/test/test_ssl.cc
  source/test/test_stack.cc
)

################################################################################
# Unit Tests built on bssl-compat
################################################################################
add_executable(utests-bssl-compat
  ${utests-source-list}
  source/crypto/test/crypto_test_data.cc
  source/extra/asn1_extra.c
  source/extra/bio_extra.c
  source/extra/err_extra.c
  source/extra/mem_extra.c
  source/extra/pem_extra.c
  source/extra/ssl_extra.c
)
target_add_bssl_source(utests-bssl-compat ${utests-bssl-source-list})
set_source_files_properties(source/extra/err_extra.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
target_link_libraries(utests-bssl-compat PRIVATE GTest::gtest_main bssl-compat)
target_link_options(utests-bssl-compat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/source/extra/digest_extra.ld)
target_link_options(utests-bssl-compat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/source/extra/cipher_extra.ld)
target_link_options(utests-bssl-compat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/source/extra/ssl_extra.ld)
target_link_options(utests-bssl-compat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/source/extra/x509_extra.ld)
gtest_discover_tests(utests-bssl-compat)

################################################################################
# Unit Tests built on BoringSSL
################################################################################
add_executable(utests-boring
  ${utests-source-list}
  ${utests-bssl-source-list}
  source/crypto/test/crypto_test_data.cc
)
add_dependencies(utests-boring BoringSSL)
target_link_libraries(utests-boring PRIVATE BoringSSL::SSL BoringSSL::Crypto)
target_link_libraries(utests-boring PRIVATE GTest::gtest_main)
gtest_discover_tests(utests-boring)
