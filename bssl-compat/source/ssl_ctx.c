/*
 * Copyright (C) 2022 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ossl/openssl/ssl.h>
#include <openssl/ssl.h>
#include <openssl/mem.h>
#include <openssl/bytestring.h>
#include <ext/openssl/ssl.h>
#include "log.h"


STACK_OF(SSL_CIPHER) *SSL_CTX_get_ciphers(const SSL_CTX *ctx) {
  return (STACK_OF(SSL_CIPHER)*)ossl_SSL_CTX_get_ciphers(ctx);
}

X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx) {
  return ossl_SSL_CTX_get0_certificate(ctx);
}

static int ssl_ctx_client_hello_cb(SSL *ssl, int *alert, void *arg) {
  enum ssl_select_cert_result_t (*callback)(const SSL_CLIENT_HELLO *) = arg;

  SSL_CLIENT_HELLO client_hello;
  memset(&client_hello, 0, sizeof(client_hello));

  client_hello.ssl = ssl;
  client_hello.version = ossl_SSL_client_hello_get0_legacy_version(ssl);
  client_hello.random_len = ossl_SSL_client_hello_get0_random(ssl, &client_hello.random);
  client_hello.session_id_len = ossl_SSL_client_hello_get0_session_id(ssl, &client_hello.session_id);
  client_hello.cipher_suites_len = ossl_SSL_client_hello_get0_ciphers(ssl, &client_hello.cipher_suites);
  client_hello.compression_methods_len = ossl_SSL_client_hello_get0_compression_methods(ssl, &client_hello.compression_methods);

  int *extension_ids;
  size_t extension_ids_len;

  if (!ossl_SSL_client_hello_get1_extensions_present(ssl, &extension_ids, &extension_ids_len)) {
    *alert = SSL_AD_INTERNAL_ERROR;
    return ossl_SSL_CLIENT_HELLO_ERROR;
  }

  CBB extensions;
  CBB_init(&extensions, 1024);

  for (size_t i = 0; i < extension_ids_len; i++) {
    const unsigned char *extension_data;
    size_t extension_len;

    if (!ossl_SSL_client_hello_get0_ext(ssl, extension_ids[i], &extension_data, &extension_len) ||
        !CBB_add_u16(&extensions, extension_ids[i]) ||
        !CBB_add_u16(&extensions, extension_len) ||
        !CBB_add_bytes(&extensions, extension_data, extension_len)) {
      OPENSSL_free(extension_ids);
      CBB_cleanup(&extensions);
      *alert = SSL_AD_INTERNAL_ERROR;
      return ossl_SSL_CLIENT_HELLO_ERROR;
    }
  }

  OPENSSL_free(extension_ids);

  if (!CBB_finish(&extensions, (uint8_t**)&client_hello.extensions, &client_hello.extensions_len)) {
    CBB_cleanup(&extensions);
    *alert = SSL_AD_INTERNAL_ERROR;
    return ossl_SSL_CLIENT_HELLO_ERROR;
  }

  enum ssl_select_cert_result_t result = callback(&client_hello);

  OPENSSL_free((void*)client_hello.extensions);

  switch (result) {
    case ssl_select_cert_success: return ossl_SSL_CLIENT_HELLO_SUCCESS;
    case ssl_select_cert_retry:   return ossl_SSL_CLIENT_HELLO_RETRY;
    case ssl_select_cert_error:   return ossl_SSL_CLIENT_HELLO_ERROR;
  };
}

void SSL_CTX_set_select_certificate_cb(SSL_CTX *ctx, enum ssl_select_cert_result_t (*cb)(const SSL_CLIENT_HELLO *)) {
  ossl_SSL_CTX_set_client_hello_cb(ctx, ssl_ctx_client_hello_cb, cb);
}

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x509) {
  int ret = ossl_SSL_CTX_use_certificate(ctx, x509);
  return (ret == 1) ? 1 : 0;
}

int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str) {
  return ossl_SSL_CTX_set_cipher_list(ctx, str);
}

/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L2670
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_client_CA_list.html
 */
void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list) {
  ossl_SSL_CTX_set_client_CA_list(ctx, (ossl_STACK_OF(ossl_X509_NAME)*)name_list);
}

/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L661
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_get_max_proto_version.html
 */
int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, uint16_t version) {
  return ossl_SSL_CTX_set_min_proto_version(ctx, version);
}

/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L667
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_max_proto_version.html
 */
int SSL_CTX_set_max_proto_version(SSL_CTX *ctx, uint16_t version) {
  return ossl_SSL_CTX_set_max_proto_version(ctx, version);
}

/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L2404
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_verify.html
 */
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*callback)(int ok, X509_STORE_CTX *store_ctx)) {
  if (callback) {
    bssl_compat_fatal("%s() with non-null callback not implemented", __func__);
  }
  ossl_SSL_CTX_set_verify(ctx, mode, NULL);
}

/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L2639
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set1_sigalgs.html
 */
int SSL_CTX_set_verify_algorithm_prefs(SSL_CTX *ctx, const uint16_t *prefs, size_t num_prefs) {
  static const struct { // Copied from boringssl/ssl/ssl_privkey.cc
    int pkey_type;
    int hash_nid;
    uint16_t signature_algorithm;
  } kSignatureAlgorithmsMapping[] = {
      {EVP_PKEY_RSA, NID_sha1, SSL_SIGN_RSA_PKCS1_SHA1},
      {EVP_PKEY_RSA, NID_sha256, SSL_SIGN_RSA_PKCS1_SHA256},
      {EVP_PKEY_RSA, NID_sha384, SSL_SIGN_RSA_PKCS1_SHA384},
      {EVP_PKEY_RSA, NID_sha512, SSL_SIGN_RSA_PKCS1_SHA512},
      {EVP_PKEY_RSA_PSS, NID_sha256, SSL_SIGN_RSA_PSS_RSAE_SHA256},
      {EVP_PKEY_RSA_PSS, NID_sha384, SSL_SIGN_RSA_PSS_RSAE_SHA384},
      {EVP_PKEY_RSA_PSS, NID_sha512, SSL_SIGN_RSA_PSS_RSAE_SHA512},
      {EVP_PKEY_EC, NID_sha1, SSL_SIGN_ECDSA_SHA1},
      {EVP_PKEY_EC, NID_sha256, SSL_SIGN_ECDSA_SECP256R1_SHA256},
      {EVP_PKEY_EC, NID_sha384, SSL_SIGN_ECDSA_SECP384R1_SHA384},
      {EVP_PKEY_EC, NID_sha512, SSL_SIGN_ECDSA_SECP521R1_SHA512},
      {EVP_PKEY_ED25519, NID_undef, SSL_SIGN_ED25519},
  };
  static const int mmax = sizeof(kSignatureAlgorithmsMapping) /
                          sizeof(kSignatureAlgorithmsMapping[0]);

  int sigalgs[num_prefs * 2];

  for(size_t pi = 0; pi < num_prefs; pi++) {
    int mi;

    for(mi = 0; mi < mmax; mi++) {
      if(kSignatureAlgorithmsMapping[mi].signature_algorithm == prefs[pi]) {
        sigalgs[pi * 2] = kSignatureAlgorithmsMapping[mi].hash_nid;
        sigalgs[pi * 2 + 1] = kSignatureAlgorithmsMapping[mi].pkey_type;
        break;
      }
    }

    if(mi == mmax) {
      ossl_ERR_raise_data(ossl_ERR_LIB_SSL, ossl_ERR_R_INTERNAL_ERROR,
                        "unknown signature algorithm : %d", prefs[pi]);
      return 0;
    }
  }

  return ossl_SSL_CTX_set1_sigalgs(ctx, sigalgs, num_prefs * 2);
}

/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L198
 * https://www.openssl.org/docs/man3.0/man3/TLS_method.html
 */
const SSL_METHOD *TLS_with_buffers_method(void) {
  return ossl_TLS_method();
}

