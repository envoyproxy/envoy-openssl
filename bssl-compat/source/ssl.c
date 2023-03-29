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

#include <openssl/ssl.h>
#include <ext/openssl/ssl.h>
#include <ossl/openssl/ssl.h>
#include "log.h"


int SSL_do_handshake(SSL *ssl) {
	return ossl_SSL_do_handshake(ssl);
}

int SSL_get_error(const SSL *ssl, int ret_code) {
	int r;

	r = ossl_SSL_get_error(ssl, ret_code);
	switch (r) {

  case ossl_SSL_ERROR_NONE:
	case ossl_SSL_ERROR_SSL:
	case ossl_SSL_ERROR_WANT_READ:
	case ossl_SSL_ERROR_WANT_WRITE:
	case ossl_SSL_ERROR_WANT_X509_LOOKUP:
	case ossl_SSL_ERROR_SYSCALL:
	case ossl_SSL_ERROR_ZERO_RETURN:
	case ossl_SSL_ERROR_WANT_CONNECT:
	case ossl_SSL_ERROR_WANT_ACCEPT:
		/* Identical error codes with BoringSSL */
		return r;

	case ossl_SSL_ERROR_WANT_ASYNC:
	case ossl_SSL_ERROR_WANT_ASYNC_JOB:
	case ossl_SSL_ERROR_WANT_CLIENT_HELLO_CB:
	  bssl_compat_fatal("OpenSSL error code %d has no BoringSSL equivalent", r);
	  break;

	default:
	  bssl_compat_fatal("Unknown OpenSSL error code %d", r);
		break;
	}

	return SSL_ERROR_SSL;
}

 /*
  * Not supported 1:1 by BoringSSL:
  * openssl_SSL_MODE_AUTO_RETRY
  * openssl_SSL_MODE_RELEASE_BUFFERS
  * openssl_SSL_MODE_SEND_CLIENTHELLO_TIME
  * openssl_SSL_MODE_SEND_SERVERHELLO_TIME
  * openssl_SSL_MODE_ASYNC
  * openssl_SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG
  *
  * Not supported 1:1 by OpenSSL:
  * SSL_MODE_ENABLE_FALSE_START
  * SSL_MODE_CBC_RECORD_SPLITTING
  * SSL_MODE_NO_SESSION_CREATION
  * SSL_MODE_HANDSHAKE_CUTTHROUGH
 */

uint32_t SSL_get_mode(const SSL *ssl) {
  uint32_t boringssl_mode = 0;
  long ossl_mode;

  ossl_mode = ossl_SSL_ctrl((SSL*)(ssl), ossl_SSL_CTRL_MODE, 0, NULL);

  if (ossl_mode & ossl_SSL_MODE_ENABLE_PARTIAL_WRITE)
    boringssl_mode |= SSL_MODE_ENABLE_PARTIAL_WRITE;

  if (ossl_mode & ossl_SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)
    boringssl_mode |=SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;

  if (ossl_mode & ossl_SSL_MODE_NO_AUTO_CHAIN)
    boringssl_mode |=  SSL_MODE_NO_AUTO_CHAIN;

  if (ossl_mode & ossl_SSL_MODE_SEND_FALLBACK_SCSV)
    boringssl_mode |= SSL_MODE_SEND_FALLBACK_SCSV;

  /* The following flags are in OpenSSL but not in BoringSSL */
  if (ossl_mode & ossl_SSL_MODE_ASYNC)
    bssl_compat_fatal("SSL_MODE_ASYNC has no BoringSSL equivalent");
  if (ossl_mode & ossl_SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG)
    bssl_compat_fatal("SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG has no BoringSSL equivalent");
  if (ossl_mode & ossl_SSL_MODE_AUTO_RETRY)
    bssl_compat_fatal("SSL_MODE_AUTO_RETRY has no BoringSSL equivalent");
  if (ossl_mode & ossl_SSL_MODE_RELEASE_BUFFERS)
    bssl_compat_fatal("SSL_MODE_RELEASE_BUFFERS has no BoringSSL equivalent");
  if (ossl_mode & ossl_SSL_MODE_SEND_CLIENTHELLO_TIME)
    bssl_compat_fatal("SSL_MODE_SEND_CLIENTHELLO_TIME has no BoringSSL equivalent");
  if (ossl_mode & ossl_SSL_MODE_SEND_SERVERHELLO_TIME)
    bssl_compat_fatal("SSL_MODE_SEND_SERVERHELLO_TIME has no BoringSSL equivalent");

	 return boringssl_mode;
}

/* #define SSL_set_mode(ssl,op) SSL_ctrl((ssl),SSL_CTRL_MODE,(op),NULL) */
uint32_t SSL_set_mode(SSL *ssl, uint32_t mode) {
	uint32_t openssl_mode = 0;
	uint32_t boringssl_mode = SSL_get_mode(ssl);

	if (mode & SSL_MODE_ENABLE_PARTIAL_WRITE) {
		openssl_mode |= ossl_SSL_MODE_ENABLE_PARTIAL_WRITE;
		boringssl_mode |= SSL_MODE_ENABLE_PARTIAL_WRITE;
	}

	if (mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER) {
		openssl_mode |= ossl_SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
		boringssl_mode |= SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
	}

	if (mode & SSL_MODE_NO_AUTO_CHAIN) {
		openssl_mode |= ossl_SSL_MODE_NO_AUTO_CHAIN;
		boringssl_mode |= SSL_MODE_NO_AUTO_CHAIN;
	}

	if (mode & SSL_MODE_SEND_FALLBACK_SCSV) {
		openssl_mode |= ossl_SSL_MODE_SEND_FALLBACK_SCSV;
		boringssl_mode |= SSL_MODE_SEND_FALLBACK_SCSV;
	}

  if(mode & SSL_MODE_ENABLE_FALSE_START)
    bssl_compat_fatal("SSL_MODE_ENABLE_FALSE_START (or SSL_MODE_HANDSHAKE_CUTTHROUGH) is not supported by OpenSSL");
  if(mode & SSL_MODE_CBC_RECORD_SPLITTING)
    bssl_compat_fatal("SSL_MODE_CBC_RECORD_SPLITTING is not supported by OpenSSL");
  if(mode & SSL_MODE_NO_SESSION_CREATION)
    bssl_compat_fatal("SSL_MODE_NO_SESSION_CREATION is not supported by OpenSSL");

	ossl_SSL_ctrl(ssl, ossl_SSL_CTRL_MODE, openssl_mode, NULL);

	return boringssl_mode;
}

/*
 *
 */
static int SSL_CTX_client_hello_cb(SSL *ssl, int *alert, void *arg) {
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
  ossl_SSL_CTX_set_client_hello_cb(ctx, SSL_CTX_client_hello_cb, cb);
}

/*
 * BoringSSL only returns: TLS1_3_VERSION, TLS1_2_VERSION, or SSL3_VERSION
 */
uint16_t SSL_CIPHER_get_min_version(const SSL_CIPHER *cipher) {
  // This logic was copied from BoringSSL's ssl_cipher.cc

  if ((ossl_SSL_CIPHER_get_kx_nid(cipher) == ossl_NID_kx_any) ||
      (ossl_SSL_CIPHER_get_auth_nid(cipher) == ossl_NID_auth_any)) {
    return TLS1_3_VERSION;
  }

  const EVP_MD *digest = ossl_SSL_CIPHER_get_handshake_digest(cipher);
  if (ossl_EVP_MD_get_type(digest) != NID_md5_sha1) {
    return TLS1_2_VERSION;
  }

  return SSL3_VERSION;
}

const char *SSL_CIPHER_get_name(const SSL_CIPHER *cipher) {
  return ossl_SSL_CIPHER_get_name(cipher);
}

int ext_SSL_get_all_async_fds(SSL *s, OSSL_ASYNC_FD *fds, size_t *numfds) {
  return ossl_SSL_get_all_async_fds(s, fds, numfds);
}
