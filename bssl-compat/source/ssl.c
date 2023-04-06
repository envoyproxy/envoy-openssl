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

void SSL_enable_ocsp_stapling(SSL *ssl) {
  ossl_SSL_set_tlsext_status_type(ssl, ossl_TLSEXT_STATUSTYPE_ocsp);
}

const char *SSL_error_description(int err) {
  switch (err) {
#ifdef SSL_ERROR_NONE
    case SSL_ERROR_NONE: return "NONE";
#endif
#ifdef SSL_ERROR_SSL
    case SSL_ERROR_SSL: return "SSL";
#endif
#ifdef SSL_ERROR_WANT_READ
    case SSL_ERROR_WANT_READ: return "WANT_READ";
#endif
#ifdef SSL_ERROR_WANT_WRITE
    case SSL_ERROR_WANT_WRITE: return "WANT_WRITE";
#endif
#ifdef SSL_ERROR_WANT_X509_LOOKUP
    case SSL_ERROR_WANT_X509_LOOKUP: return "WANT_X509_LOOKUP";
#endif
#ifdef SSL_ERROR_SYSCALL
    case SSL_ERROR_SYSCALL: return "SYSCALL";
#endif
#ifdef SSL_ERROR_ZERO_RETURN
    case SSL_ERROR_ZERO_RETURN: return "ZERO_RETURN";
#endif
#ifdef SSL_ERROR_WANT_CONNECT
    case SSL_ERROR_WANT_CONNECT: return "WANT_CONNECT";
#endif
#ifdef SSL_ERROR_WANT_ACCEPT
    case SSL_ERROR_WANT_ACCEPT: return "WANT_ACCEPT";
#endif
#ifdef SSL_ERROR_PENDING_SESSION
    case SSL_ERROR_PENDING_SESSION: return "PENDING_SESSION";
#endif
#ifdef SSL_ERROR_PENDING_CERTIFICATE
    case SSL_ERROR_PENDING_CERTIFICATE: return "PENDING_CERTIFICATE";
#endif
#ifdef SSL_ERROR_WANT_PRIVATE_KEY_OPERATION
    case SSL_ERROR_WANT_PRIVATE_KEY_OPERATION: return "WANT_PRIVATE_KEY_OPERATION";
#endif
#ifdef SSL_ERROR_PENDING_TICKET
    case SSL_ERROR_PENDING_TICKET: return "PENDING_TICKET";
#endif
#ifdef SSL_ERROR_EARLY_DATA_REJECTED
    case SSL_ERROR_EARLY_DATA_REJECTED: return "EARLY_DATA_REJECTED";
#endif
#ifdef SSL_ERROR_WANT_CERTIFICATE_VERIFY
    case SSL_ERROR_WANT_CERTIFICATE_VERIFY: return "WANT_CERTIFICATE_VERIFY";
#endif
#ifdef SSL_ERROR_HANDOFF
    case SSL_ERROR_HANDOFF: return "HANDOFF";
#endif
#ifdef SSL_ERROR_HANDBACK
    case SSL_ERROR_HANDBACK: return "HANDBACK";
#endif
#ifdef SSL_ERROR_WANT_RENEGOTIATE
    case SSL_ERROR_WANT_RENEGOTIATE: return "WANT_RENEGOTIATE";
#endif
#ifdef SSL_ERROR_HANDSHAKE_HINTS_READY
    case SSL_ERROR_HANDSHAKE_HINTS_READY: return "HANDSHAKE_HINTS_READY";
#endif
    default:
      return NULL;
  }
}

X509 *SSL_get_certificate(const SSL *ssl) {
  return ossl_SSL_get_certificate(ssl);
}

int SSL_get_error(const SSL *ssl, int ret_code) {
	return ossl_SSL_get_error(ssl, ret_code);
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

SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx) {
  return ossl_SSL_set_SSL_CTX(ssl, ctx);
}