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
#include <ossl/openssl/tls1.h>
#include <ossl/openssl/x509.h>
#include <ossl/openssl/safestack.h>
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
 * BoringSSL
 * =========
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L1586
 * 
 * SSL_get_peer_full_cert_chain returns the peer's certificate chain, or NULL
 * if unavailable or the peer did not use certificates. This is the unverified
 * list of certificates as sent by the peer, not the final chain built during
 * verification. The caller does not take ownership of the result.
 * 
 * This is the same as |SSL_get_peer_cert_chain| except that this function
 * always returns the full chain, i.e. the first element of the return value
 * (if any) will be the leaf certificate. In constrast,
 * |SSL_get_peer_cert_chain| returns only the intermediate certificates if the
 * |ssl| is a server.
 * 
 * OpenSSL
 * =======
 * 
 * SSL_get_peer_cert_chain() returns a pointer to STACK_OF(X509) certificates
 * forming the certificate chain sent by the peer. If called on the client side,
 * the stack also contains the peer's certificate; if called on the server side,
 * the peer's certificate must be obtained separately using
 * SSL_get_peer_certificate(3). If the peer did not present a certificate, NULL
 * is returned.
 * 
 * SSL_get0_peer_certificate() & SSL_get1_peer_certificate() return a pointer to
 * the X509 certificate the peer presented. If the peer did not present a
 * certificate, NULL is returned.
 * 
 * SSL_get1_peer_certificate() The reference count of the X509 object returned
 * is incremented by one, so that it will not be destroyed when the session
 * containing the peer certificate is freed. The X509 object must be explicitly
 * freed using X509_free().
 * 
 * SSL_get0_peer_certificate() The reference count of the X509 object returned
 * is not incremented, and must not be freed.
 */
STACK_OF(X509) *SSL_get_peer_full_cert_chain(const SSL *ssl) {
  // ossl_SSL_get_peer_cert_chain() doesn't return ownership of either the stack
  // object or the elements it contains, and no X509 ref counts are incremented.
  STACK_OF(X509)* tmp = (STACK_OF(X509)*)ossl_SSL_get_peer_cert_chain(ssl);

  // Make a shallow copy of the stack if it's not null
  STACK_OF(X509)* result = (tmp ? sk_X509_dup(tmp) : NULL);

  if (result && ossl_SSL_is_server(ssl)) {
    // The ssl object represents a server, so result does not contain the
    // client's leaf certificate. Therefore, we must get the client's leaf
    // certificate separately, and insert it into the result stack.
    // We use SSL_get0_peer_certificate() so that the ownership of the X509 is
    // not passed back to us, in order to match the ownership status of the
    // other X509 objects already in the result stack.
    X509* client_leaf_cert = ossl_SSL_get0_peer_certificate(ssl);

    if ((client_leaf_cert == NULL) || !sk_X509_insert(result, client_leaf_cert, 0)) {
      sk_X509_free(result);
      result = NULL;
    }
  }

  return result;
}

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

void SSL_set_renegotiate_mode(SSL *ssl, enum ssl_renegotiate_mode_t mode) {
  switch(mode) {
    case ssl_renegotiate_never: {
      ossl_SSL_clear_options(ssl,ossl_SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
      break;
    }
    case ssl_renegotiate_freely: {
      ossl_SSL_set_options(ssl,ossl_SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
      break;
    }
    case ssl_renegotiate_once: {
      bssl_compat_fatal("%s(ssl_renegotiate_once) NYI", __func__);
      break;
    }
    case ssl_renegotiate_ignore: {
      bssl_compat_fatal("%s(ssl_renegotiate_ignore) NYI", __func__);
      break;
    }
    case ssl_renegotiate_explicit: {
      bssl_compat_fatal("%s(ssl_renegotiate_explicit) NYI", __func__);
      break;
    }
  }
}

int SSL_set_ocsp_response(SSL *ssl, const uint8_t *response, size_t response_len) {
  // OpenSSL takes ownership of the response buffer so we have to take a copy
  void *copy = ossl_OPENSSL_memdup(response, response_len);
  if ((copy == NULL) && response) {
    return 0;
  }
  return ossl_SSL_set_tlsext_status_ocsp_resp(ssl, copy, response_len);
}

int SSL_SESSION_should_be_single_use(const SSL_SESSION *session) {
  return (ossl_SSL_SESSION_get_protocol_version(session) >= ossl_TLS1_3_VERSION);
}
