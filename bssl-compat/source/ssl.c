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

#include "bssl_compat/openssl/ssl.h"

int SSL_do_handshake(SSL *ssl) {
	return openssl.SSL_do_handshake(ssl);
}

/* OpenSSL error codes identical to BoringSSL */
#define openssl_SSL_ERROR_NONE                  0
#define openssl_SSL_ERROR_SSL                   1
#define openssl_SSL_ERROR_WANT_READ             2
#define openssl_SSL_ERROR_WANT_WRITE            3
#define openssl_SSL_ERROR_WANT_X509_LOOKUP      4
#define openssl_SSL_ERROR_SYSCALL               5
#define openssl_SSL_ERROR_ZERO_RETURN           6
#define openssl_SSL_ERROR_WANT_CONNECT          7
#define openssl_SSL_ERROR_WANT_ACCEPT           8
/* OpenSSL error codes different from BoringSSL */
#define openssl_SSL_ERROR_WANT_ASYNC            9
#define openssl_SSL_ERROR_WANT_ASYNC_JOB       10
#define openssl_SSL_ERROR_WANT_CLIENT_HELLO_CB 11

int SSL_get_error(const SSL *ssl, int ret_code) {
	int r;

	r = openssl.SSL_get_error(ssl, ret_code);
	switch (r) {

	case openssl_SSL_ERROR_NONE:
	case openssl_SSL_ERROR_SSL:
	case openssl_SSL_ERROR_WANT_READ:
	case openssl_SSL_ERROR_WANT_WRITE:
	case openssl_SSL_ERROR_WANT_X509_LOOKUP:
	case openssl_SSL_ERROR_SYSCALL:
	case openssl_SSL_ERROR_ZERO_RETURN:
	case openssl_SSL_ERROR_WANT_CONNECT:
	case openssl_SSL_ERROR_WANT_ACCEPT:
		/* Identical error codes with BoringSSL */
		return r;

	case openssl_SSL_ERROR_WANT_ASYNC:
		return SSL_ERROR_WANT_ASYNC;

	case openssl_SSL_ERROR_WANT_ASYNC_JOB:
		return SSL_ERROR_WANT_ASYNC_JOB;

	case openssl_SSL_ERROR_WANT_CLIENT_HELLO_CB:
	default:
		/* not implemented */
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
#define openssl_SSL_MODE_ENABLE_PARTIAL_WRITE       0x00000001L
#define openssl_SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002L
#define openssl_SSL_MODE_AUTO_RETRY                 0x00000004L
#define openssl_SSL_MODE_NO_AUTO_CHAIN              0x00000008L
#define openssl_SSL_MODE_RELEASE_BUFFERS            0x00000010L
#define openssl_SSL_MODE_SEND_CLIENTHELLO_TIME      0x00000020L
#define openssl_SSL_MODE_SEND_SERVERHELLO_TIME      0x00000040L
#define openssl_SSL_MODE_SEND_FALLBACK_SCSV         0x00000080L
#define openssl_SSL_MODE_ASYNC                      0x00000100L
#define openssl_SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG 0x00000400L

#define SSL_CTRL_MODE                           33

uint32_t SSL_get_mode(const SSL *ssl) {
	uint32_t boringssl_mode = 0;
	long mode;

	mode = openssl.SSL_ctrl((SSL *)ssl, SSL_CTRL_MODE, 0, NULL);

	 if (mode & openssl_SSL_MODE_ENABLE_PARTIAL_WRITE)
		 boringssl_mode |= SSL_MODE_ENABLE_PARTIAL_WRITE;

	 if (mode & openssl_SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)
		 boringssl_mode |=SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;

	 if (mode & openssl_SSL_MODE_NO_AUTO_CHAIN)
		 boringssl_mode |=  SSL_MODE_NO_AUTO_CHAIN;

	 if (mode & openssl_SSL_MODE_SEND_FALLBACK_SCSV)
		 boringssl_mode |= SSL_MODE_SEND_FALLBACK_SCSV;

	 if (mode & openssl_SSL_MODE_ASYNC)
		 boringssl_mode |= SSL_MODE_ASYNC;

	 return boringssl_mode;
}

/* #define SSL_set_mode(ssl,op) SSL_ctrl((ssl),SSL_CTRL_MODE,(op),NULL) */
uint32_t SSL_set_mode(SSL *ssl, uint32_t mode) {
	uint32_t openssl_mode = 0;
	uint32_t boringssl_mode = 0;

	if (mode & SSL_MODE_ENABLE_PARTIAL_WRITE) {
		openssl_mode |= openssl_SSL_MODE_ENABLE_PARTIAL_WRITE;
		boringssl_mode |= SSL_MODE_ENABLE_PARTIAL_WRITE;
	}

	if (mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER) {
		openssl_mode |= openssl_SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
		boringssl_mode |= SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
	}

	if (mode & SSL_MODE_NO_AUTO_CHAIN) {
		openssl_mode |= openssl_SSL_MODE_NO_AUTO_CHAIN;
		boringssl_mode |= SSL_MODE_NO_AUTO_CHAIN;
	}

	if (mode & SSL_MODE_SEND_FALLBACK_SCSV) {
		openssl_mode |= openssl_SSL_MODE_SEND_FALLBACK_SCSV;
		boringssl_mode |= SSL_MODE_SEND_FALLBACK_SCSV;
	}

	if (mode & SSL_MODE_ASYNC) {
		openssl_mode |= openssl_SSL_MODE_ASYNC;
		boringssl_mode |= SSL_MODE_ASYNC;
	}

	openssl.SSL_ctrl(ssl, SSL_CTRL_MODE, openssl_mode, NULL);

	return boringssl_mode;
}

/* SSL_get_all_async_fds exists only in OpenSSL */
int SSL_get_all_async_fds(SSL *s, OSSL_ASYNC_FD *fds, size_t *numfds) {
	return openssl.SSL_get_all_async_fds(s, fds, numfds);
}
