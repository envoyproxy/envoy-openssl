/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <stdio.h>
#include "bssl_compat/bssl_openssl.h"
#include "openssl/e_os2.h"

#ifndef OPENSSL_HEADER_SSL_H
#define OPENSSL_HEADER_SSL_H


#if defined(__cplusplus)
extern "C" {
#endif


// SSL implementation.


// SSL_do_handshake continues the current handshake. If there is none or the
// handshake has completed or False Started, it returns one. Otherwise, it
// returns <= 0. The caller should pass the value into |SSL_get_error| to
// determine how to proceed.
//
// In DTLS, the caller must drive retransmissions. Whenever |SSL_get_error|
// signals |SSL_ERROR_WANT_READ|, use |DTLSv1_get_timeout| to determine the
// current timeout. If it expires before the next retry, call
// |DTLSv1_handle_timeout|. Note that DTLS handshake retransmissions use fresh
// sequence numbers, so it is not sufficient to replay packets at the transport.
//
// TODO(davidben): Ensure 0 is only returned on transport EOF.
// https://crbug.com/466303.
OPENSSL_EXPORT int SSL_do_handshake(SSL *ssl);


// SSL_get_error returns a |SSL_ERROR_*| value for the most recent operation on
// |ssl|. It should be called after an operation failed to determine whether the
// error was fatal and, if not, when to retry.
OPENSSL_EXPORT int SSL_get_error(const SSL *ssl, int ret_code);

// SSL_ERROR_NONE indicates the operation succeeded.
#define SSL_ERROR_NONE 0

// SSL_ERROR_SSL indicates the operation failed within the library. The caller
// may inspect the error queue for more information.
#define SSL_ERROR_SSL 1

// SSL_ERROR_WANT_READ indicates the operation failed attempting to read from
// the transport. The caller may retry the operation when the transport is ready
// for reading.
//
// If signaled by a DTLS handshake, the caller must also call
// |DTLSv1_get_timeout| and |DTLSv1_handle_timeout| as appropriate. See
// |SSL_do_handshake|.
#define SSL_ERROR_WANT_READ 2

// SSL_ERROR_WANT_WRITE indicates the operation failed attempting to write to
// the transport. The caller may retry the operation when the transport is ready
// for writing.
#define SSL_ERROR_WANT_WRITE 3

// SSL_ERROR_WANT_X509_LOOKUP indicates the operation failed in calling the
// |cert_cb| or |client_cert_cb|. The caller may retry the operation when the
// callback is ready to return a certificate or one has been configured
// externally.
//
// See also |SSL_CTX_set_cert_cb| and |SSL_CTX_set_client_cert_cb|.
#define SSL_ERROR_WANT_X509_LOOKUP 4

// SSL_ERROR_SYSCALL indicates the operation failed externally to the library.
// The caller should consult the system-specific error mechanism. This is
// typically |errno| but may be something custom if using a custom |BIO|. It
// may also be signaled if the transport returned EOF, in which case the
// operation's return value will be zero.
#define SSL_ERROR_SYSCALL 5

// SSL_ERROR_ZERO_RETURN indicates the operation failed because the connection
// was cleanly shut down with a close_notify alert.
#define SSL_ERROR_ZERO_RETURN 6

// SSL_ERROR_WANT_CONNECT indicates the operation failed attempting to connect
// the transport (the |BIO| signaled |BIO_RR_CONNECT|). The caller may retry the
// operation when the transport is ready.
#define SSL_ERROR_WANT_CONNECT 7

// SSL_ERROR_WANT_ACCEPT indicates the operation failed attempting to accept a
// connection from the transport (the |BIO| signaled |BIO_RR_ACCEPT|). The
// caller may retry the operation when the transport is ready.
//
// TODO(davidben): Remove this. It's used by accept BIOs which are bizarre.
#define SSL_ERROR_WANT_ACCEPT 8

// SSL_ERROR_WANT_CHANNEL_ID_LOOKUP is never used.
//
// TODO(davidben): Remove this. Some callers reference it when stringifying
// errors. They should use |SSL_error_description| instead.
#define SSL_ERROR_WANT_CHANNEL_ID_LOOKUP 9

// SSL_ERROR_PENDING_SESSION indicates the operation failed because the session
// lookup callback indicated the session was unavailable. The caller may retry
// the operation when lookup has completed.
//
// See also |SSL_CTX_sess_set_get_cb| and |SSL_magic_pending_session_ptr|.
#define SSL_ERROR_PENDING_SESSION 11

// SSL_ERROR_PENDING_CERTIFICATE indicates the operation failed because the
// early callback indicated certificate lookup was incomplete. The caller may
// retry the operation when lookup has completed.
//
// See also |SSL_CTX_set_select_certificate_cb|.
#define SSL_ERROR_PENDING_CERTIFICATE 12

// SSL_ERROR_WANT_PRIVATE_KEY_OPERATION indicates the operation failed because
// a private key operation was unfinished. The caller may retry the operation
// when the private key operation is complete.
//
// See also |SSL_set_private_key_method| and
// |SSL_CTX_set_private_key_method|.
#define SSL_ERROR_WANT_PRIVATE_KEY_OPERATION 13

// SSL_ERROR_PENDING_TICKET indicates that a ticket decryption is pending. The
// caller may retry the operation when the decryption is ready.
//
// See also |SSL_CTX_set_ticket_aead_method|.
#define SSL_ERROR_PENDING_TICKET 14

// SSL_ERROR_EARLY_DATA_REJECTED indicates that early data was rejected. The
// caller should treat this as a connection failure and retry any operations
// associated with the rejected early data. |SSL_reset_early_data_reject| may be
// used to reuse the underlying connection for the retry.
#define SSL_ERROR_EARLY_DATA_REJECTED 15

// SSL_ERROR_WANT_CERTIFICATE_VERIFY indicates the operation failed because
// certificate verification was incomplete. The caller may retry the operation
// when certificate verification is complete.
//
// See also |SSL_CTX_set_custom_verify|.
#define SSL_ERROR_WANT_CERTIFICATE_VERIFY 16

#define SSL_ERROR_HANDOFF 17
#define SSL_ERROR_HANDBACK 18

// SSL_ERROR_WANT_RENEGOTIATE indicates the operation is pending a response to
// a renegotiation request from the server. The caller may call
// |SSL_renegotiate| to schedule a renegotiation and retry the operation.
//
// See also |ssl_renegotiate_explicit|.
#define SSL_ERROR_WANT_RENEGOTIATE 19

// SSL_ERROR_HANDSHAKE_HINTS_READY indicates the handshake has progressed enough
// for |SSL_serialize_handshake_hints| to be called. See also
// |SSL_request_handshake_hints|.
#define SSL_ERROR_HANDSHAKE_HINTS_READY 20


// Modes.
//
// Modes configure API behavior.

// SSL_MODE_ENABLE_PARTIAL_WRITE, in TLS, allows |SSL_write| to complete with a
// partial result when the only part of the input was written in a single
// record. In DTLS, it does nothing.
#define SSL_MODE_ENABLE_PARTIAL_WRITE 0x00000001L

// SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER, in TLS, allows retrying an incomplete
// |SSL_write| with a different buffer. However, |SSL_write| still assumes the
// buffer contents are unchanged. This is not the default to avoid the
// misconception that non-blocking |SSL_write| behaves like non-blocking
// |write|. In DTLS, it does nothing.
#define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002L

// SSL_MODE_NO_AUTO_CHAIN disables automatically building a certificate chain
// before sending certificates to the peer. This flag is set (and the feature
// disabled) by default.
// TODO(davidben): Remove this behavior. https://crbug.com/boringssl/42.
#define SSL_MODE_NO_AUTO_CHAIN 0x00000008L

// SSL_MODE_ENABLE_FALSE_START allows clients to send application data before
// receipt of ChangeCipherSpec and Finished. This mode enables full handshakes
// to 'complete' in one RTT. See RFC 7918.
//
// When False Start is enabled, |SSL_do_handshake| may succeed before the
// handshake has completely finished. |SSL_write| will function at this point,
// and |SSL_read| will transparently wait for the final handshake leg before
// returning application data. To determine if False Start occurred or when the
// handshake is completely finished, see |SSL_in_false_start|, |SSL_in_init|,
// and |SSL_CB_HANDSHAKE_DONE| from |SSL_CTX_set_info_callback|.
#define SSL_MODE_ENABLE_FALSE_START 0x00000080L

// SSL_MODE_CBC_RECORD_SPLITTING causes multi-byte CBC records in TLS 1.0 to be
// split in two: the first record will contain a single byte and the second will
// contain the remainder. This effectively randomises the IV and prevents BEAST
// attacks.
#define SSL_MODE_CBC_RECORD_SPLITTING 0x00000100L

// SSL_MODE_NO_SESSION_CREATION will cause any attempts to create a session to
// fail with SSL_R_SESSION_MAY_NOT_BE_CREATED. This can be used to enforce that
// session resumption is used for a given SSL*.
#define SSL_MODE_NO_SESSION_CREATION 0x00000200L

// SSL_MODE_SEND_FALLBACK_SCSV sends TLS_FALLBACK_SCSV in the ClientHello.
// To be set only by applications that reconnect with a downgraded protocol
// version; see RFC 7507 for details.
//
// DO NOT ENABLE THIS if your application attempts a normal handshake. Only use
// this in explicit fallback retries, following the guidance in RFC 7507.
#define SSL_MODE_SEND_FALLBACK_SCSV 0x00000400L


// SSL_set_mode enables all modes set in |mode| (which should be one or more of
// the |SSL_MODE_*| values, ORed together) in |ssl|. It returns a bitmask
// representing the resulting enabled modes.
OPENSSL_EXPORT uint32_t SSL_set_mode(SSL *ssl, uint32_t mode);


// SSL_CTX_get_mode returns a bitmask of |SSL_MODE_*| values that represent all
// the modes enabled for |ssl|.
OPENSSL_EXPORT uint32_t SSL_CTX_get_mode(const SSL_CTX *ctx);


/* SSL async mode, errors and functions not part of BoringSSL */
#define SSL_MODE_ASYNC 0x10000000L

#define SSL_ERROR_WANT_ASYNC           109
#define SSL_ERROR_WANT_ASYNC_JOB       110

#define OSSL_ASYNC_FD       int
#define OSSL_BAD_ASYNC_FD   -1

struct ssl_st {
	    uint32_t mode;
};

int SSL_get_all_async_fds(SSL *s, OSSL_ASYNC_FD *fds, size_t *numfds);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_SSL_H
