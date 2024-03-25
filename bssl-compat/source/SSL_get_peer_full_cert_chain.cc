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
#include <ossl.h>


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
extern "C" STACK_OF(X509) *SSL_get_peer_full_cert_chain(const SSL *ssl) {
  // ossl_SSL_get_peer_cert_chain() doesn't return ownership of either the stack
  // object or the elements it contains, and no X509 ref counts are incremented.
  STACK_OF(X509)* tmp = (STACK_OF(X509)*)ossl.ossl_SSL_get_peer_cert_chain(ssl);

  // Make a shallow copy of the stack if it's not null
  STACK_OF(X509)* result = (tmp ? sk_X509_dup(tmp) : NULL);

  if (result && ossl.ossl_SSL_is_server(ssl)) {
    // The ssl object represents a server, so result does not contain the
    // client's leaf certificate. Therefore, we must get the client's leaf
    // certificate separately, and insert it into the result stack.
    // We use SSL_get0_peer_certificate() so that the ownership of the X509 is
    // not passed back to us, in order to match the ownership status of the
    // other X509 objects already in the result stack.
    X509* client_leaf_cert = ossl.ossl_SSL_get0_peer_certificate(ssl);

    if ((client_leaf_cert == NULL) || !sk_X509_insert(result, client_leaf_cert, 0)) {
      sk_X509_free(result);
      result = NULL;
    }
  }

  return result;
}
