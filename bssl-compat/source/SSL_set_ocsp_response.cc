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


extern "C" int SSL_set_ocsp_response(SSL *ssl, const uint8_t *response, size_t response_len) {
  // OpenSSL takes ownership of the response buffer so we have to take a copy
  void *copy = ossl.ossl_OPENSSL_memdup(response, response_len);
  if ((copy == NULL) && response) {
    return 0;
  }
  return ossl.ossl_SSL_set_tlsext_status_ocsp_resp(ssl, copy, response_len);
}
