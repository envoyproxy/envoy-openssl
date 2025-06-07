#ifndef __EXT_OPENSSL_SSL_H__
#define __EXT_OPENSSL_SSL_H__

#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>

#define OSSL_ASYNC_FD ossl_OSSL_ASYNC_FD

OPENSSL_EXPORT int ext_SSL_get_all_async_fds(SSL *s, OSSL_ASYNC_FD *fds, size_t *numfds);

OPENSSL_EXPORT void SSL_CTX_enable_ntls(SSL_CTX *ctx);

OPENSSL_EXPORT int SSL_CTX_use_NTLS_certificate(SSL_CTX *ctx, X509 *x509, int ntls_enabled);

OPENSSL_EXPORT int SSL_CTX_use_NTLS_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey, int ntls_enabled);

#endif
