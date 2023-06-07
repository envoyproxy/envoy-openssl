#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L2816
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_alpn_protos.html
 */
extern "C" int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const uint8_t *protos, unsigned protos_len) {
  return ossl.ossl_SSL_CTX_set_alpn_protos(ctx, protos, protos_len);
}
