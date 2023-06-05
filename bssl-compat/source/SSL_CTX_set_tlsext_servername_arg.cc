#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L2778
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_tlsext_servername_arg.html
 */
extern "C" int SSL_CTX_set_tlsext_servername_arg(SSL_CTX *ctx, void *arg) {
  return ossl.ossl_SSL_CTX_set_tlsext_servername_arg(ctx, arg);
}
