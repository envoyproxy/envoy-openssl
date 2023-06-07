#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L212
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_free.html
 */
extern "C" void SSL_CTX_free(SSL_CTX *ctx) {
  ossl.ossl_SSL_CTX_free(ctx);
}
