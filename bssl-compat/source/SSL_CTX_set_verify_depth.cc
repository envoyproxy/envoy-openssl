#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L2481
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_verify_depth.html
 */
extern "C" void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth) {
  ossl.ossl_SSL_CTX_set_verify_depth(ctx, depth);
}
