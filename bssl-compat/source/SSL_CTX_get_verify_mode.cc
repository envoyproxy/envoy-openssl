#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L2453
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_get_verify_mode.html
 */
extern "C" int SSL_CTX_get_verify_mode(const SSL_CTX *ctx) {
  return ossl.ossl_SSL_CTX_get_verify_mode(ctx);
}
