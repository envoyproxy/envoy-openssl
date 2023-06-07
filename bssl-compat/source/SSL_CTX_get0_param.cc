#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L2509
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_get0_param.html
 */
extern "C" X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *ctx) {
  return ossl.ossl_SSL_CTX_get0_param(ctx);
}
