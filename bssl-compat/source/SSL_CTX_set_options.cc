#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L729
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_options.html
 */
extern "C" uint32_t SSL_CTX_set_options(SSL_CTX *ctx, uint32_t options) {
  return ossl.ossl_SSL_CTX_set_options(ctx, options);
}
