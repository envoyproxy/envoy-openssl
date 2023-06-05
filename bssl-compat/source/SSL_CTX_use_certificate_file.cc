#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L1194
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_use_certificate_file.html
 */
extern "C" int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type) {
  return ossl.ossl_SSL_CTX_use_certificate_file(ctx, file, type);
}
