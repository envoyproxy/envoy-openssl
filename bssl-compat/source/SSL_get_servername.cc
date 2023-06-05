#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L2756
 * https://www.openssl.org/docs/man3.0/man3/SSL_get_servername.html
 */
extern "C" const char *SSL_get_servername(const SSL *ssl, const int type) {
  return ossl.ossl_SSL_get_servername(ssl, type);
}
