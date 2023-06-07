#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L206
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_new.html
 */
extern "C" SSL_CTX *SSL_CTX_new(const SSL_METHOD *method) {
  return ossl.ossl_SSL_CTX_new(method);
}
