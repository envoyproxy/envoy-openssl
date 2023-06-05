#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L5004
 * https://www.openssl.org/docs/man3.0/man3/SSL_get_session.html
 */
extern "C" SSL_SESSION *SSL_get_session(const SSL *ssl) {
  return ossl.ossl_SSL_get_session(ssl);
}
