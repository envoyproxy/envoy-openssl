#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L455
 * https://www.openssl.org/docs/man3.0/man3/SSL_shutdown.html
 */
int SSL_shutdown(SSL *ssl) {
  return ossl.ossl_SSL_shutdown(ssl);
}
