#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L5011
 * https://www.openssl.org/docs/man3.0/man3/SSL_get1_session.html
 */
SSL_SESSION *SSL_get1_session(SSL *ssl) {
  return ossl_SSL_get1_session(ssl);
}