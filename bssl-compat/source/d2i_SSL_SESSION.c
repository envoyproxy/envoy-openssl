#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


/* 
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L4644
 * https://www.openssl.org/docs/man3.0/man3/d2i_SSL_SESSION.html
 */
SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const uint8_t **pp, long length) {
  return ossl_d2i_SSL_SESSION(a, pp, length);
}
