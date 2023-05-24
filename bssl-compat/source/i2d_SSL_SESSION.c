#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L4638
 * https://www.openssl.org/docs/man3.0/man3/i2d_SSL_SESSION.html
 */
int i2d_SSL_SESSION(SSL_SESSION *in, uint8_t **pp) {
  return ossl_i2d_SSL_SESSION(in, pp);
}
