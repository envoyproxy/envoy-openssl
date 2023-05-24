#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L1745
 * https://www.openssl.org/docs/man3.0/man3/SSL_SESSION_get_id.html
 */
const uint8_t *SSL_SESSION_get_id(const SSL_SESSION *session, unsigned *out_len) {
  return ossl_SSL_SESSION_get_id(session, out_len);
}