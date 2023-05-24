#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L1842
 * https://www.openssl.org/docs/man3.0/man3/SSL_SESSION_is_resumable.html
 */
int SSL_SESSION_is_resumable(const SSL_SESSION *session) {
  return ossl_SSL_SESSION_is_resumable(session);
}