#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L1650
 * https://www.openssl.org/docs/man3.0/man3/SSL_session_reused.html
 */
extern "C" int SSL_session_reused(const SSL *ssl) {
  return ossl_SSL_session_reused(ssl);
}
