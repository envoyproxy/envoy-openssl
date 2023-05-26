#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L1964
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_session_cache_mode.html
 */
extern "C" int SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, int mode) {
  return ossl_SSL_CTX_set_session_cache_mode(ctx, mode);
}
