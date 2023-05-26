#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L2019
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_session_id_context.html
 */
extern "C" int SSL_CTX_set_session_id_context(SSL_CTX *ctx, const uint8_t *sid_ctx, size_t sid_ctx_len) {
  return ossl_SSL_CTX_set_session_id_context(ctx, sid_ctx, sid_ctx_len);
}
