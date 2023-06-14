#include <openssl/hmac.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/ec476ef0441f32fbcab558127412461617516336/include/openssl/hmac.h#L117
 * https://www.openssl.org/docs/man3.0/man3/HMAC_Init_ex.html
 */
extern "C" int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, size_t key_len, const EVP_MD *md, ENGINE *impl) {
  return ossl.ossl_HMAC_Init_ex(ctx, key, key_len, md, impl);
}
