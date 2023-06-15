#include <openssl/hmac.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/ec476ef0441f32fbcab558127412461617516336/include/openssl/hmac.h#L122
 * https://www.openssl.org/docs/man3.0/man3/HMAC_Update.html
 */
extern "C" int HMAC_Update(HMAC_CTX *ctx, const uint8_t *data, size_t data_len) {
  return ossl.ossl_HMAC_Update(ctx, data, data_len);
}
