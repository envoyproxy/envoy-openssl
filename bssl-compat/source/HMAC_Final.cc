#include <openssl/hmac.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/ec476ef0441f32fbcab558127412461617516336/include/openssl/hmac.h#L130
 * https://www.openssl.org/docs/man3.0/man3/HMAC_Final.html
 */
extern "C" int HMAC_Final(HMAC_CTX *ctx, uint8_t *out, unsigned int *out_len) {
  return ossl.ossl_HMAC_Final(ctx, out, out_len);
}
