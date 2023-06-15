#include <openssl/hmac.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/ec476ef0441f32fbcab558127412461617516336/include/openssl/hmac.h#L106
 * https://www.openssl.org/docs/man3.0/man3/HMAC_CTX_free.html
 */
extern "C" void HMAC_CTX_free(HMAC_CTX *ctx) {
  ossl.ossl_HMAC_CTX_free(ctx);
}
