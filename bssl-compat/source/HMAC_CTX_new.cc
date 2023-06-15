#include <openssl/hmac.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/ec476ef0441f32fbcab558127412461617516336/include/openssl/hmac.h#L96
 * https://www.openssl.org/docs/man3.0/man3/HMAC_CTX_new.html
 */
extern "C" HMAC_CTX *HMAC_CTX_new(void) {
  return ossl.ossl_HMAC_CTX_new();
}
