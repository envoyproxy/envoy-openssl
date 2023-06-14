#include <openssl/hmac.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/ec476ef0441f32fbcab558127412461617516336/include/openssl/hmac.h#L80
 * https://www.openssl.org/docs/man3.0/man3/HMAC.html
 */
extern "C" uint8_t *HMAC(const EVP_MD *evp_md, const void *key,
                         size_t key_len, const uint8_t *data,
                         size_t data_len, uint8_t *out,
                         unsigned int *out_len) {
  return ossl.ossl_HMAC(evp_md, key, key_len, data, data_len, out, out_len);
}
