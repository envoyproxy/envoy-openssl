#include <openssl/md5.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/387b07b78dac785a341eeb2ff86e29393ffe8627/include/openssl/md5.h#L89
 * https://www.openssl.org/docs/man3.0/man3/MD5.html
 */
extern "C" uint8_t *MD5(const uint8_t *data, size_t len, uint8_t out[MD5_DIGEST_LENGTH]) {
  return ossl.ossl_MD5(data, len, out);
}
