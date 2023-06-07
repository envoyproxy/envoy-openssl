#include <openssl/rsa.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/cd0b767492199a82c7e362d1a117e8c3fef6b943/include/openssl/rsa.h#L300
 * https://www.openssl.org/docs/man3.0/man3/RSA_sign.html
 */
extern "C" int RSA_sign(int hash_nid, const uint8_t *digest, unsigned digest_len, uint8_t *out, unsigned *out_len, RSA *rsa) {
  return ossl.ossl_RSA_sign(hash_nid, digest, digest_len, out, out_len, rsa);
}
