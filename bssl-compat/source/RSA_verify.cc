#include <openssl/rsa.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/cd0b767492199a82c7e362d1a117e8c3fef6b943/include/openssl/rsa.h#L363
 * https://www.openssl.org/docs/man3.0/man3/RSA_verify.html
 */
extern "C" int RSA_verify(int hash_nid, const uint8_t *digest, size_t digest_len, const uint8_t *sig, size_t sig_len, RSA *rsa) {
  return ossl.ossl_RSA_verify(hash_nid, digest, digest_len, sig, sig_len, rsa);
}
