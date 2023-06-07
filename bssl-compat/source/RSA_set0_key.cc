#include <openssl/rsa.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/cd0b767492199a82c7e362d1a117e8c3fef6b943/include/openssl/rsa.h#L160
 * https://www.openssl.org/docs/man3.0/man3/RSA_set0_key.html
 */
extern "C" int RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
  return ossl.ossl_RSA_set0_key(rsa, n, e, d);
}
