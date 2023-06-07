#include <openssl/rsa.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/cd0b767492199a82c7e362d1a117e8c3fef6b943/include/openssl/rsa.h#L170
 * https://www.openssl.org/docs/man3.0/man3/RSA_set0_factors.html
 */
extern "C" int RSA_set0_factors(RSA *rsa, BIGNUM *p, BIGNUM *q) {
  return ossl.ossl_RSA_set0_factors(rsa, p, q);
}
