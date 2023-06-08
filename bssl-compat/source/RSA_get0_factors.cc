#include <openssl/rsa.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/cd0b767492199a82c7e362d1a117e8c3fef6b943/include/openssl/rsa.h#L140
 * https://www.openssl.org/docs/man3.0/man3/RSA_get0_factors.html
 */
extern "C" void RSA_get0_factors(const RSA *rsa, const BIGNUM **out_p, const BIGNUM **out_q) {
  ossl.ossl_RSA_get0_factors(rsa, out_p, out_q);
}
