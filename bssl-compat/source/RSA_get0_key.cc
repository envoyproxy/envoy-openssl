#include <openssl/rsa.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/cd0b767492199a82c7e362d1a117e8c3fef6b943/include/openssl/rsa.h#L135
 * https://www.openssl.org/docs/man3.0/man3/RSA_get0_key.html
 */
extern "C" void RSA_get0_key(const RSA *rsa, const BIGNUM **out_n, const BIGNUM **out_e, const BIGNUM **out_d) {
  ossl.ossl_RSA_get0_key(rsa, out_n, out_e, out_d);
}
