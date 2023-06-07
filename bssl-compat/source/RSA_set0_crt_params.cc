#include <openssl/rsa.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/cd0b767492199a82c7e362d1a117e8c3fef6b943/include/openssl/rsa.h#L180
 * https://www.openssl.org/docs/man3.0/man3/RSA_set0_crt_params.html
 */
extern "C" int RSA_set0_crt_params(RSA *rsa, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp) {
  return ossl.ossl_RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
}
