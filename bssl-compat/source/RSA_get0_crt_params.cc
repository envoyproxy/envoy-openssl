#include <openssl/rsa.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/cd0b767492199a82c7e362d1a117e8c3fef6b943/include/openssl/rsa.h#L147
 * https://www.openssl.org/docs/man3.0/man3/RSA_get0_crt_params.html
 */
extern "C" void RSA_get0_crt_params(const RSA *rsa, const BIGNUM **out_dmp1, const BIGNUM **out_dmq1, const BIGNUM **out_iqmp) {
  ossl.ossl_RSA_get0_crt_params(rsa, out_dmp1, out_dmq1, out_iqmp);
}
