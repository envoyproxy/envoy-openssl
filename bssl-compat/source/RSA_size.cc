#include <openssl/rsa.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/cd0b767492199a82c7e362d1a117e8c3fef6b943/include/openssl/rsa.h#L444
 * https://www.openssl.org/docs/man3.0/man3/RSA_size.html
 */
extern "C" unsigned RSA_size(const RSA *rsa) {
  return ossl.ossl_RSA_size(rsa);
}