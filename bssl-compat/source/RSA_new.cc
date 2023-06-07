#include <openssl/rsa.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/cd0b767492199a82c7e362d1a117e8c3fef6b943/include/openssl/rsa.h#L83
 * https://www.openssl.org/docs/man3.0/man3/RSA_new.html
 */
extern "C" RSA *RSA_new() {
  return ossl.ossl_RSA_new();
}
