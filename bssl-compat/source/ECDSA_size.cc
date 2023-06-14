#include <openssl/ecdsa.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/cfafcd454fd01ebc40f1a7f43537dd306b7b64c3/include/openssl/ecdsa.h#L97
 * https://www.openssl.org/docs/man3.0/man3/ECDSA_size.html
 */
extern "C" size_t ECDSA_size(const EC_KEY *key) {
  return ossl.ossl_ECDSA_size(key);
}
