#include <openssl/ec_key.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/8bbefbfeee609b17622deedd100163c12f5c95dc/include/openssl/ec_key.h#L120
 * https://www.openssl.org/docs/man3.0/man3/EC_KEY_get0_group.html
 */
extern "C" const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key) {
  return ossl.ossl_EC_KEY_get0_group(key);
}
