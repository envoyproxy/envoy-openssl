#include <openssl/ec_key.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/8bbefbfeee609b17622deedd100163c12f5c95dc/include/openssl/ec_key.h#L106
 * https://www.openssl.org/docs/man3.0/man3/EC_KEY_free.html
 */
extern "C" void EC_KEY_free(EC_KEY *key) {
  ossl.ossl_EC_KEY_free(key);
}
