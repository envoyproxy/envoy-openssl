#include <openssl/ec.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/c7a3c46574e7fc32357b2cc68f961c56c72b0ca4/include/openssl/ec.h#L134
 * https://www.openssl.org/docs/man3.0/man3/EC_GROUP_get0_order.html
 */
extern "C" const BIGNUM *EC_GROUP_get0_order(const EC_GROUP *group) {
  return ossl.ossl_EC_GROUP_get0_order(group);
}
