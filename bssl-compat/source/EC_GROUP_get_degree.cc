#include <openssl/ec.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/c7a3c46574e7fc32357b2cc68f961c56c72b0ca4/include/openssl/ec.h#L158
 * https://www.openssl.org/docs/man3.0/man3/EC_GROUP_get_degree.html
 */
extern "C" unsigned EC_GROUP_get_degree(const EC_GROUP *group) {
  return ossl.ossl_EC_GROUP_get_degree(group);
}
