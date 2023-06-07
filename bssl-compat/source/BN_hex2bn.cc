#include <openssl/bn.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/0ebd69bd1e0ae834e01935ad0c5cfac63a5aea32/include/openssl/bn.h#L280
 * https://www.openssl.org/docs/man3.0/man3/BN_hex2bn.html
 */
extern "C" int BN_hex2bn(BIGNUM **outp, const char *in) {
  return ossl.ossl_BN_hex2bn(outp, in);
}
