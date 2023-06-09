#include <openssl/bn.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/0ebd69bd1e0ae834e01935ad0c5cfac63a5aea32/include/openssl/bn.h#L221
 * https://www.openssl.org/docs/man3.0/man3/BN_set_word.html
 */
extern "C" int BN_set_word(BIGNUM *bn, BN_ULONG value) {
  return ossl.ossl_BN_set_word(bn, value);
}
