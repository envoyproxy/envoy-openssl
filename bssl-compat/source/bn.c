#include "bssl_compat/bssl_compat.h"

int BN_cmp_word(const BIGNUM *a, BN_ULONG b) {
  BIGNUM* b_bn = BN_new();

  BN_set_word(b_bn, b);

  int result = BN_cmp(a, b_bn);

  BN_free(b_bn);

  return result;
}
