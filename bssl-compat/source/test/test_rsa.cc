#include <gtest/gtest.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>


TEST(RSATest, test_RSA_set0_factors) {
  bssl::UniquePtr<RSA> key {RSA_new()};
  ASSERT_EQ(1, RSA_set0_factors(key.get(), BN_new(), BN_new()));
}

TEST(RSATest, test_RSA_set0_key) {
  bssl::UniquePtr<RSA> key {RSA_new()};
  BIGNUM *n {BN_new()};
  BIGNUM *e {BN_new()};
  BIGNUM *d {BN_new()};
  ASSERT_EQ(1, RSA_set0_key(key.get(), n, e, d));
  const BIGNUM *n2 {};
  const BIGNUM *e2 {};
  const BIGNUM *d2 {};
  RSA_get0_key(key.get(), &n2, &e2, &d2);
  ASSERT_EQ(n2, n);
  ASSERT_EQ(e2, e);
  ASSERT_EQ(d2, d);
}