#include <gtest/gtest.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>


TEST(RSATest, test_RSA_set0_factors) {
  bssl::UniquePtr<RSA> key {RSA_new()};
  ASSERT_EQ(1, RSA_set0_factors(key.get(), BN_new(), BN_new()));
}

TEST(RSATest, test_RSA_set0_key) {
  bssl::UniquePtr<RSA> key {RSA_new()};
  ASSERT_EQ(1, RSA_set0_key(key.get(), BN_new(), BN_new(), BN_new()));
}