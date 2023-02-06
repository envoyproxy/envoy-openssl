#include <gtest/gtest.h>
#include <openssl/bn.h>
#include <openssl/mem.h>

TEST(BNTest, BN) {
  BN_free(nullptr);

  BIGNUM *b1 = BN_new();
  EXPECT_NE(b1, nullptr);

  EXPECT_EQ(BN_num_bits(b1), 0);

  EXPECT_EQ(BN_add_word(b1, 0x499602D2), 1);

  EXPECT_EQ(BN_num_bits(b1), 31);

  char *hex1 = BN_bn2hex(b1);
  EXPECT_NE(hex1, nullptr);
  EXPECT_STREQ(hex1, "499602D2");
  OPENSSL_free(hex1);

  BIGNUM *b2 = BN_dup(b1);
  EXPECT_NE(b2, nullptr);

  char *hex2 = BN_bn2hex(b2);
  EXPECT_NE(hex2, nullptr);
  EXPECT_STREQ(hex2, "499602D2");
  OPENSSL_free(hex2);

  EXPECT_EQ(BN_add_word(b2, 0x1), 1);

  hex2 = BN_bn2hex(b2);
  EXPECT_NE(hex2, nullptr);
  EXPECT_STREQ(hex2, "499602D3");
  OPENSSL_free(hex2);

  hex1 = BN_bn2hex(b1);
  EXPECT_NE(hex1, nullptr);
  EXPECT_STREQ(hex1, "499602D2");
  OPENSSL_free(hex1);

  EXPECT_TRUE(BN_ucmp(b1, b2) < 0);
  EXPECT_TRUE(BN_ucmp(b2, b1) > 0);

  BIGNUM *b3 = BN_dup(b2);
  EXPECT_TRUE(BN_ucmp(b2, b3) == 0);
  EXPECT_TRUE(BN_ucmp(b3, b2) == 0);
  BN_free(b3);

  BN_free(b1);
  BN_free(b2);
}
