#include <gtest/gtest.h>
#include <openssl/err.h>
#include <limits>


TEST(MiscTest, test_ERR_func_error_string) {
  ASSERT_STREQ("OPENSSL_internal", ERR_func_error_string(0));
  ASSERT_STREQ("OPENSSL_internal", ERR_func_error_string(42));
}