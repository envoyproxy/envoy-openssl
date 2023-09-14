#include <gtest/gtest.h>
#include <openssl/asn1.h>
#include <openssl/ec_key.h>


TEST(MiscTest, test_UniquePtr_ASN1_OBJECT) {
  bssl::UniquePtr<ASN1_OBJECT> p;
}

TEST(MiscTest, test_UniquePtr_EC_KEY) {
  bssl::UniquePtr<EC_KEY> p;
}
