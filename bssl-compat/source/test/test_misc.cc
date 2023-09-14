#include <gtest/gtest.h>
#include <openssl/asn1.h>


TEST(MiscTest, test_UniquePtr_ASN1_OBJECT) {
  bssl::UniquePtr<ASN1_OBJECT> p;
}
