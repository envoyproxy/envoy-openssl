#include <gtest/gtest.h>
#include <openssl/bio.h>


TEST(BIOTest, test_BIO_get_mem_ptr) {
  bssl::UniquePtr<BIO> mem {BIO_new(BIO_s_mem())};
  ASSERT_TRUE(mem);

  ASSERT_EQ(3, BIO_puts(mem.get(), "XYZ"));

  BUF_MEM *bptr;
  ASSERT_EQ(1, BIO_get_mem_ptr(mem.get(), &bptr));
  ASSERT_NE(nullptr, bptr);

  ASSERT_EQ(3, bptr->length);
  ASSERT_EQ('X', bptr->data[0]);
  ASSERT_EQ('Y', bptr->data[1]);
  ASSERT_EQ('Z', bptr->data[2]);
}