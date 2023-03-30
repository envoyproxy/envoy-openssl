#include <gtest/gtest.h>
#include <openssl/stack.h>
#include <openssl/mem.h>

using FOO = int;

static void FOO_free(FOO *x) { OPENSSL_free(x); }

BSSL_NAMESPACE_BEGIN
BORINGSSL_MAKE_DELETER(FOO, FOO_free)
BSSL_NAMESPACE_END

static bssl::UniquePtr<FOO> FOO_new(int x) {
  bssl::UniquePtr<FOO> ret(
      static_cast<FOO *>(OPENSSL_malloc(sizeof(FOO))));
  if (!ret) {
    return nullptr;
  }
  *ret = x;
  return ret;
}

DEFINE_STACK_OF(FOO)


TEST(StackTests, test1) {
  STACK_OF(FOO) *s = sk_FOO_new_null();
  ASSERT_TRUE(s);

  int num = sk_FOO_num(s);
  EXPECT_EQ(0, num);

  sk_FOO_free(s);
}

TEST(StackTests, test2) {
  {
    bssl::UniquePtr<STACK_OF(FOO)> s {sk_FOO_new_null()};
    ASSERT_TRUE(s.get());
  }

  {
    bssl::UniquePtr<STACK_OF(FOO)> s {sk_FOO_new_null()};
    ASSERT_TRUE(s.get());

    auto seven = FOO_new(7);
    sk_FOO_push(s.get(), seven.release());
  }
}
