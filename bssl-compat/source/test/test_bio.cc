#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <queue>


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



static int test_meth_new_calls {0};
static int test_meth_new(BIO* bio) {
  test_meth_new_calls++;
  BIO_set_data(bio, new std::queue<char>());
  BIO_set_init(bio, 1);
  return 1;
}

static int test_meth_free_calls {0};
static int test_meth_free(BIO* bio) {
  test_meth_free_calls++;
  if (BIO_get_init(bio)) {
    delete reinterpret_cast<std::queue<char>*>(BIO_get_data(bio));
    BIO_set_data(bio, nullptr);
    BIO_set_init(bio, 0);
  }
  return 1;
}

static int test_meth_read_calls {0};
static int test_meth_read(BIO* b, char* out, int outl) {
  test_meth_read_calls++;
  std::queue<char> &queue {*reinterpret_cast<std::queue<char>*>(BIO_get_data(b))};

  int i = 0;
  while ((i < outl) && queue.size()) {
    out[i++] = queue.front();
    queue.pop();
  }

  return i;
}

static int test_meth_write_calls {0};
static int test_meth_write(BIO* b, const char* in, int inl) {
  test_meth_write_calls++;
  std::queue<char> &queue {*reinterpret_cast<std::queue<char>*>(BIO_get_data(b))};

  int i = 0;
  while (i < inl) {
    queue.push(in[i++]);
  }

  return i;
}

static BIO_METHOD test_meth {
  BIO_TYPE_SOCKET,
  "test_meth",
  test_meth_write,
  test_meth_read,
  nullptr /* puts */,
  nullptr /* gets, */,
  nullptr /* test_meth_ctrl */,
  test_meth_new,
  test_meth_free,
  nullptr /* callback_ctrl */,
};

TEST(BIOTest, test_custom_BIO_METHOD_1) {
  ASSERT_EQ(0, test_meth_new_calls);
  ASSERT_EQ(0, test_meth_free_calls);
  {
    bssl::UniquePtr<BIO> bio {BIO_new(&test_meth)};
    ASSERT_EQ(1, test_meth_new_calls);
    ASSERT_EQ(0, test_meth_free_calls);
  }
  ASSERT_EQ(1, test_meth_new_calls);
  ASSERT_EQ(1, test_meth_free_calls);
}

TEST(BIOTest, test_custom_BIO_METHOD_2) {
  bssl::UniquePtr<BIO> bio {BIO_new(&test_meth)};

  ASSERT_EQ(0, test_meth_write_calls);
  ASSERT_EQ(0, test_meth_read_calls);

  const char XYZ[] { 'X', 'Y', 'Z' };

  ASSERT_EQ(sizeof(XYZ), BIO_write(bio.get(), &XYZ, sizeof(XYZ)));
  ASSERT_EQ(1, test_meth_write_calls);

  char buffer[10];

  ASSERT_EQ(0, test_meth_read_calls);
  ASSERT_EQ(2, BIO_read(bio.get(), buffer, 2));
  ASSERT_EQ(1, test_meth_read_calls);
  ASSERT_EQ('X', buffer[0]);
  ASSERT_EQ('Y', buffer[1]);

  ASSERT_EQ(1, BIO_read(bio.get(), buffer, sizeof(buffer)));
  ASSERT_EQ(2, test_meth_read_calls);
  ASSERT_EQ('Z', buffer[0]);

  ASSERT_EQ(sizeof(XYZ), BIO_write(bio.get(), &XYZ, sizeof(XYZ)));
  ASSERT_EQ(2, test_meth_write_calls);
  ASSERT_EQ(sizeof(XYZ), BIO_write(bio.get(), &XYZ, sizeof(XYZ)));
  ASSERT_EQ(3, test_meth_write_calls);

  ASSERT_EQ(6, BIO_read(bio.get(), buffer, sizeof(buffer)));
  ASSERT_EQ(3, test_meth_read_calls);
  ASSERT_EQ('X', buffer[0]);
}


long test_meth_callback_ctrl(BIO*, int, bio_info_cb) {
  return 0;
}

TEST(BIOTest, test_BIO_METHOD_unsupported_callback_ctrl) {
#ifndef BSSL_COMPAT
  GTEST_SKIP(); // callback_ctrl *is* supported on BoringSSL so skip
#else
  static BIO_METHOD test_meth {
    BIO_TYPE_SOCKET,
    "testingtesting",
    test_meth_write,
    test_meth_read,
    nullptr /* puts */,
    nullptr /* gets, */,
    nullptr /* test_meth_ctrl */,
    test_meth_new,
    test_meth_free,
    test_meth_callback_ctrl
  };

  // The callback_ctrl function is not supported so we should hit an assert
  ASSERT_DEATH({BIO_new(&test_meth);}, "BIO_METHOD::callback_ctrl is not supported");
#endif
}