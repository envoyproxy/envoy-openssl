#include <gtest/gtest.h>
#include <openssl/cipher.h>

TEST(CipherTest, cipher1) {
  uint8_t key[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
  uint8_t iv[] = "\x9c\x2d\x88\x42\xe5\xf4\x8f\x57\x64\x82\x05\xd3\x9a\x23\x9a\xf1";
  uint8_t plaintext1[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f0";
  int plainlen1 = sizeof(plaintext1);
  uint8_t plaintext2[256];
  int plainlen2;
  uint8_t ciphertext[1024];
  int cipherlen;
  int tmplen;


  const EVP_CIPHER *aes_256_cbc = EVP_aes_256_cbc();

  EXPECT_TRUE(aes_256_cbc);

  EXPECT_EQ(16, EVP_CIPHER_iv_length(aes_256_cbc));
  EXPECT_EQ(32, EVP_CIPHER_key_length(aes_256_cbc));

  {
    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());

    EXPECT_EQ(1, EVP_EncryptInit_ex(ctx.get(), aes_256_cbc, nullptr, key, iv));
    EXPECT_EQ(1, EVP_EncryptUpdate(ctx.get(), ciphertext, &cipherlen, plaintext1, plainlen1));
    EXPECT_EQ(1, EVP_EncryptFinal_ex(ctx.get(), ciphertext + cipherlen, &tmplen));
    cipherlen += tmplen;
  }

  {
    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());

    EXPECT_EQ(1, EVP_DecryptInit_ex(ctx.get(), aes_256_cbc, nullptr, key, iv));
    EXPECT_EQ(1, EVP_DecryptUpdate(ctx.get(), plaintext2, &plainlen2, ciphertext, cipherlen));
    EXPECT_EQ(1, EVP_DecryptFinal_ex(ctx.get(), plaintext2 + plainlen2, &tmplen));
    plainlen2 += tmplen;
  }

  EXPECT_EQ(plainlen1, plainlen2);
  for(auto i = 0; i < plainlen1; i++) {
    EXPECT_EQ(plaintext1[i], plaintext2[i]);
  }
}

