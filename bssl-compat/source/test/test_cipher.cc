#include <gtest/gtest.h>
#include <openssl/cipher.h>

TEST(CipherTest, cipher1) {
  uint8_t key[EVP_MAX_KEY_LENGTH] = {0};
  uint8_t iv[EVP_MAX_IV_LENGTH] = {1};

  uint8_t plaintext1[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
  int plainlen1 = sizeof(plaintext1);

  uint8_t plaintext2[sizeof(plaintext1)];
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

