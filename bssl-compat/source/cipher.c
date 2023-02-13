#include <openssl/cipher.h>
#include <ossl/openssl/evp.h>


const EVP_CIPHER *EVP_aes_256_cbc(void) {
  return ossl_EVP_aes_256_cbc();
}

unsigned EVP_CIPHER_iv_length(const EVP_CIPHER *cipher) {
  return ossl_EVP_CIPHER_iv_length(cipher);
}

unsigned EVP_CIPHER_key_length(const EVP_CIPHER *cipher) {
  return ossl_EVP_CIPHER_key_length(cipher);
}

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const uint8_t *key, const uint8_t *iv) {
  return ossl_EVP_DecryptInit_ex(ctx, cipher, impl, key, iv);
}

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const uint8_t *key, const uint8_t *iv) {
  return ossl_EVP_EncryptInit_ex(ctx, cipher, impl, key, iv);
}
