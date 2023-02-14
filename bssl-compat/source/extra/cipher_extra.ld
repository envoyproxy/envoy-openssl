PROVIDE(EVP_CIPHER_CTX_new = ossl_EVP_CIPHER_CTX_new);
PROVIDE(EVP_CIPHER_CTX_free = ossl_EVP_CIPHER_CTX_free);
PROVIDE(EVP_CIPHER_CTX_set_padding = ossl_EVP_CIPHER_CTX_set_padding);
PROVIDE(EVP_EncryptFinal_ex = ossl_EVP_EncryptFinal_ex);
PROVIDE(EVP_EncryptUpdate = ossl_EVP_EncryptUpdate);
PROVIDE(EVP_DecryptUpdate = ossl_EVP_DecryptUpdate);
PROVIDE(EVP_DecryptFinal_ex = ossl_EVP_DecryptFinal_ex);
