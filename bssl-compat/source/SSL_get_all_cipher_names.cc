#include <openssl/ssl.h>
#include <ossl.h>
#include <string.h>
#define CANDIDATES_SIZE 1024 // there should not be more than 1024 ciphersuites
size_t SSL_get_all_cipher_names(const char **out, size_t max_out) {
  static uint8_t initialized = 0;
  static char validCiphers[CANDIDATES_SIZE][256];
  static size_t validCiphersSize = 0;
  if (initialized == 0) {
    ossl_SSL_CTX* ctx = ossl.ossl_SSL_CTX_new(ossl.ossl_TLS_client_method());
    if (!ctx) {
      return 0;
    }
    ossl_SSL* ssl = ossl.ossl_SSL_new(ctx);
    if (!ssl) {
      ossl.ossl_SSL_CTX_free(ctx);
      return 0;
    }
    STACK_OF(SSL_CIPHER)* cipherStack = SSL_get_ciphers(ssl);
    size_t sslCipherNum = sk_SSL_CIPHER_num(cipherStack);
    for (int i = 0; i < sslCipherNum && i < CANDIDATES_SIZE; ++i) {
        const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(cipherStack, i);
        if (cipher != NULL) {
            const char* cipherName = SSL_CIPHER_get_name(cipher);
            if (cipherName != NULL) {
                strcpy(validCiphers[validCiphersSize], cipherName);
                validCiphersSize++;
            }
        }
    }
    ossl.ossl_SSL_free(ssl);
    ossl.ossl_SSL_CTX_free(ctx);
    initialized = 1;
  }
  for(int i = 0; i < max_out && i < validCiphersSize; i++) {
    *out++ = validCiphers[i];
  }
  return validCiphersSize; // Return number of curves found, not written
}
