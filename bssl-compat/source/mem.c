#include <openssl/mem.h>
#include <ossl/openssl/crypto.h>

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/mem.h#L94-L99
 * OSSL: https://www.openssl.org/docs/man3.0/man3/CRYPTO_memcmp.html
 */
int CRYPTO_memcmp(const void *a, const void *b, size_t len) {
  return ossl_CRYPTO_memcmp(a, b, len);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/mem.h#L81-L83
 * OSSL: https://www.openssl.org/docs/man3.0/man3/OPENSSL_free.html
 */
void OPENSSL_free(void *ptr) {
  ossl_OPENSSL_free(ptr);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/mem.h#L78-L79
 * OSSL: https://www.openssl.org/docs/man3.0/man3/OPENSSL_malloc.html
 */
void *OPENSSL_malloc(size_t size) {
  return ossl_OPENSSL_malloc(size);
}
