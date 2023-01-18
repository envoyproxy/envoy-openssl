#include <openssl/mem.h>
#include <ossl/openssl/crypto.h>


// OPENSSL_malloc acts like a regular |malloc|.
void *OPENSSL_malloc(size_t size) {
  return ossl_OPENSSL_malloc(size);
}
