#include <openssl/mem.h>
#include <ossl/openssl/crypto.h>

// OPENSSL_free does nothing if |ptr| is NULL. Otherwise it zeros out the
// memory allocated at |ptr| and frees it.
void OPENSSL_free(void *ptr) {
  ossl_OPENSSL_free(ptr);
}
