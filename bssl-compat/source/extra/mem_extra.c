#include <openssl/mem.h>
#include <ossl/openssl/crypto.h>

// OPENSSL_memdup returns an allocated, duplicate of |size| bytes from |data| or
// NULL on allocation failure.
void *OPENSSL_memdup(const void *data, size_t size) {
  return ossl_OPENSSL_memdup(data, size);
}

// OPENSSL_realloc returns a pointer to a buffer of |new_size| bytes that
// contains the contents of |ptr|. Unlike |realloc|, a new buffer is always
// allocated and the data at |ptr| is always wiped and freed.
void *OPENSSL_realloc(void *ptr, size_t new_size) {
  return ossl_OPENSSL_realloc(ptr, new_size);
}

// OPENSSL_strndup returns an allocated, duplicate of |str|, which is, at most,
// |size| bytes. The result is always NUL terminated.
char *OPENSSL_strndup(const char *str, size_t size) {
  return ossl_OPENSSL_strndup(str, size);
}
