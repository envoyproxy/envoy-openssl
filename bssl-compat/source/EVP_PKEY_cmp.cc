#include <openssl/evp.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/44872e1c74cbac6a0772dd588a7693bffbdade17/include/openssl/evp.h#L114
 * https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_cmp.html
 */
extern "C" int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
  return ossl.ossl_EVP_PKEY_cmp(a, b);
}
