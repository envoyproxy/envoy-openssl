#include <openssl/rsa.h>
#include <ossl/openssl/rsa.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/rsa.h#L90
 */
void RSA_free(RSA *rsa) {
  ossl_RSA_free(rsa);
}
