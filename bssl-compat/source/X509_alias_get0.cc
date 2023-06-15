#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L437
 * https://www.openssl.org/docs/man3.0/man3/X509_alias_get0.html
 */
extern "C" unsigned char *X509_alias_get0(X509 *x509, int *out_len) {
  return ossl.ossl_X509_alias_get0(x509, out_len);
}
