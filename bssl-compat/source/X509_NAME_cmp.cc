#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L2058
 * https://www.openssl.org/docs/man3.0/man3/X509_NAME_cmp.html
 */
extern "C" int X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b) {
  return ossl.ossl_X509_NAME_cmp(a, b);
}
