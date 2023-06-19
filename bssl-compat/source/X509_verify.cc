#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L1765
 * https://www.openssl.org/docs/man3.0/man3/X509_verify.html
 */
extern "C" int X509_verify(X509 *x509, EVP_PKEY *pkey) {
  return ossl.ossl_X509_verify(x509, pkey);
}
