#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L312
 * https://www.openssl.org/docs/man3.0/man3/X509_getm_notBefore.html
 */
extern "C" ASN1_TIME *X509_getm_notBefore(X509 *x509) {
  return ossl.ossl_X509_getm_notBefore(x509);
}
