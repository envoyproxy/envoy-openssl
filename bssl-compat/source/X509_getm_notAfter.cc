#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L315
 * https://www.openssl.org/docs/man3.0/man3/X509_getm_notAfter.html
 */
extern "C" ASN1_TIME *X509_getm_notAfter(X509 *x) {
  return ossl.ossl_X509_getm_notAfter(x);
}
