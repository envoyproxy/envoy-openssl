#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L2938
 * https://www.openssl.org/docs/man3.0/man3/X509_VERIFY_PARAM_set1.html
 */
extern "C" int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to, const X509_VERIFY_PARAM *from) {
  return ossl.ossl_X509_VERIFY_PARAM_set1(to, from);
}
