#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L472
 * https://www.openssl.org/docs/man3.0/man3/X509_CRL_up_ref.html
 */
extern "C" int X509_CRL_up_ref(X509_CRL *crl) {
  return ossl.ossl_X509_CRL_up_ref(crl);
}
