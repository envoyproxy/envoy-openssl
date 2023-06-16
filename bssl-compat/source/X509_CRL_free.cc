#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L485
 * https://www.openssl.org/docs/man3.0/man3/X509_CRL_free.html
 */
extern "C" void X509_CRL_free(X509_CRL *crl) {
  ossl.ossl_X509_CRL_free(crl);
}
