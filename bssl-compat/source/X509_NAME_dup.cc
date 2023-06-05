#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L870
 * https://www.openssl.org/docs/man3.0/man3/X509_NAME_dup.html
 */
extern "C" X509_NAME *X509_NAME_dup(X509_NAME *name) {
  return ossl.ossl_X509_NAME_dup(name);
}
