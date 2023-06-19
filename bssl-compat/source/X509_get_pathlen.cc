#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L1743
 * https://www.openssl.org/docs/man3.0/man3/X509_get_pathlen.html
 */
extern "C" long X509_get_pathlen(X509 *x509) {
  return ossl.ossl_X509_get_pathlen(x509);
}
