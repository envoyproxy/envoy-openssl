#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L126
 * https://www.openssl.org/docs/man3.0/man3/X509_up_ref.html
 */
extern "C" int X509_up_ref(X509 *x509) {
  return ossl.ossl_X509_up_ref(x509);
}
