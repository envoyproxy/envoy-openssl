#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L2768
 * https://www.openssl.org/docs/man3.0/man3/X509_STORE_free.html
 */
extern "C" void X509_STORE_free(X509_STORE *v) {
  ossl.ossl_X509_STORE_free(v);
}
