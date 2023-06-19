#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L328
 * https://www.openssl.org/docs/man3.0/man3/X509_set_pubkey.html
 */
extern "C" int X509_set_pubkey(X509 *x509, EVP_PKEY *pkey) {
  return ossl.ossl_X509_set_pubkey(x509, pkey);
}
