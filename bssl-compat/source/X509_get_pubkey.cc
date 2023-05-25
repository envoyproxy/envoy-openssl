#include <openssl/x509.h>
#include <ossl/openssl/x509.h>


extern "C" EVP_PKEY *X509_get_pubkey(X509 *x509) {
  return ossl_X509_get_pubkey(x509);
}