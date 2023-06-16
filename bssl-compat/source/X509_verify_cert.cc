#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L2324
 * https://www.openssl.org/docs/man3.0/man3/X509_verify_cert.html
 */
extern "C" int X509_verify_cert(X509_STORE_CTX *ctx) {
  return ossl.ossl_X509_verify_cert(ctx);
}
