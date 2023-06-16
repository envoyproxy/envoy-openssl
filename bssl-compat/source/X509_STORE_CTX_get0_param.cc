#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L2925
 * https://www.openssl.org/docs/man3.0/man3/X509_STORE_CTX_get0_param.html
 */
extern "C" X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx) {
  return ossl.ossl_X509_STORE_CTX_get0_param(ctx);
}
