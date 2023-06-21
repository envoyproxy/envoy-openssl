#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L2769
 * https://www.openssl.org/docs/man3.0/man3/X509_STORE_CTX_set_default.html
 */
extern "C" int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name) {
  return ossl.ossl_X509_STORE_CTX_set_default(ctx, name);
}
