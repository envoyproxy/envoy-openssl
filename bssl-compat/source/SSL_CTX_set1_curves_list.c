#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L2324
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set1_curves_list.html
 */
int SSL_CTX_set1_curves_list(SSL_CTX *ctx, const char *curves) {
  return ossl_SSL_CTX_set1_curves_list(ctx, curves);
}
