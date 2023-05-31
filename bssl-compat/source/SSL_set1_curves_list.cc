#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#LL2330C45-L2330C45
 * https://www.openssl.org/docs/man3.0/man3/SSL_set1_cur  ves_list.html
 */
extern "C" int SSL_set1_curves_list(SSL *ssl, const char *curves) {
  return ossl.ossl_SSL_set1_curves_list(ssl, curves);
}