#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L3881
 * https://www.openssl.org/docs/man3.0/man3/SSL_get_ex_data.html
 */
extern "C" void *SSL_get_ex_data(const SSL *ssl, int idx) {
  return ossl.ossl_SSL_get_ex_data(ssl, idx);
}