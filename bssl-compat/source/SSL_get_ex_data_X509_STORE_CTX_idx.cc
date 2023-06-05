#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L2570
 * https://www.openssl.org/docs/man3.0/man3/SSL_get_ex_data_X509_STORE_CTX_idx.html
 */
extern "C" int SSL_get_ex_data_X509_STORE_CTX_idx(void) {
  return ossl.ossl_SSL_get_ex_data_X509_STORE_CTX_idx();
}
