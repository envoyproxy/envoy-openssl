#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L2540
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_get_cert_store.html
 */
extern "C" X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx) {
  return ossl.ossl_SSL_CTX_get_cert_store(ctx);
}
