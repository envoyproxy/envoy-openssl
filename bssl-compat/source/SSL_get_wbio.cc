#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


extern "C" BIO *SSL_get_wbio(const SSL *ssl) {
  return ossl_SSL_get_wbio(ssl);
}