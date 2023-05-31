#include <openssl/ssl.h>
#include <ossl.h>


extern "C" int SSL_set_ex_data(SSL *ssl, int idx, void *data) {
  return ossl.ossl_SSL_set_ex_data(ssl, idx, data);
}