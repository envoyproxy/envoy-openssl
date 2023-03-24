#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


const SSL_METHOD *TLS_server_method(void) {
  return ossl_TLS_server_method();
}

const SSL_METHOD *TLS_client_method(void) {
  return ossl_TLS_client_method();
}
