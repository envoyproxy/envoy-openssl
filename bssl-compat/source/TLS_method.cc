#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


const SSL_METHOD *TLS_method(void) {
  return ossl_TLS_method();
}
