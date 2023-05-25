#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


extern "C" const SSL_METHOD *DTLS_method(void) {
  return ossl_DTLS_method();
}