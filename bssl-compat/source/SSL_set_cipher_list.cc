#include <openssl/ssl.h>
#include <ossl.h>


extern "C" int SSL_set_cipher_list(SSL *ssl, const char *str) {
  return ossl.ossl_SSL_set_cipher_list(ssl, str);
}
