#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


extern "C" void SSL_set_connect_state(SSL *ssl) {
  ossl_SSL_set_connect_state(ssl);
}
