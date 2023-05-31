#include <openssl/ssl.h>
#include <ossl.h>


extern "C" void SSL_set_quiet_shutdown(SSL *ssl, int mode) {
  ossl_SSL_set_quiet_shutdown(ssl, mode);
}
