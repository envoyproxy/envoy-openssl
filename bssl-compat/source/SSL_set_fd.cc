#include <openssl/ssl.h>
#include <ossl.h>


extern "C" int SSL_set_fd(SSL *ssl, int fd) {
  return ossl.ossl_SSL_set_fd(ssl, fd);
}