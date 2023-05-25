#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


int SSL_write(SSL *ssl, const void *buf, int num) {
  return ossl_SSL_write(ssl, buf, num);
}