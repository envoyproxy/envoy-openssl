#include <openssl/ssl.h>
#include <ossl.h>


extern "C" int SSL_read(SSL *ssl, void *buf, int num) {
  return ossl.ossl_SSL_read(ssl, buf, num);
}