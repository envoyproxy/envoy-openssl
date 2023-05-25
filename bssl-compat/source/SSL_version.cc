#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


extern "C" int SSL_version(const SSL *ssl) {
  return ossl_SSL_version(ssl);
}
