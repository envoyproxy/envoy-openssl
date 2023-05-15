#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


int SSL_set_tlsext_host_name(SSL *ssl, const char *name) {
  return ossl_SSL_set_tlsext_host_name(ssl, name);
}