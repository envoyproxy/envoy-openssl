#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


extern "C" STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *ssl) {
  return (STACK_OF(X509)*)ossl_SSL_get_peer_cert_chain(ssl);
}