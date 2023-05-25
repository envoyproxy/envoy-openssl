#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


extern "C" X509 *SSL_get_peer_certificate(const SSL *ssl) {
  return ossl_SSL_get_peer_certificate(ssl);
}
