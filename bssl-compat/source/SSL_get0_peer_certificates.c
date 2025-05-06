#include <openssl/ssl.h>
#include <ossl.h>

const STACK_OF(CRYPTO_BUFFER) *SSL_get0_peer_certificates(const SSL *ssl) {
  return SSL_get_peer_cert_chain(ssl);
}

