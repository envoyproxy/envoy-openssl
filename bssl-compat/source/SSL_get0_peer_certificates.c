#include <openssl/ssl.h>
#include <ossl.h>

STACK_OF(CRYPTO_BUFFER) *criptoBuffer;

const STACK_OF(CRYPTO_BUFFER) *SSL_get0_peer_certificates(const SSL *ssl) {
  STACK_OF(X509) *x509Temp = SSL_get_peer_cert_chain(ssl);
  if(x509Temp == NULL)
    return NULL;
  else
    return criptoBuffer;
}

