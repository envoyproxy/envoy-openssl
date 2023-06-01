#include <openssl/ssl.h>
#include <ossl.h>


extern "C" int SSL_set_alpn_protos(SSL *ssl, const uint8_t *protos, unsigned protos_len) {
  return ossl.ossl_SSL_set_alpn_protos(ssl, protos, protos_len);
}
