#include <openssl/ssl.h>
#include <ossl.h>


extern "C" void SSL_get0_alpn_selected(const SSL *ssl, const uint8_t **out_data, unsigned *out_len) {
  ossl.ossl_SSL_get0_alpn_selected(ssl, out_data, out_len);
}
