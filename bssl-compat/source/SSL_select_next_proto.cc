#include <openssl/ssl.h>
#include <ossl.h>


extern "C" int SSL_select_next_proto(uint8_t **out, uint8_t *out_len, const uint8_t *peer, unsigned peer_len, const uint8_t *supported, unsigned supported_len) {
  return ossl.ossl_SSL_select_next_proto(out, out_len, peer, peer_len, supported, supported_len);
}
