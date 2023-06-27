#include <openssl/err.h>
#include <ossl.h>


extern "C" char *ERR_error_string_n(uint32_t packed_error, char *buf, size_t len) {
  ossl.ossl_ERR_error_string_n(packed_error, buf, len);
  return buf;
}
