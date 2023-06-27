#include <openssl/err.h>
#include <ossl.h>


extern "C" const char *ERR_lib_error_string(uint32_t packed_error) {
  const char *ret = ossl.ossl_ERR_lib_error_string(packed_error);
  return (ret ? ret : "unknown library");
}
