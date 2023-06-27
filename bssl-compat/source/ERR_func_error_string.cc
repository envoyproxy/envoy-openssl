#include <openssl/err.h>


extern "C" const char *ERR_func_error_string(uint32_t packed_error) {
  return "OPENSSL_internal";
}
