#include <openssl/err.h>
#include <ossl/openssl/err.h>


uint32_t ERR_peek_error_line_data(const char **file, int *line, const char **data, int *flags) {
  return ossl_ERR_peek_error_line_data(file, line, data, flags);
}

