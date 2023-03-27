#include <openssl/err.h>
#include <ossl/openssl/err.h>


char *ERR_error_string(uint32_t packed_error, char *buf) {
  return ossl_ERR_error_string(packed_error, buf);
}

uint32_t ERR_peek_error(void) {
  return ossl_ERR_peek_error();
}

uint32_t ERR_peek_error_line_data(const char **file, int *line, const char **data, int *flags) {
  return ossl_ERR_peek_error_line_data(file, line, data, flags);
}

// ERR_print_errors_fp clears the current thread's error queue, printing each
// error to |file|. See |ERR_print_errors_cb| for the format.
void ERR_print_errors_fp(FILE *file) {
  ossl_ERR_print_errors_fp(file);
}
