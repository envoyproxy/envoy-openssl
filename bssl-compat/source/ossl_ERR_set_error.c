#include <ossl/openssl/err.h>
#include <ossl.h>

/*
 * This function doesn't get automatically generated into ossl.c by
 * the prefixer because it doesn't understand how to deal with the varargs.
 */
void ossl_ERR_set_error(int lib, int reason, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  ossl.ossl_ERR_vset_error(lib, reason, fmt, args);
  va_end(args);
}
