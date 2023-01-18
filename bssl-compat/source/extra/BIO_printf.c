#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


// BIO_printf behaves like |printf| but outputs to |bio| rather than a |FILE|.
// It returns the number of bytes written or a negative number on error.
int BIO_printf(BIO *bio, const char *format, ...) {
  va_list args;
  va_start(args, format);
  int ret = ossl_BIO_vprintf(bio, format, args);
  va_end(args);
  return ret;
}
