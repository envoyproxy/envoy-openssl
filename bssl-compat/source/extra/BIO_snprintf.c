#include <openssl/mem.h>
#include <ossl/openssl/bio.h>


int BIO_snprintf(char *buf, size_t n, const char *format, ...) {
  va_list args;
  va_start(args, format);
  int ret = ossl_BIO_vsnprintf(buf, n, format, args);
  va_end(args);
  return ret;
}
