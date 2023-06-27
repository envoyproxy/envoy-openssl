#include <openssl/err.h>
#include <ossl/openssl/err.h>


extern "C" void ERR_put_error(int library, int unused, int reason, const char *file, unsigned line) {
  return ossl_ERR_put_error(library, unused, reason, file, line);
}
