#include <openssl/err.h>
#include <ossl/openssl/err.h>

// ERR_put_error adds an error to the error queue, dropping the least recent
// error if necessary for space reasons.
void ERR_put_error(int library, int unused, int reason, const char *file, unsigned line) {
  ossl_ERR_put_error(library, unused, reason, file, line);
}
