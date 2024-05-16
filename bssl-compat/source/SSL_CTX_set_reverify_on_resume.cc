#include <openssl/ssl.h>
#include "log.h"


extern "C" void SSL_CTX_set_reverify_on_resume(SSL_CTX *ctx, int enabled) {
  bssl_compat_warn("SSL_CTX_set_reverify_on_resume() is not implemented");
}
