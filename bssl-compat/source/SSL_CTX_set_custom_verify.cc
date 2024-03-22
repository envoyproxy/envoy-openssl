#include <openssl/ssl.h>
#include "log.h"


extern "C" void SSL_CTX_set_custom_verify(SSL_CTX *ctx, int mode,
          enum ssl_verify_result_t (*callback)(SSL *ssl, uint8_t *out_alert)) {
  bssl_compat_fatal("SSL_CTX_set_custom_verify() is not implemented");
}
