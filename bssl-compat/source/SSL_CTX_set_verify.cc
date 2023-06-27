#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*callback)(int ok, X509_STORE_CTX *store_ctx)) {
  if (callback) {
    bssl_compat_fatal("%s() with non-null callback not implemented", __func__);
  }
  ossl.ossl_SSL_CTX_set_verify(ctx, mode, NULL);
}
