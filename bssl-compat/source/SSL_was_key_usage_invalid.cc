#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" int SSL_was_key_usage_invalid(const SSL *ssl) {
  bssl_compat_fatal("SSL_was_key_usage_invalid() is not implemented");
  return 0;
}
