#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" void SSL_set_enforce_rsa_key_usage(SSL *ssl, int enabled) {
  bssl_compat_warn("SSL_set_enforce_rsa_key_usage() is not implemented");
}

