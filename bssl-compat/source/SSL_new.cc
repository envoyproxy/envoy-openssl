#include <openssl/ssl.h>
#include <ossl.h>


extern "C" SSL *SSL_new(SSL_CTX *ctx) {
  return ossl.ossl_SSL_new(ctx);
}