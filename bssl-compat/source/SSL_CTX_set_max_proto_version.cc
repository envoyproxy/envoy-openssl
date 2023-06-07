#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L667
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_max_proto_version.html
 */
extern "C" int SSL_CTX_set_max_proto_version(SSL_CTX *ctx, uint16_t version) {
  return ossl.ossl_SSL_CTX_set_max_proto_version(ctx, version);
}
