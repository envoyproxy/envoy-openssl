#include <openssl/ssl.h>
#include <ossl.h>


extern "C" void SSL_SESSION_free(SSL_SESSION *session) {
  ossl.ossl_SSL_SESSION_free(session);
}