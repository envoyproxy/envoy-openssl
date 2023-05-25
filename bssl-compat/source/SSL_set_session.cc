#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


extern "C" int SSL_set_session(SSL *ssl, SSL_SESSION *session) {
  return ossl_SSL_set_session(ssl, session);
}