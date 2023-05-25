#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


extern "C" void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio) {
  ossl_SSL_set_bio(ssl, rbio, wbio);
}