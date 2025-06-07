#include <openssl/ssl.h>  
#include <ossl.h>  
  
extern "C" void SSL_CTX_enable_ntls(SSL_CTX *ctx) {  
  ossl.ossl_SSL_CTX_enable_ntls(ctx); 
}
