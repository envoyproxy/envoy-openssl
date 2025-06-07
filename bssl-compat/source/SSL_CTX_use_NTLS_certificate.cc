#include <openssl/ssl.h>
#include <ossl.h>


extern "C" int SSL_CTX_use_NTLS_certificate(SSL_CTX *ctx, X509 *x509, int ntls_enabled) {
    if(ntls_enabled) {
    if(0 == ossl.ossl_SSL_CTX_use_sign_certificate(ctx, x509))
    {
      return 0;
    }
    if(0 == ossl.ossl_SSL_CTX_use_enc_certificate(ctx, x509))
    {
      return 0;
    }
    return 1;
  }
  else
  {
    int ret = ossl.ossl_SSL_CTX_use_certificate(ctx, x509);
    return (ret == 1) ? 1 : 0;
  }
}