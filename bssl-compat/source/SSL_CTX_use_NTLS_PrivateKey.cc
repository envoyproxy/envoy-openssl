#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L867
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_use_PrivateKey.html
 */
extern "C" int SSL_CTX_use_NTLS_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey, int ntls_enabled) {
  if(ntls_enabled) {
    if(ossl.ossl_SSL_CTX_use_sign_PrivateKey(ctx, pkey) == 0)
    {
      return 0;
    }
    if(ossl.ossl_SSL_CTX_use_enc_PrivateKey(ctx, pkey) == 0)
    {
      return 0;
    }
    return 1;
  }
  else
  {
    return (ossl.ossl_SSL_CTX_use_PrivateKey(ctx, pkey) == 1) ? 1 : 0;
  }
}