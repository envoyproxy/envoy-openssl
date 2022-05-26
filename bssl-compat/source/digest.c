#include "bssl_compat/bssl_compat.h"
#include "bssl_compat/openssl/digest.h"

EVP_MD_CTX* evp_md_ctx_init() { 
  return EVP_MD_CTX_new();
}

int evp_md_ctx_cleanup(EVP_MD_CTX* ctx) {
  EVP_MD_CTX_free(ctx); 
  return 1;
}
