#include <openssl/rsa.h>
#include <ossl.h>


/**
 * This implementats some mappings only where necessary to support Envoy
 */
extern "C" int RSA_padding_add_PKCS1_PSS_mgf1(const RSA *rsa, unsigned char *EM,
                                              const unsigned char *mHash,
                                              const EVP_MD *Hash, const EVP_MD *mgf1Hash,
                                              int sLenRequested) {
      return ossl.ossl_RSA_padding_add_PKCS1_PSS_mgf1((ossl_RSA *)rsa, EM, mHash, Hash, mgf1Hash, sLenRequested);
}
