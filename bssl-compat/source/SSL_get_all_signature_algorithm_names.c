#include <openssl/ssl.h>
#include <ossl.h>

static const char* kSigAlgCandidates[] = {
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "ed25519",
    "ed448",
    "rsa_pss_pss_sha256",
    "rsa_pss_pss_sha384",
    "rsa_pss_pss_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
    "ecdsa_sha224",
    "ecdsa_sha256",
    "ecdsa_sha384",
    "ecdsa_sha512",
    "ecdsa_sha1",
    "rsa_pkcs1_sha224",
    "rsa_pkcs1_sha1",
    "dsa_sha224",
    "dsa_sha1",
    "dsa_sha256",
    "dsa_sha384",
    "dsa_sha512",
    "gostr34102012_256_intrinsic",
    "gostr34102012_512_intrinsic",
    "gostr34102012_256_gostr34112012_256",
    "gostr34102012_512_gostr34112012_512",
    "gostr34102001_gostr3411",
    "rsa_pkcs1_md5_sha1",
    "rsa_pkcs1_sha256_legacy"
};

#define CANDIDATES_SIZE 33

size_t SSL_get_all_signature_algorithm_names(const char **out, size_t max_out) {
  static uint8_t initialized = 0;
  static char* validSigAlgNames[CANDIDATES_SIZE];
  static size_t validSigAlgSize = 0;
  if (initialized == 0) {
    ossl_SSL_CTX* ctx = ossl.ossl_SSL_CTX_new(ossl.ossl_TLS_client_method());
    if (!ctx) {
      return 0;
    }
    ossl_SSL* ssl = ossl.ossl_SSL_new(ctx);
    if (!ssl) {
      ossl.ossl_SSL_CTX_free(ctx);
      return 0;
    }

    // Iterate through our hardcoded candidates and attempt to set each one.
    for (size_t i = 0; i < CANDIDATES_SIZE; ++i) {
      const char* candidate =	kSigAlgCandidates[i];

      if (ossl.ossl_SSL_set1_sigalgs_list(ssl, candidate)) {
        // Success: OpenSSL knows this signature_algorithm and can handle it.
        validSigAlgNames[validSigAlgSize] = candidate;
        validSigAlgSize++;
      }
    }

    ossl.ossl_SSL_free(ssl);
    ossl.ossl_SSL_CTX_free(ctx);
    initialized = 1;
  }
  for(int i = 0; i < max_out && i < validSigAlgSize; i++) {
    *out++ = validSigAlgNames[i];
  }
  return validSigAlgSize; // Return number of signature_algorithms found, not written
}


