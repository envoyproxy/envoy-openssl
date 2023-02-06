#include <openssl/evp.h>
#include <ossl/openssl/evp.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <ossl/openssl/x509.h>
#include "log.h"


/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L376-L380
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_DigestVerify.html
 */
int EVP_DigestVerify(EVP_MD_CTX *ctx, const uint8_t *sig, size_t sig_len, const uint8_t *data, size_t len) {
  return ossl_EVP_DigestVerify(ctx, sig, sig_len, data, len);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L339-L355
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_DigestVerifyInit.html
 */
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey) {
  return ossl_EVP_DigestVerifyInit(ctx, pctx, type, e, pkey);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L203-L211
 * OSSL: N/A
 */
EVP_PKEY *EVP_parse_public_key(CBS *cbs) {
  const unsigned char* tmp = cbs->data;
  return ossl_d2i_PUBKEY_ex(NULL, &tmp, cbs->len, NULL, NULL);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L170
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_assign_EC_KEY.html
 */
int EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *key) {
  return ossl_EVP_PKEY_assign_EC_KEY(pkey, key); // TODO(tpoole) ossl_EVP_PKEY_assign_EC_KEY is deprecated
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L160
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_assign_RSA.html
 */
int EVP_PKEY_assign_RSA(EVP_PKEY *pkey, RSA *key) {
  return ossl_EVP_PKEY_assign_RSA(pkey, key); // TODO(tpoole) ossl_EVP_PKEY_assign_RSA is deprecated
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L95-L97
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_free.html
 *
 * The BoringSSL documentation says nothing about decrementing the ref count, and deleting when zero (as the OpenSSL docs do)
 * However, looking at the BoringSSL implementation shows that it does exactly that.
 */
void EVP_PKEY_free(EVP_PKEY *pkey) {
  ossl_EVP_PKEY_free(pkey);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L171
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_get0_EC_KEY.html
 */
EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey) {
  return (EC_KEY*)ossl_EVP_PKEY_get0_EC_KEY(pkey);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L161
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_get0_RSA.html
 */
RSA *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey) {
  return (RSA*)ossl_EVP_PKEY_get0_RSA(pkey);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L172
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_get1_EC_KEY.html
 */
EC_KEY *EVP_PKEY_get1_EC_KEY(const EVP_PKEY *pkey) {
  return ossl_EVP_PKEY_get1_EC_KEY((EVP_PKEY*)pkey);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L162
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_get1_RSA.html
 */
RSA *EVP_PKEY_get1_RSA(const EVP_PKEY *pkey) {
  return ossl_EVP_PKEY_get1_RSA((EVP_PKEY*)pkey);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L135-L137
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_id.html
 */
int EVP_PKEY_id(const EVP_PKEY *pkey) {
  int ossl = ossl_EVP_PKEY_base_id(pkey);
  switch(ossl) {
    case ossl_EVP_PKEY_DSA: return EVP_PKEY_DSA;
    case ossl_EVP_PKEY_EC: return EVP_PKEY_EC;
    case ossl_EVP_PKEY_ED25519: return EVP_PKEY_ED25519;
    case ossl_EVP_PKEY_HKDF: return EVP_PKEY_HKDF;
    case ossl_EVP_PKEY_NONE: return EVP_PKEY_NONE;
    case ossl_EVP_PKEY_RSA: return EVP_PKEY_RSA;
    case ossl_EVP_PKEY_RSA_PSS: return EVP_PKEY_RSA_PSS;
    case ossl_EVP_PKEY_X25519: return EVP_PKEY_X25519;

    case ossl_EVP_PKEY_RSA2:
    case ossl_EVP_PKEY_DSA1:
    case ossl_EVP_PKEY_DSA2:
    case ossl_EVP_PKEY_DSA3:
    case ossl_EVP_PKEY_DSA4:
    case ossl_EVP_PKEY_DH:
    case ossl_EVP_PKEY_DHX:
    case ossl_EVP_PKEY_SM2:
    case ossl_EVP_PKEY_HMAC:
    case ossl_EVP_PKEY_CMAC:
    case ossl_EVP_PKEY_SCRYPT:
    case ossl_EVP_PKEY_TLS1_PRF:
    case ossl_EVP_PKEY_POLY1305:
    case ossl_EVP_PKEY_SIPHASH:
    case ossl_EVP_PKEY_X448:
    case ossl_EVP_PKEY_ED448: {
      bssl_compat_error("Cannot convert ossl_EVP_PKEY_base_id() value %d", ossl);
      return EVP_PKEY_NONE;
    }
    default: {
      bssl_compat_error("Unknown ossl_EVP_PKEY_base_id() value %d", ossl);
      return EVP_PKEY_NONE;
    }
  }
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/evp.h#L91-L93
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_new.html
 */
EVP_PKEY *EVP_PKEY_new(void) {
  return ossl_EVP_PKEY_new();
}
