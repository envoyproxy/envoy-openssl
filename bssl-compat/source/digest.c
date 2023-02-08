#include <openssl/digest.h>
#include <ossl/openssl/evp.h>


/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L169-L176
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_DigestFinal_ex.html
 */
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, uint8_t *md_out, unsigned int *out_size) {
  return ossl_EVP_DigestFinal_ex(ctx, md_out, out_size);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L178-L181
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_DigestFinal.html
 */
int EVP_DigestFinal(EVP_MD_CTX *ctx, uint8_t *md_out, unsigned int *out_size) {
  return ossl_EVP_DigestFinal(ctx, md_out, out_size);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L145-L149
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_DigestInit_ex.html
 */
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *engine) {
  return ossl_EVP_DigestInit_ex(ctx, type, engine);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L151-L153
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_DigestInit.html
 */
int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
  return ossl_EVP_DigestInit(ctx, type);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L155-L158
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_DigestUpdate.html
 */
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t len) {
  return ossl_EVP_DigestUpdate(ctx, data, len);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L127-L128
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_MD_CTX_free.html
 */
void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
  ossl_EVP_MD_CTX_free(ctx);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L111-L114
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_MD_CTX_new.html
 */
EVP_MD_CTX *EVP_MD_CTX_new(void) {
  return ossl_EVP_MD_CTX_new();
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L198-L199
 * OSSL: https://www.openssl.org/docs/man3.0/man3/EVP_MD_type.html
 */
int EVP_MD_type(const EVP_MD *md) {
  return ossl_EVP_MD_type(md);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L81
 * OSSL:
 */
const EVP_MD *EVP_sha1(void) {
  return ossl_EVP_sha1();
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L82
 * OSSL:
 */
const EVP_MD *EVP_sha224(void) {
  return ossl_EVP_sha224();
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L83
 * OSSL:
 */
const EVP_MD *EVP_sha256(void) {
  return ossl_EVP_sha256();
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L84
 * OSSL:
 */
const EVP_MD *EVP_sha384(void) {
  return ossl_EVP_sha384();
}

/*
 * BSSL: https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/digest.h#L85
 * OSSL:
 */
const EVP_MD *EVP_sha512(void) {
  return ossl_EVP_sha512();
}
