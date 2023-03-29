#include <openssl/bn.h>
#include <ossl/openssl/bn.h>
#include <ctype.h>


/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bn.h#L376
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BN_add_word.html
 */
int BN_add_word(BIGNUM *a, BN_ULONG w) {
  return ossl_BN_add_word(a, w);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bn.h#L267
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BN_bn2hex.html
 *
 * While the BoringSSL description doesn't mention how to free the resulting string,
 * looking at the source shows that it is allocated with OPENSSL_malloc(), so it
 * should be freed with OPENSSL_free(), consistent with what OpenSSL says.
 */
char *BN_bn2hex(const BIGNUM *bn) {
  char *s = ossl_BN_bn2hex(bn);

  if (s) {
    for(int i = 0; s[i]; i++) {
      s[i] = tolower(s[i]);
    }
  }

  return s;
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bn.h#L185
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BN_dup.html
 */
BIGNUM *BN_dup(const BIGNUM *src) {
  return ossl_BN_dup(src);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bn.h#L177
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BN_free.html
 */
void BN_free(BIGNUM *bn) {
  ossl_BN_free(bn);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bn.h#L171
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BN_new.html
 */
BIGNUM *BN_new(void) {
  return ossl_BN_new();
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bn.h#L202
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BN_num_bits.html
 */
unsigned BN_num_bits(const BIGNUM *bn) {
  return ossl_BN_num_bits(bn);
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bn.h#L436
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BN_ucmp.html
 */
int BN_ucmp(const BIGNUM *a, const BIGNUM *b) {
  return ossl_BN_ucmp(a, b);
}
