#include <openssl/err.h>
#include <ossl/openssl/err.h>
#include <assert.h>


/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/err.h#L272
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/ERR_clear_error.html
 */
void ERR_clear_error(void) {
  ossl_ERR_clear_error();
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/err.h#L216-L227
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/ERR_clear_error.html
 */
char *ERR_error_string_n(uint32_t packed_error, char *buf, size_t len) {
  ossl_ERR_error_string_n(packed_error, buf, len);
  return buf;
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/err.h#L396-L397
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/ERR_func_error_string.html
 */
const char *ERR_func_error_string(uint32_t packed_error) {
  return "OPENSSL_internal";
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/err.h#L173-L176
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/ERR_get_error.html
 */
uint32_t ERR_get_error(void) {
  return ossl_ERR_get_error();
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/err.h#L230-L233
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/ERR_lib_error_string.html
 */
const char *ERR_lib_error_string(uint32_t packed_error) {
  const char *ret = ossl_ERR_lib_error_string(packed_error);
  return (ret ? ret : "unknown library");
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/err.h#L207-L209
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/ERR_peek_last_error.html
 */
uint32_t ERR_peek_last_error(void) {
  return ossl_ERR_peek_last_error();
}

/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/err.h#L438-L441
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/ERR_put_error.html
 */
void ERR_put_error(int library, int unused, int reason, const char *file, unsigned line) {
  ossl_ERR_put_error(library, insed, reason, file, line);
}


/*
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/err.h#L235-L237
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/ERR_reason_error_string.html
 */
const char *ERR_reason_error_string(uint32_t packed_error) {
  const char *ret = ossl_ERR_reason_error_string(packed_error);
  return (ret ? ret : "unknown error");
}
