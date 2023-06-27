#include <openssl/ssl.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/include/openssl/ssl.h#L4486
 * https://www.openssl.org/docs/man3.0/man3/SSL_CIPHER_standard_name.html
 */
extern "C" char *SSL_CIPHER_get_rfc_name(const SSL_CIPHER *cipher) {
  const char *ostr {ossl.ossl_SSL_CIPHER_standard_name(cipher)};
  return (ostr == nullptr) ? nullptr : ossl.ossl_OPENSSL_strdup(ostr);
}
