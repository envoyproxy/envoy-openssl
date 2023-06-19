#include <openssl/x509v3.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/09b8fd44c3d36cab0860a8e520ecbfe58b02a7fa/include/openssl/x509v3.h#L863
 * https://www.openssl.org/docs/man3.0/man3/X509_get_extension_flags.html
 */
extern "C" uint32_t X509_get_extension_flags(X509 *x) {
  return ossl.ossl_X509_get_extension_flags(x);
}
