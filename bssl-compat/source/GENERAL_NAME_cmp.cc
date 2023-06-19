#include <openssl/x509v3.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/09b8fd44c3d36cab0860a8e520ecbfe58b02a7fa/include/openssl/x509v3.h#L509
 * https://www.openssl.org/docs/man3.0/man3/GENERAL_NAME_cmp.html
 */
extern "C" int GENERAL_NAME_cmp(const GENERAL_NAME *a, const GENERAL_NAME *b) {
  return ossl.ossl_GENERAL_NAME_cmp(const_cast<GENERAL_NAME*>(a), const_cast<GENERAL_NAME*>(b));
}
