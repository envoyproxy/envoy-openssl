#include <openssl/x509v3.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/09b8fd44c3d36cab0860a8e520ecbfe58b02a7fa/include/openssl/x509v3.h#L500
 * https://www.openssl.org/docs/man3.0/man3/GENERAL_NAME_set0_value.html
 */
extern "C" void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value) {
  ossl.ossl_GENERAL_NAME_set0_value(a, type, value);
}
