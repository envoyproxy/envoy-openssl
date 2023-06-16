#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L2942
 * https://www.openssl.org/docs/man3.0/man3/X509_VERIFY_PARAM_set_flags.html
 */
extern "C" int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags) {
  return ossl.ossl_X509_VERIFY_PARAM_set_flags(param, flags);
}
