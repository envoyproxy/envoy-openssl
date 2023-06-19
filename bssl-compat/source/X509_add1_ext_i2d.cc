#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L2097
 * https://www.openssl.org/docs/man3.0/man3/X509_add1_ext_i2d.html
 */
extern "C" int X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit, unsigned long flags) {
  return ossl.ossl_X509_add1_ext_i2d(x, nid, value, crit, flags);
}
