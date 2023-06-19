#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L956
 * https://www.openssl.org/docs/man3.0/man3/X509_NAME_add_entry_by_txt.html
 */
extern "C" int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type, const uint8_t *bytes, int len, int loc, int set) {
  return ossl.ossl_X509_NAME_add_entry_by_txt(name, field, type, bytes, len, loc, set);
}
