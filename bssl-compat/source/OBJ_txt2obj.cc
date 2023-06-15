#include <openssl/obj.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/170045f4900cf6ffc2d5bf162a4ef196b2400e1a/include/openssl/obj.h#L170
 * https://www.openssl.org/docs/man3.0/man3/OBJ_txt2obj.html
 */
extern "C" ASN1_OBJECT *OBJ_txt2obj(const char *s, int dont_search_names) {
  return ossl.ossl_OBJ_txt2obj(s, dont_search_names);
}
