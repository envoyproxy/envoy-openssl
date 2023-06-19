#include <openssl/asn1.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/df6311bc6cc29765f97d952d00790233e2469e93/include/openssl/asn1.h#L1371
 * https://www.openssl.org/docs/man3.0/man3/ASN1_TIME_adj.html
 */
extern "C" ASN1_TIME *ASN1_TIME_adj(ASN1_TIME *s, time_t t, int offset_day, long offset_sec) {
  return ossl.ossl_ASN1_TIME_adj(s, t, offset_day, offset_sec);
}
