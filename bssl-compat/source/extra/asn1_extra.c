#include <openssl/asn1.h>
#include <ossl/openssl/asn1.h>


void ASN1_INTEGER_free(ASN1_INTEGER *str) {
  return ossl_ASN1_INTEGER_free(str);
}

void ASN1_TIME_free(ASN1_TIME *s) {
  ossl_ASN1_TIME_free(s);
}

ASN1_INTEGER *ASN1_INTEGER_new() {
  return ossl_ASN1_INTEGER_new();
}

