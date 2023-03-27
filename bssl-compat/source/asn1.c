#include <openssl/asn1.h>
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <ossl.h>


void ASN1_IA5STRING_free(ASN1_IA5STRING *str) {
  ossl_ASN1_IA5STRING_free(str);
}

ASN1_IA5STRING * ASN1_IA5STRING_new( void ) {
  return ossl_ASN1_IA5STRING_new();
}

BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn) {
  return ossl_ASN1_INTEGER_to_BN(ai, bn);
}

unsigned char *ASN1_STRING_data(ASN1_STRING *str) {
  return (unsigned char*)ossl_ASN1_STRING_get0_data(str);
}

void ASN1_STRING_free(ASN1_STRING *str) {
  return ossl_ASN1_STRING_free(str);
}

const unsigned char *ASN1_STRING_get0_data( const ASN1_STRING *str) {
  return ossl_ASN1_STRING_get0_data(str);
}


int ASN1_STRING_length(const ASN1_STRING *str) {
  return ossl_ASN1_STRING_length(str);
}

int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len) {
  return ossl_ASN1_STRING_set(str, data, len);
}

int ASN1_TIME_diff(int *out_days, int *out_seconds,
                   const ASN1_TIME *from, const ASN1_TIME *to) {
  return ossl_ASN1_TIME_diff(out_days, out_seconds, from, to);
}

ASN1_TIME *ASN1_TIME_new(void) {
  return ossl_ASN1_TIME_new();
}

ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t) {
  return ossl_ASN1_TIME_set(s, t);
}

ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **out, const unsigned char **inp, long len) {
  ASN1_INTEGER *result = NULL;
  CBB cbb;

  if (CBB_init(&cbb, len + 2)) {
    CBB child;

    if (CBB_add_asn1(&cbb, &child, CBS_ASN1_INTEGER) && CBB_add_bytes(&child, *inp, len) && CBB_flush(&cbb)) {
      const uint8_t *data = CBB_data(&cbb);

      if ((result = ossl.ossl_d2i_ASN1_INTEGER(out, &data, CBB_len(&cbb))) != NULL) {
        *inp += len;
      }
    }

    CBB_cleanup(&cbb);
  }

  return result;
}
