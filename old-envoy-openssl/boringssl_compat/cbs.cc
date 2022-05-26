#include "cbs.h"

#ifndef OPENSSL_IS_BORINGSSL

#include <assert.h>

#define CBS_ASN1_TAG_SHIFT 24
#define CBS_ASN1_CONSTRUCTED (0x20u << CBS_ASN1_TAG_SHIFT)
#define CBS_ASN1_SEQUENCE (0x10u | CBS_ASN1_CONSTRUCTED)
#define CBS_ASN1_TAG_NUMBER_MASK ((1u << (5 + CBS_ASN1_TAG_SHIFT)) - 1)
#define CBS_ASN1_INTEGER 0x2u
#define CBS_ASN1_CONTEXT_SPECIFIC (0x80u << CBS_ASN1_TAG_SHIFT)

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Cbs {

void CBS_init(CBS* cbs, const uint8_t* data, size_t len) {
  cbs->data = data;
  cbs->len = len;
}

static int cbs_get(CBS* cbs, const uint8_t** p, size_t n) {
  if (cbs->len < n) {
    return 0;
  }

  *p = cbs->data;
  cbs->data += n;
  cbs->len -= n;
  return 1;
}

static int cbs_get_u(CBS* cbs, uint64_t* out, size_t len) {
  uint64_t result = 0;
  const uint8_t* data;

  if (!cbs_get(cbs, &data, len)) {
    return 0;
  }
  for (size_t i = 0; i < len; i++) {
    result <<= 8;
    result |= data[i];
  }
  *out = result;
  return 1;
}

int CBS_get_bytes(CBS* cbs, CBS* out, size_t len) {
  const uint8_t* v;
  if (!cbs_get(cbs, &v, len)) {
    return 0;
  }
  CBS_init(out, v, len);
  return 1;
}

static int cbs_get_length_prefixed(CBS* cbs, CBS* out, size_t len_len) {
  uint64_t len;
  if (!cbs_get_u(cbs, &len, len_len)) {
    return 0;
  }
  // If |len_len| <= 3 then we know that |len| will fit into a |size_t|, even on
  // 32-bit systems.
  assert(len_len <= 3);
  return CBS_get_bytes(cbs, out, len);
}

size_t CBS_len(const CBS* cbs) { return cbs->len; }

const uint8_t* CBS_data(const CBS* cbs) { return cbs->data; }

int CBS_get_u8_length_prefixed(CBS* cbs, CBS* out) { return cbs_get_length_prefixed(cbs, out, 1); }

int CBS_get_u16_length_prefixed(CBS* cbs, CBS* out) { return cbs_get_length_prefixed(cbs, out, 2); }

// These functions are used outside of Envoy repository (e.g. by jwt_verify_lib)

int BN_cmp_word(BIGNUM* a, BN_ULONG b) {
  BIGNUM* b_bn = BN_new();

  BN_set_word(b_bn, b);

  int result = BN_cmp(a, b_bn);

  BN_free(b_bn);

  return result;
}

int CBS_get(CBS* cbs, const uint8_t** p, size_t n) {
  if (cbs->len < n) {
    return 0;
  }

  *p = cbs->data;
  cbs->data += n;
  cbs->len -= n;
  return 1;
}

int CBS_skip(CBS* cbs, size_t len) {
  const uint8_t* dummy;
  return CBS_get(cbs, &dummy, len);
}

int CBS_get_u8(CBS* cbs, uint8_t* out) {
  const uint8_t* v;
  if (!CBS_get(cbs, &v, 1)) {
    return 0;
  }
  *out = *v;
  return 1;
}

int parse_base128_integer(CBS* cbs, uint64_t* out) {
  uint64_t v = 0;
  uint8_t b;
  do {
    if (!CBS_get_u8(cbs, &b)) {
      return 0;
    }
    if ((v >> (64 - 7)) != 0) {
      // The value is too large.
      return 0;
    }
    if (v == 0 && b == 0x80) {
      // The value must be minimally encoded.
      return 0;
    }
    v = (v << 7) | (b & 0x7f);

    // Values end at an octet with the high bit cleared.
  } while (b & 0x80);

  *out = v;
  return 1;
}

int parse_asn1_tag(CBS* cbs, unsigned* out) {
  uint8_t tag_byte;
  if (!CBS_get_u8(cbs, &tag_byte)) {
    return 0;
  }

  // ITU-T X.690 section 8.1.2.3 specifies the format for identifiers with a tag
  // number no greater than 30.
  //
  // If the number portion is 31 (0x1f, the largest value that fits in the
  // allotted bits), then the tag is more than one byte long and the
  // continuation bytes contain the tag number. This parser only supports tag
  // numbers less than 31 (and thus single-byte tags).
  unsigned tag = (static_cast<unsigned>(tag_byte) & 0xe0) << CBS_ASN1_TAG_SHIFT;
  unsigned tag_number = tag_byte & 0x1f;
  if (tag_number == 0x1f) {
    uint64_t v;
    if (!parse_base128_integer(cbs, &v) ||
        // Check the tag number is within our supported bounds.
        v > CBS_ASN1_TAG_NUMBER_MASK ||
        // Small tag numbers should have used low tag number form.
        v < 0x1f) {
      return 0;
    }
    tag_number = static_cast<unsigned>(v);
  }

  tag |= tag_number;

  *out = tag;
  return 1;
}

int CBS_get_u(CBS* cbs, uint32_t* out, size_t len) {
  uint32_t result = 0;
  const uint8_t* data;

  if (!CBS_get(cbs, &data, len)) {
    return 0;
  }
  for (size_t i = 0; i < len; i++) {
    result <<= 8;
    result |= data[i];
  }
  *out = result;
  return 1;
}

int CBS_get_any_asn1_element(CBS* cbs, CBS* out, unsigned* out_tag, size_t* out_header_len,
                             int ber_ok) {
  CBS header = *cbs;
  CBS throwaway;
  CBS_init(&throwaway, NULL, 0);

  if (out == NULL) {
    out = &throwaway;
  }

  unsigned tag;
  if (!parse_asn1_tag(&header, &tag)) {
    return 0;
  }
  if (out_tag != NULL) {
    *out_tag = tag;
  }

  uint8_t length_byte;
  if (!CBS_get_u8(&header, &length_byte)) {
    return 0;
  }

  size_t header_len = cbs->len - header.len;

  size_t len;
  // The format for the length encoding is specified in ITU-T X.690 section
  // 8.1.3.
  if ((length_byte & 0x80) == 0) {
    // Short form length.
    len = static_cast<size_t>(length_byte) + header_len;
    if (out_header_len != NULL) {
      *out_header_len = header_len;
    }
  } else {
    // The high bit indicate that this is the long form, while the next 7 bits
    // encode the number of subsequent octets used to encode the length (ITU-T
    // X.690 clause 8.1.3.5.b).
    const size_t num_bytes = length_byte & 0x7f;
    uint32_t len32;

    if (ber_ok && (tag & CBS_ASN1_CONSTRUCTED) != 0 && num_bytes == 0) {
      // indefinite length
      if (out_header_len != NULL) {
        *out_header_len = header_len;
      }
      return CBS_get_bytes(cbs, out, header_len);
    }

    // ITU-T X.690 clause 8.1.3.5.c specifies that the value 0xff shall not be
    // used as the first byte of the length. If this parser encounters that
    // value, num_bytes will be parsed as 127, which will fail the check below.
    if (num_bytes == 0 || num_bytes > 4) {
      return 0;
    }
    if (!CBS_get_u(&header, &len32, num_bytes)) {
      return 0;
    }
    // ITU-T X.690 section 10.1 (DER length forms) requires encoding the length
    // with the minimum number of octets.
    if (len32 < 128) {
      // Length should have used short-form encoding.
      return 0;
    }
    if ((len32 >> ((num_bytes - 1) * 8)) == 0) {
      // Length should have been at least one byte shorter.
      return 0;
    }
    len = len32;
    if (len + header_len + num_bytes < len) {
      // Overflow.
      return 0;
    }
    len += header_len + num_bytes;
    if (out_header_len != NULL) {
      *out_header_len = header_len + num_bytes;
    }
  }

  return CBS_get_bytes(cbs, out, len);
}

int cbs_get_asn1(CBS* cbs, CBS* out, unsigned tag_value, int skip_header) {
  size_t header_len;
  unsigned tag;
  CBS throwaway;
  CBS_init(&throwaway, NULL, 0);

  if (out == NULL) {
    out = &throwaway;
  }

  if (!CBS_get_any_asn1_element(cbs, out, &tag, &header_len, 0) || tag != tag_value) {
    return 0;
  }

  if (skip_header && !CBS_skip(out, header_len)) {
    assert(0);
    return 0;
  }

  return 1;
}

int CBS_get_asn1(CBS* cbs, CBS* out, unsigned tag_value) {
  return cbs_get_asn1(cbs, out, tag_value, 1);
}

int BN_parse_asn1_unsigned(CBS* cbs, BIGNUM* ret) {
  CBS child;
  CBS_init(&child, NULL, 0);
  if (!CBS_get_asn1(cbs, &child, CBS_ASN1_INTEGER) || child.len == 0) {
    //      OPENSSL_PUT_ERROR(BN, BN_R_BAD_ENCODING);
    return 0;
  }

  if (child.data[0] & 0x80) {
    //      OPENSSL_PUT_ERROR(BN, BN_R_NEGATIVE_NUMBER);
    return 0;
  }

  // INTEGERs must be minimal.
  if (child.data[0] == 0x00 && child.len > 1 && !(child.data[1] & 0x80)) {
    //      OPENSSL_PUT_ERROR(BN, BN_R_BAD_ENCODING);
    return 0;
  }

  return BN_bin2bn(child.data, child.len, ret) != NULL;
}
int parse_integer(CBS* cbs, BIGNUM** out) {
  assert(*out == NULL);
  *out = BN_new();
  if (*out == NULL) {
    return 0;
  }
  return BN_parse_asn1_unsigned(cbs, *out);
}

RSA* RSA_parse_public_key(CBS* cbs) {
  RSA* rsa = RSA_new();
  if (rsa == NULL) {
    return NULL;
  }
  BIGNUM* bn_n = NULL;
  BIGNUM* bn_e = NULL;
  CBS child;
  CBS_init(&child, NULL, 0);
  if (!CBS_get_asn1(cbs, &child, CBS_ASN1_SEQUENCE)) {
    RSA_free(rsa);
    return NULL;
  } else {

    if (!parse_integer(&child, &bn_n) || !parse_integer(&child, &bn_e) || child.len != 0) {
      RSA_free(rsa);
      return NULL;
    } else {
      RSA_set0_key(rsa, bn_n, bn_e, NULL);
    }
  }

  if (!BN_is_odd(bn_e) || BN_num_bits(bn_e) < 2) {
    RSA_free(rsa);
    return NULL;
  }

  return rsa;
}

RSA* RSA_public_key_from_bytes(const uint8_t* in, size_t in_len) {
  CBS cbs;
  CBS_init(&cbs, in, in_len);
  RSA* ret = RSA_parse_public_key(&cbs);
  if (ret == NULL) {
    return NULL;
  }
  return ret;
}

} // namespace Cbs
} // namespace Common
} // namespace Extensions
} // namespace Envoy

#endif // OPENSSL_IS_BORINGSSL
