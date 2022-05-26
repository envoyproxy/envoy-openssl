#pragma once

#include "openssl/ssl.h"

#ifndef OPENSSL_IS_BORINGSSL

#include <cstddef> // for size_t
#include <cstdint> // for uint8_t

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Cbs {

struct CBS {
  const uint8_t* data;
  size_t len;
};

void CBS_init(CBS* cbs, const uint8_t* data, size_t len);

size_t CBS_len(const CBS* cbs);
const uint8_t* CBS_data(const CBS* cbs);

int CBS_get_u8_length_prefixed(CBS* cbs, CBS* out);
int CBS_get_u16_length_prefixed(CBS* cbs, CBS* out);

// These functions are used outside of Envoy repository (e.g. by jwt_verify_lib)
int BN_cmp_word(BIGNUM* a, BN_ULONG b);
RSA* RSA_public_key_from_bytes(const uint8_t* in, size_t in_len);

} // namespace Cbs
} // namespace Common
} // namespace Extensions
} // namespace Envoy

#endif