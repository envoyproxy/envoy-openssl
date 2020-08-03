#include "boringssl_compat/bssl.h"

#ifndef OPENSSL_IS_BORINGSSL

int BIO_mem_contents(const BIO* bio, const uint8_t** out_contents, size_t* out_len) {
  size_t length = BIO_get_mem_data(const_cast<BIO*>(bio), out_contents);
  *out_len = length;
  return 1;
}

const SSL_METHOD* TLS_with_buffers_method() { return TLS_method(); }

#endif
