#ifndef BSSL_COMPAT_HEADER_BN_H
#define BSSL_COMPAT_HEADER_BN_H

#include "openssl/bn.h"
#include "bssl_compat/bssl_compat.h"

#if !defined(BORINGSSL_NO_CXX)
extern "C" {
#endif

int BN_cmp_word(const BIGNUM *a, BN_ULONG b);

#if !defined(BORINGSSL_NO_CXX)
} // extern "C"

extern "C++" {

BSSL_NAMESPACE_BEGIN

BORINGSSL_MAKE_DELETER(BIGNUM, BN_free)
BORINGSSL_MAKE_DELETER(BN_CTX, BN_CTX_free)
BORINGSSL_MAKE_DELETER(BN_MONT_CTX, BN_MONT_CTX_free)

BSSL_NAMESPACE_END

}  // extern C++
#endif

#endif // BSSL_COMPAT_HEADER_BN_H
