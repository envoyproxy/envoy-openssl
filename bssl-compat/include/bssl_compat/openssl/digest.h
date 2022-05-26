#ifndef BSSL_COMPAT_HEADER_DIGEST_H
#define BSSL_COMPAT_HEADER_DIGEST_H

#include "bssl_compat/bssl_compat.h"

#if !defined(BORINGSSL_NO_CXX)
extern "C" {
#endif

EVP_MD_CTX* evp_md_ctx_init(void);
int evp_md_ctx_cleanup(EVP_MD_CTX* ctx);

#if !defined(BORINGSSL_NO_CXX)
} // extern "C"
#endif

#if !defined(BORINGSSL_NO_CXX)
extern "C++" {

BSSL_NAMESPACE_BEGIN

BORINGSSL_MAKE_DELETER(EVP_MD_CTX, EVP_MD_CTX_free)

using ScopedEVP_MD_CTX =
    internal::StackAllocated<EVP_MD_CTX, int, evp_md_ctx_init,
                             evp_md_ctx_cleanup>;

BSSL_NAMESPACE_END

}  // extern C++
#endif

#endif // BSSL_COMPAT_HEADER_DIGEST_H
