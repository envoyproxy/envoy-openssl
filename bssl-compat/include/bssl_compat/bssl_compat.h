#ifndef BSSL_COMPAT_HEADER_H
#define BSSL_COMPAT_HEADER_H

#if !defined(__cplusplus) && !defined(BORINGSSL_NO_CXX)
#define BORINGSSL_NO_CXX
#endif

#define BSSL_NAMESPACE_BEGIN namespace bssl {
#define BSSL_NAMESPACE_END }

/* Needed for BORINGSSL_MAKE_DELETER */
#include "openssl/ossl_typ.h"
#include "openssl/evp.h"
#include "openssl/x509v3.h"
#include "openssl/ssl.h"

// stack_free_func is a function that frees an element in a stack. Note its
// actual type is void (*)(T *) for some T. Low-level |sk_*| functions will be
// passed a type-specific wrapper to call it correctly.
typedef void (*stack_free_func)(void *ptr);

#if !defined(BORINGSSL_NO_CXX)

/*extern "C" {
  int BIO_free(BIO *a);
  void X509_free(X509 *a);
  void X509_INFO_free(X509_INFO *a);
  void X509_NAME_free(X509_NAME *a);
  void SSL_free(SSL *ssl);
  void SSL_CTX_free(SSL_CTX *);
  void GENERAL_NAME_free(GENERAL_NAME *a);
  void EVP_PKEY_free(EVP_PKEY *pkey);
  void EC_KEY_free(EC_KEY *key);
  void RSA_free(RSA *r);
  void BN_free(BIGNUM *a);
  void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
  void ECDSA_SIG_free(ECDSA_SIG *sig);
}*/

#endif // !BORINGSSL_NO_CXX

#if !defined(BORINGSSL_NO_CXX)
extern "C++" {
BSSL_NAMESPACE_BEGIN
namespace internal {
template <typename T>
struct StackTraits {};
}
BSSL_NAMESPACE_END
}

#define BORINGSSL_DEFINE_STACK_TRAITS(name, type, is_const) \
  extern "C++" {                                            \
  BSSL_NAMESPACE_BEGIN                                      \
  namespace internal {                                      \
  template <>                                               \
  struct StackTraits<STACK_OF(name)> {                      \
    static constexpr bool kIsStack = true;                  \
    using Type = type;                                      \
    static constexpr bool kIsConst = is_const;              \
  };                                                        \
  }                                                         \
  BSSL_NAMESPACE_END                                        \
  }

#else
#define BORINGSSL_DEFINE_STACK_TRAITS(name, type, is_const)
#endif

#if !defined(BORINGSSL_NO_CXX)
extern "C++" {

#include <memory>

BSSL_NAMESPACE_BEGIN

namespace internal {

// The Enable parameter is ignored and only exists so specializations can use
// SFINAE.
template <typename T, typename Enable = void>
struct DeleterImpl {};

template <typename T>
struct Deleter {
  void operator()(T *ptr) {
    // Rather than specialize Deleter for each type, we specialize
    // DeleterImpl. This allows bssl::UniquePtr<T> to be used while only
    // including base.h as long as the destructor is not emitted. This matches
    // std::unique_ptr's behavior on forward-declared types.
    //
    // DeleterImpl itself is specialized in the corresponding module's header
    // and must be included to release an object. If not included, the compiler
    // will error that DeleterImpl<T> does not have a method Free.
    DeleterImpl<T>::Free(ptr);
  }
};

// OpenSSL internal data structures are hidden; bssl's original implementation of
// StackAllocated was changed to support OpenSSL api
template <typename T, typename CleanupRet, T* (*init)(),
          CleanupRet (*cleanup)(T *)>
class StackAllocated {
 public:
  StackAllocated() { ctx_ = init(); }
  ~StackAllocated() { cleanup(ctx_); }

  StackAllocated(const StackAllocated<T, CleanupRet, init, cleanup> &) = delete;
  T& operator=(const StackAllocated<T, CleanupRet, init, cleanup> &) = delete;

  T *get() { return ctx_; }
  const T *get() const { return ctx_; }

  T *operator->() { return ctx_; }
  const T *operator->() const { return ctx_; }

  void Reset() {
    cleanup(ctx_);
    ctx_ = init();
  }

 private:
  T* ctx_;
};

}  // namespace internal

#define BORINGSSL_MAKE_DELETER(type, deleter)     \
  namespace internal {                            \
  template <>                                     \
  struct DeleterImpl<type> {                      \
    static void Free(type *ptr) { deleter(ptr); } \
  };                                              \
  }

// Holds ownership of heap-allocated BoringSSL structures. Sample usage:
//   bssl::UniquePtr<RSA> rsa(RSA_new());
//   bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
template <typename T>
using UniquePtr = std::unique_ptr<T, internal::Deleter<T>>;

#define BORINGSSL_MAKE_UP_REF(type, up_ref_func)             \
  inline UniquePtr<type> UpRef(type *v) {                    \
    if (v != nullptr) {                                      \
      up_ref_func(v);                                        \
    }                                                        \
    return UniquePtr<type>(v);                               \
  }                                                          \
                                                             \
  inline UniquePtr<type> UpRef(const UniquePtr<type> &ptr) { \
    return UpRef(ptr.get());                                 \
  }

BSSL_NAMESPACE_END

}  // extern C++

#endif  // !BORINGSSL_NO_CXX

#if !defined(BORINGSSL_NO_CXX)
extern "C++" {

#include <type_traits>

BSSL_NAMESPACE_BEGIN

namespace internal {

// Stacks defined with |DEFINE_CONST_STACK_OF| are freed with |sk_free|.
template <typename Stack>
struct DeleterImpl<
    Stack, typename std::enable_if<StackTraits<Stack>::kIsConst>::type> {
  static void Free(Stack *sk) { sk_free(reinterpret_cast<_STACK *>(sk)); }
};

// Stacks defined with |DEFINE_STACK_OF| are freed with |sk_pop_free| and the
// corresponding type's deleter.
template <typename Stack>
struct DeleterImpl<
    Stack, typename std::enable_if<!StackTraits<Stack>::kIsConst>::type> {
  
  static void Free(Stack *sk) {
    // sk_FOO_pop_free is defined by macros and bound by name, so we cannot
    // access it from C++ here.
    using Type = typename StackTraits<Stack>::Type;
    OPENSSL_sk_pop_free(reinterpret_cast<_STACK *>(sk),
                   reinterpret_cast<void (*)(void *)>(DeleterImpl<Type>::Free));
  }
};

template <typename Stack>
class StackIteratorImpl {
 public:
  using Type = typename StackTraits<Stack>::Type;
  // Iterators must be default-constructable.
  StackIteratorImpl() : sk_(nullptr), idx_(0) {}
  StackIteratorImpl(const Stack *sk, size_t idx) : sk_(sk), idx_(idx) {}

  bool operator==(StackIteratorImpl other) const {
    return sk_ == other.sk_ && idx_ == other.idx_;
  }
  bool operator!=(StackIteratorImpl other) const {
    return !(*this == other);
  }

  Type *operator*() const {
    return reinterpret_cast<Type *>(
        sk_value(reinterpret_cast<const _STACK *>(sk_), idx_));
  }

  StackIteratorImpl &operator++(/* prefix */) {
    idx_++;
    return *this;
  }

  StackIteratorImpl operator++(int /* postfix */) {
    StackIteratorImpl copy(*this);
    ++(*this);
    return copy;
  }

private:
  const Stack *sk_;
  size_t idx_;
};

template <typename Stack>
using StackIterator = typename std::enable_if<StackTraits<Stack>::kIsStack,
                                              StackIteratorImpl<Stack>>::type;

}  // namespace internal

// PushToStack pushes |elem| to |sk|. It returns true on success and false on
// allocation failure.
template <typename Stack>
inline
    typename std::enable_if<!internal::StackTraits<Stack>::kIsConst, bool>::type
    PushToStack(Stack *sk,
                UniquePtr<typename internal::StackTraits<Stack>::Type> elem) {
  if (!sk_push(reinterpret_cast<_STACK *>(sk), elem.get())) {
    return false;
  }
  // sk_push takes ownership on success.
  elem.release();
  return true;
}

BSSL_NAMESPACE_END

// Define begin() and end() for stack types so C++ range for loops work.
template <typename Stack>
inline bssl::internal::StackIterator<Stack> begin(const Stack *sk) {
  return bssl::internal::StackIterator<Stack>(sk, 0);
}

template <typename Stack>
inline bssl::internal::StackIterator<Stack> end(const Stack *sk) {
  return bssl::internal::StackIterator<Stack>(
      sk, sk_num(reinterpret_cast<const _STACK *>(sk)));
}

}  // extern C++
#endif

#if !defined(BORINGSSL_NO_CXX)
extern "C++" {

BSSL_NAMESPACE_BEGIN

BORINGSSL_MAKE_DELETER(ASN1_OBJECT, ASN1_OBJECT_free)
BORINGSSL_MAKE_DELETER(ASN1_STRING, ASN1_STRING_free)
BORINGSSL_MAKE_DELETER(ASN1_TYPE, ASN1_TYPE_free)
BORINGSSL_MAKE_DELETER(BIO, BIO_free)
BORINGSSL_MAKE_DELETER(BUF_MEM, BUF_MEM_free)
BORINGSSL_MAKE_DELETER(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)
BORINGSSL_MAKE_DELETER(CONF, NCONF_free)
BORINGSSL_MAKE_DELETER(DH, DH_free)
BORINGSSL_MAKE_DELETER(DSA, DSA_free)
BORINGSSL_MAKE_DELETER(DSA_SIG, DSA_SIG_free)
BORINGSSL_MAKE_DELETER(EC_POINT, EC_POINT_free)
BORINGSSL_MAKE_DELETER(EC_GROUP, EC_GROUP_free)
BORINGSSL_MAKE_DELETER(EC_KEY, EC_KEY_free)
BORINGSSL_MAKE_DELETER(ECDSA_SIG, ECDSA_SIG_free)
BORINGSSL_MAKE_DELETER(EVP_PKEY, EVP_PKEY_free)
BORINGSSL_MAKE_DELETER(EVP_PKEY_CTX, EVP_PKEY_CTX_free)
BORINGSSL_MAKE_DELETER(char, OPENSSL_free)
BORINGSSL_MAKE_DELETER(uint8_t, OPENSSL_free)
BORINGSSL_MAKE_DELETER(RSA, RSA_free)
BORINGSSL_MAKE_DELETER(SSL, SSL_free)
BORINGSSL_MAKE_DELETER(SSL_CTX, SSL_CTX_free)
BORINGSSL_MAKE_DELETER(SSL_SESSION, SSL_SESSION_free)
BORINGSSL_MAKE_DELETER(X509, X509_free)
BORINGSSL_MAKE_DELETER(X509_ALGOR, X509_ALGOR_free)
BORINGSSL_MAKE_DELETER(X509_CRL, X509_CRL_free)
BORINGSSL_MAKE_DELETER(X509_CRL_METHOD, X509_CRL_METHOD_free)
BORINGSSL_MAKE_DELETER(X509_EXTENSION, X509_EXTENSION_free)
BORINGSSL_MAKE_DELETER(X509_INFO, X509_INFO_free)
BORINGSSL_MAKE_DELETER(X509_LOOKUP, X509_LOOKUP_free)
BORINGSSL_MAKE_DELETER(X509_NAME, X509_NAME_free)
BORINGSSL_MAKE_DELETER(X509_NAME_ENTRY, X509_NAME_ENTRY_free)
BORINGSSL_MAKE_DELETER(X509_PKEY, X509_PKEY_free)
BORINGSSL_MAKE_DELETER(X509_POLICY_TREE, X509_policy_tree_free)
BORINGSSL_MAKE_DELETER(X509_REVOKED, X509_REVOKED_free)
BORINGSSL_MAKE_DELETER(X509_STORE, X509_STORE_free)
BORINGSSL_MAKE_DELETER(X509_STORE_CTX, X509_STORE_CTX_free)
BORINGSSL_MAKE_DELETER(X509_VERIFY_PARAM, X509_VERIFY_PARAM_free)
BORINGSSL_MAKE_DELETER(DIST_POINT, DIST_POINT_free)
BORINGSSL_MAKE_DELETER(GENERAL_NAME, GENERAL_NAME_free)

BSSL_NAMESPACE_END

}  // extern C++

#endif  // !BORINGSSL_NO_CXX

BORINGSSL_DEFINE_STACK_TRAITS(X509_INFO, X509_INFO, false)
BORINGSSL_DEFINE_STACK_TRAITS(X509_NAME, X509_NAME, false)
BORINGSSL_DEFINE_STACK_TRAITS(GENERAL_NAME, GENERAL_NAME, false)
BORINGSSL_DEFINE_STACK_TRAITS(SSL_CIPHER, SSL_CIPHER, false)

//#define sk_X509_NAME_find(a,b,c) sk_X509_NAME_find((a), (c))

// SSL_TICKET_KEY_NAME_LEN is the length of the key name prefix of a session
// ticket.
#define SSL_TICKET_KEY_NAME_LEN 16

inline int BIO_mem_contents(const BIO *bio, const uint8_t **out_contents, size_t *out_len) {
  size_t length = BIO_get_mem_data((BIO *)bio, out_contents);
  *out_len = length;
  return 1;
}

#include "bssl_compat/openssl/digest.h"
#include "bssl_compat/openssl/bn.h"

#endif  // BSSL_COMPAT_HEADER_H

