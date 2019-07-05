#pragma once

#include <openssl/ssl.h>

#ifndef OPENSSL_IS_BORINGSSL

#include <openssl/x509v3.h>

#include <memory>

namespace bssl {

namespace internal {

// The Enable parameter is ignored and only exists so specializations can use
// SFINAE.
template <typename T, typename Enable = void> struct DeleterImpl {};

template <typename T> struct Deleter {
  void operator()(T* ptr) {
    // Rather than specialize Deleter for each type, we specialize
    // DeleterImpl. This allows bssl::UniquePtr<T> to be used while only
    // including bssl.h as long as the destructor is not emitted. This matches
    // std::unique_ptr's behavior on forward-declared types.
    //
    // DeleterImpl itself is specialized in the corresponding module's header
    // and must be included to release an object. If not included, the compiler
    // will error that DeleterImpl<T> does not have a method Free.
    DeleterImpl<T>::Free(ptr);
  }
};

template <typename T> struct StackTraits {};

#define BORINGSSL_DEFINE_STACK_TRAITS(name, type, is_const)                                        \
  extern "C++" {                                                                                   \
  namespace bssl {                                                                                 \
  namespace internal {                                                                             \
  template <> struct StackTraits<STACK_OF(name)> {                                                 \
    static constexpr bool kIsStack = true;                                                         \
    using Type = type;                                                                             \
    static constexpr bool kIsConst = is_const;                                                     \
  };                                                                                               \
  }                                                                                                \
  }                                                                                                \
  }

// Stacks defined with |DEFINE_STACK_OF| are freed with |sk_pop_free| and the
// corresponding type's deleter.
template <typename Stack>
struct DeleterImpl<Stack, typename std::enable_if<!StackTraits<Stack>::kIsConst>::type> {
  static void Free(Stack* sk) {
    sk_pop_free(
        reinterpret_cast<_STACK*>(sk),
        reinterpret_cast<void (*)(void*)>(DeleterImpl<typename StackTraits<Stack>::Type>::Free));
  }
};

template <typename Stack> class StackIteratorImpl {
public:
  using Type = typename StackTraits<Stack>::Type;
  // Iterators must be default-constructable.
  StackIteratorImpl() : sk_(nullptr), idx_(0) {}
  StackIteratorImpl(const Stack* sk, size_t idx) : sk_(sk), idx_(idx) {}

  bool operator==(StackIteratorImpl other) const { return sk_ == other.sk_ && idx_ == other.idx_; }
  bool operator!=(StackIteratorImpl other) const { return !(*this == other); }

  Type* operator*() const {
    return reinterpret_cast<Type*>(sk_value(reinterpret_cast<const _STACK*>(sk_), idx_));
  }

  StackIteratorImpl& operator++(/* prefix */) {
    idx_++;
    return *this;
  }

  StackIteratorImpl operator++(int /* postfix */) {
    StackIteratorImpl copy(*this);
    ++(*this);
    return copy;
  }

private:
  const Stack* sk_;
  size_t idx_;
};

template <typename Stack>
using StackIterator =
    typename std::enable_if<StackTraits<Stack>::kIsStack, StackIteratorImpl<Stack>>::type;
} // namespace internal

#define BORINGSSL_MAKE_DELETER(type, deleter)                                                      \
  namespace internal {                                                                             \
  template <> struct DeleterImpl<type> {                                                           \
    static void Free(type* ptr) { deleter(ptr); }                                                  \
  };                                                                                               \
  }

template <typename T> using UniquePtr = std::unique_ptr<T, internal::Deleter<T>>;

BORINGSSL_MAKE_DELETER(uint8_t, OPENSSL_free)
BORINGSSL_MAKE_DELETER(ASN1_TIME, ASN1_TIME_free)
BORINGSSL_MAKE_DELETER(BIO, BIO_free)
BORINGSSL_MAKE_DELETER(EVP_MD_CTX, EVP_MD_CTX_free)
BORINGSSL_MAKE_DELETER(EVP_PKEY, EVP_PKEY_free)
BORINGSSL_MAKE_DELETER(SSL, SSL_free)
BORINGSSL_MAKE_DELETER(SSL_CTX, SSL_CTX_free)
BORINGSSL_MAKE_DELETER(SSL_SESSION, SSL_SESSION_free)
BORINGSSL_MAKE_DELETER(X509, X509_free)
BORINGSSL_MAKE_DELETER(X509_INFO, X509_INFO_free)
BORINGSSL_MAKE_DELETER(X509_NAME, X509_NAME_free)
BORINGSSL_MAKE_DELETER(GENERAL_NAME, GENERAL_NAME_free)

BORINGSSL_MAKE_DELETER(ECDSA_SIG, ECDSA_SIG_free)
BORINGSSL_MAKE_DELETER(BIGNUM, BN_free)
BORINGSSL_MAKE_DELETER(RSA, RSA_free)
BORINGSSL_MAKE_DELETER(EC_KEY, EC_KEY_free)

} // namespace bssl

// Define begin() and end() for stack types so C++ range for loops work.
template <typename Stack>
static inline bssl::internal::StackIterator<Stack> begin(const Stack* sk) {
  return bssl::internal::StackIterator<Stack>(sk, 0);
}

template <typename Stack> static inline bssl::internal::StackIterator<Stack> end(const Stack* sk) {
  return bssl::internal::StackIterator<Stack>(sk, sk_num(reinterpret_cast<const _STACK*>(sk)));
}

BORINGSSL_DEFINE_STACK_TRAITS(GENERAL_NAME, GENERAL_NAME, false)
BORINGSSL_DEFINE_STACK_TRAITS(X509_INFO, X509_INFO, false)
BORINGSSL_DEFINE_STACK_TRAITS(X509_NAME, X509_NAME, false)

int BIO_mem_contents(const BIO* bio, const uint8_t** out_contents, size_t* out_len);

const SSL_METHOD* TLS_with_buffers_method();

#endif // OPENSSL_IS_BORINGSSL