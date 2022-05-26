#include "extensions/common/crypto/utility_impl.h"

#include "common/common/assert.h"

#include "extensions/common/crypto/crypto_impl.h"

#include "absl/container/fixed_array.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"

namespace Envoy {
namespace Common {
namespace Crypto {

std::vector<uint8_t> UtilityImpl::getSha256Digest(const Buffer::Instance& buffer) {
  std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
  EVP_MD_CTX* ctx(EVP_MD_CTX_new());
  auto rc = EVP_DigestInit(ctx, EVP_sha256());
  RELEASE_ASSERT(rc == 1, "Failed to init digest context");
  for (const auto& slice : buffer.getRawSlices()) {
    rc = EVP_DigestUpdate(ctx, slice.mem_, slice.len_);
    RELEASE_ASSERT(rc == 1, "Failed to update digest");
  }
  rc = EVP_DigestFinal(ctx, digest.data(), nullptr);
  RELEASE_ASSERT(rc == 1, "Failed to finalize digest");
  EVP_MD_CTX_free(ctx);
  return digest;
}

std::vector<uint8_t> UtilityImpl::getSha256Hmac(const std::vector<uint8_t>& key,
                                                absl::string_view message) {
  std::vector<uint8_t> hmac(SHA256_DIGEST_LENGTH);
  const auto ret =
      HMAC(EVP_sha256(), key.data(), key.size(), reinterpret_cast<const uint8_t*>(message.data()),
           message.size(), hmac.data(), nullptr);
  RELEASE_ASSERT(ret != nullptr, "Failed to create HMAC");
  return hmac;
}

const VerificationOutput UtilityImpl::verifySignature(absl::string_view hash, CryptoObject& key,
                                                      const std::vector<uint8_t>& signature,
                                                      const std::vector<uint8_t>& text) {
  // Step 1: initialize EVP_MD_CTX
  EVP_MD_CTX* ctx(EVP_MD_CTX_new());

  // Step 2: initialize EVP_MD
  const EVP_MD* md = getHashFunction(hash);

  if (md == nullptr) {
    EVP_MD_CTX_free(ctx);
    return {false, absl::StrCat(hash, " is not supported.")};
  }
  // Step 3: initialize EVP_DigestVerify
  auto pkey_wrapper = Common::Crypto::Access::getTyped<Common::Crypto::PublicKeyObject>(key);
  EVP_PKEY* pkey = pkey_wrapper->getEVP_PKEY();

  if (pkey == nullptr) {
    EVP_MD_CTX_free(ctx);
    return {false, "Failed to initialize digest verify."};
  }

  int ok = EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey);
  if (!ok) {
    EVP_MD_CTX_free(ctx);
    return {false, "Failed to initialize digest verify."};
  }

  // Step 4: verify signature
  ok = EVP_DigestVerify(ctx, signature.data(), signature.size(), text.data(), text.size());

  // Step 5: check result
  if (ok == 1) {
    EVP_MD_CTX_free(ctx);
    return {true, ""};
  }

  EVP_MD_CTX_free(ctx);
  return {false, absl::StrCat("Failed to verify digest. Error code: ", ok)};
}

CryptoObjectPtr UtilityImpl::importPublicKey(const std::vector<uint8_t>& key) {
  const uint8_t* data = reinterpret_cast<const uint8_t*>(key.data());
  EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &data, key.size());

  auto publicKeyWrapper = new PublicKeyObject();
  publicKeyWrapper->setEVP_PKEY(pkey);

  std::unique_ptr<PublicKeyObject> publicKeyPtr = std::make_unique<PublicKeyObject>();
  publicKeyPtr.reset(publicKeyWrapper);

  return publicKeyPtr;
}

const EVP_MD* UtilityImpl::getHashFunction(absl::string_view name) {
  const std::string hash = absl::AsciiStrToLower(name);

  // Hash algorithms set refers
  // https://github.com/google/boringssl/blob/master/include/openssl/digest.h
  if (hash == "sha1") {
    return EVP_sha1();
  } else if (hash == "sha224") {
    return EVP_sha224();
  } else if (hash == "sha256") {
    return EVP_sha256();
  } else if (hash == "sha384") {
    return EVP_sha384();
  } else if (hash == "sha512") {
    return EVP_sha512();
  } else {
    return nullptr;
  }
}

// Register the crypto utility singleton.
static Crypto::ScopedUtilitySingleton* utility_ =
    new Crypto::ScopedUtilitySingleton(std::make_unique<Crypto::UtilityImpl>());

} // namespace Crypto
} // namespace Common
} // namespace Envoy
