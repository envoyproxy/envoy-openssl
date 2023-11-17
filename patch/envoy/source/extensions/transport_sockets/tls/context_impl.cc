#include "source/extensions/transport_sockets/tls/context_impl.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "envoy/admin/v3/certs.pb.h"
#include "envoy/common/exception.h"
#include "envoy/common/platform.h"
#include "envoy/ssl/ssl_socket_extended_info.h"
#include "envoy/stats/scope.h"
#include "envoy/type/matcher/v3/string.pb.h"

#include "source/common/common/assert.h"
#include "source/common/common/base64.h"
#include "source/common/common/fmt.h"
#include "source/common/common/hex.h"
#include "source/common/common/utility.h"
#include "source/common/network/address_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/common/runtime/runtime_features.h"
#include "source/common/stats/utility.h"
#include "source/extensions/transport_sockets/tls/cert_validator/factory.h"
#include "source/extensions/transport_sockets/tls/openssl_impl.h"
#include "source/extensions/transport_sockets/tls/stats.h"
#include "source/extensions/transport_sockets/tls/utility.h"

#include "absl/container/node_hash_set.h"
#include "absl/strings/match.h"
#include "absl/strings/str_join.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/pkcs12.h"
#include "openssl/rand.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

namespace {
std::string certificateDigest(X509* cert) {
  std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
  unsigned int n;
  X509_digest(cert, EVP_sha1(), digest.data(), &n);
  return Hex::encode(digest);
}

void logSslErrorChain() {
  while (uint64_t err = ERR_get_error()) {
    ENVOY_LOG_MISC(debug, "SSL error: {}:{}:{}:{}", err,
                   absl::NullSafeStringView(ERR_lib_error_string(err)),
                   absl::NullSafeStringView(ERR_func_error_string(err)), ERR_GET_REASON(err),
                   absl::NullSafeStringView(ERR_reason_error_string(err)));
  }
}

} // namespace

int ContextImpl::sslExtendedSocketInfoIndex() {
  CONSTRUCT_ON_FIRST_USE(int, []() -> int {
    int ssl_context_index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    RELEASE_ASSERT(ssl_context_index >= 0, "");
    return ssl_context_index;
  }());
}


ContextImpl::ContextImpl(Stats::Scope& scope, const Envoy::Ssl::ContextConfig& config,
                         TimeSource& time_source)
    : scope_(scope), stats_(generateSslStats(scope)), time_source_(time_source),
      tls_max_version_(config.maxProtocolVersion()),
      stat_name_set_(scope.symbolTable().makeSet("TransportSockets::Tls")),
      unknown_ssl_cipher_(stat_name_set_->add("unknown_ssl_cipher")),
      unknown_ssl_curve_(stat_name_set_->add("unknown_ssl_curve")),
      unknown_ssl_algorithm_(stat_name_set_->add("unknown_ssl_algorithm")),
      unknown_ssl_version_(stat_name_set_->add("unknown_ssl_version")),
      ssl_ciphers_(stat_name_set_->add("ssl.ciphers")),
      ssl_versions_(stat_name_set_->add("ssl.versions")),
      ssl_curves_(stat_name_set_->add("ssl.curves")),
      ssl_sigalgs_(stat_name_set_->add("ssl.sigalgs")), capabilities_(config.capabilities()),
      tls_keylog_local_(config.tlsKeyLogLocal()), tls_keylog_remote_(config.tlsKeyLogRemote()) {

  auto cert_validator_name = getCertValidatorName(config.certificateValidationContext());
  auto cert_validator_factory =
      Registry::FactoryRegistry<CertValidatorFactory>::getFactory(cert_validator_name);

  if (!cert_validator_factory) {
    throw EnvoyException(
        absl::StrCat("Failed to get certificate validator factory for ", cert_validator_name));
  }

  cert_validator_ = cert_validator_factory->createCertValidator(
      config.certificateValidationContext(), stats_, time_source_);

  const auto tls_certificates = config.tlsCertificates();

  tls_context_.cert_contexts_.resize(std::max(static_cast<size_t>(1), tls_certificates.size()));
  tls_context_.ssl_ctx_.reset(SSL_CTX_new(TLS_method()));

  int rc = SSL_CTX_set_app_data(tls_context_.ssl_ctx_.get(), this);
  RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));

  rc = SSL_CTX_set_min_proto_version(tls_context_.ssl_ctx_.get(), config.minProtocolVersion());
  RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));

  rc = SSL_CTX_set_max_proto_version(tls_context_.ssl_ctx_.get(), config.maxProtocolVersion());
  RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));

  if (!capabilities_.provides_ciphers_and_curves &&
      !Envoy::Extensions::TransportSockets::Tls::set_strict_cipher_list(
          tls_context_.ssl_ctx_.get(), config.cipherSuites().c_str())) {
    // Break up a set of ciphers into each individual cipher and try them each individually in
    // order to attempt to log which specific one failed. Example of config.cipherSuites():
    // "-ALL:[ECDHE-ECDSA-AES128-GCM-SHA256|ECDHE-ECDSA-CHACHA20-POLY1305]:ECDHE-ECDSA-AES128-SHA".
    //
    // "-" is both an operator when in the leading position of a token (-ALL: don't allow this
    // cipher), and the common separator in names (ECDHE-ECDSA-AES128-GCM-SHA256). Don't split on
    // it because it will separate pieces of the same cipher. When it is a leading character, it
    // is removed below.
    std::vector<absl::string_view> ciphers =
        StringUtil::splitToken(config.cipherSuites(), ":+![|]", false);
    std::vector<std::string> bad_ciphers;
    for (const auto& cipher : ciphers) {
      std::string cipher_str(cipher);

      if (absl::StartsWith(cipher_str, "-")) {
        cipher_str.erase(cipher_str.begin());
      }

      if (!Envoy::Extensions::TransportSockets::Tls::set_strict_cipher_list(
              tls_context_.ssl_ctx_.get(), cipher_str.c_str())) {
        bad_ciphers.push_back(cipher_str);
      }
    }
    throw EnvoyException(fmt::format("Failed to initialize cipher suites {}. The following "
                                     "ciphers were rejected when tried individually: {}",
                                     config.cipherSuites(), absl::StrJoin(bad_ciphers, ", ")));
  }

  if (!capabilities_.provides_ciphers_and_curves &&
      !SSL_CTX_set1_curves_list(tls_context_.ssl_ctx_.get(), config.ecdhCurves().c_str())) {
    throw EnvoyException(absl::StrCat("Failed to initialize ECDH curves ", config.ecdhCurves()));
  }

  // We only maintain one SSL_CTX under OpenSSL, but to keep maintenance simple[r],
  // initializeSslContexts() parameter list was kept unchanged from upstream,
  // hence construction of a vector of ssl contexts...
  auto verify_mode = cert_validator_->initializeSslContexts(
      {tls_context_.ssl_ctx_.get()}, config.capabilities().provides_certificates);
  if (!capabilities_.verifies_peer_certificates) {
    if (verify_mode != SSL_VERIFY_NONE) {
      SSL_CTX_set_verify(tls_context_.ssl_ctx_.get(), verify_mode, nullptr);
      SSL_CTX_set_cert_verify_callback(tls_context_.ssl_ctx_.get(), verifyCallback, this);
    }
  }

  absl::node_hash_set<int> cert_pkey_ids;
 
  if (!capabilities_.provides_certificates) {
    for (uint32_t i = 0; i < tls_certificates.size(); ++i) {
      auto& cert_context = tls_context_.cert_contexts_[i];
      // Load certificate chain.
      const auto& tls_certificate = tls_certificates[i].get();

      if (!tls_certificate.pkcs12().empty()) {
        tls_context_.loadPkcs12(i, tls_certificate.pkcs12(), tls_certificate.pkcs12Path(),
                       tls_certificate.password());
      } else {
        tls_context_.loadCertificateChain(i, tls_certificate.certificateChain(),
                                 tls_certificate.certificateChainPath());
      }

      // The must staple extension means the certificate promises to carry
      // with it an OCSP staple. https://tools.ietf.org/html/rfc7633#section-6
      constexpr absl::string_view tls_feature_ext = "1.3.6.1.5.5.7.1.24";
      constexpr absl::string_view must_staple_ext_value = "\x30\x3\x02\x01\x05";
      auto must_staple =
          Utility::getCertificateExtensionValue(*cert_context.cert_chain_, tls_feature_ext);
      tls_context_.cert_context_lookup_.emplace(certificateDigest(cert_context.cert_chain_.get()),
                                                std::reference_wrapper<CertContext>(cert_context));
      if (must_staple == must_staple_ext_value) {
        cert_context.is_must_staple_ = true;
      }

      bssl::UniquePtr<EVP_PKEY> public_key(X509_get_pubkey(cert_context.cert_chain_.get()));
      const int pkey_id = EVP_PKEY_id(public_key.get());
      if (!cert_pkey_ids.insert(pkey_id).second) {
        throw EnvoyException(fmt::format("Failed to load certificate chain from {}, at most one "
                                         "certificate of a given type may be specified",
                                         cert_context.cert_chain_file_path_));
      }

      cert_context.is_ecdsa_ = pkey_id == EVP_PKEY_EC;
      switch (pkey_id) {
      case EVP_PKEY_EC: {
        // We only support P-256 ECDSA today.
        const EC_KEY* ecdsa_public_key = EVP_PKEY_get0_EC_KEY(public_key.get());
        // Since we checked the key type above, this should be valid.
        ASSERT(ecdsa_public_key != nullptr);
        const EC_GROUP* ecdsa_group = EC_KEY_get0_group(ecdsa_public_key);
        if (ecdsa_group == nullptr ||
            EC_GROUP_get_curve_name(ecdsa_group) != NID_X9_62_prime256v1) {
          throw EnvoyException(fmt::format("Failed to load certificate chain from {}, only P-256 "
                                           "ECDSA certificates are supported",
                                           cert_context.cert_chain_file_path_));
        }
        cert_context.is_ecdsa_ = true;
      } break;
      case EVP_PKEY_RSA: {
        // We require RSA certificates with 2048-bit or larger keys.
        const RSA* rsa_public_key = EVP_PKEY_get0_RSA(public_key.get());
        // Since we checked the key type above, this should be valid.
        ASSERT(rsa_public_key != nullptr);
        const unsigned rsa_key_length = RSA_size(rsa_public_key);

        if (rsa_key_length < 2048 / 8) {
          throw EnvoyException(
              fmt::format("Failed to load certificate chain from {}, only RSA "
                          "certificates with 2048-bit or larger keys are supported",
                          cert_context.cert_chain_file_path_));
        }
      } break;
      }

      Envoy::Ssl::PrivateKeyMethodProviderSharedPtr private_key_method_provider =
          tls_certificate.privateKeyMethod();
      // We either have a private key or a BoringSSL private key method provider.
       if (private_key_method_provider) {
        throw EnvoyException(fmt::format("Private key provider configured, but not supported"));
        /*
              ctx.private_key_method_provider_ = private_key_method_provider;
              // The provider has a reference to the private key method for the context lifetime.
              Ssl::BoringSslPrivateKeyMethodSharedPtr private_key_method =
                  private_key_method_provider->getBoringSslPrivateKeyMethod();
              if (private_key_method == nullptr) {
              }
              SSL_CTX_set_private_key_method(ctx.ssl_ctx_.get(), private_key_method.get());
        */
      } else {
      if (!tls_certificate.privateKey().empty()) {
        // Load private key.
        tls_context_.loadPrivateKey(tls_certificate.privateKey(), tls_certificate.privateKeyPath(),
                           tls_certificate.password());
      }
      }
    }
  }

  // use the server's cipher list preferences
  SSL_CTX_set_options(tls_context_.ssl_ctx_.get(), SSL_OP_CIPHER_SERVER_PREFERENCE);

  parsed_alpn_protocols_ = parseAlpnProtocols(config.alpnProtocols());

  // Use the SSL library to iterate over the configured ciphers.
  //
  // Note that if a negotiated cipher suite is outside of this set, we'll issue an ENVOY_BUG.
  for (const SSL_CIPHER* cipher : SSL_CTX_get_ciphers(tls_context_.ssl_ctx_.get())) {
    stat_name_set_->rememberBuiltin(SSL_CIPHER_get_name(cipher));
  }

  // Ciphers
  const STACK_OF(SSL_CIPHER)* ciphers = SSL_CTX_get_ciphers(tls_context_.ssl_ctx_.get());
  for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
    const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
    stat_name_set_->rememberBuiltin(SSL_CIPHER_get_name(cipher));
  }

  // As late as possible, run the custom SSL_CTX configuration callback on each
  // SSL_CTX, if set.
  if (auto sslctx_cb = config.sslctxCb(); sslctx_cb) {
    sslctx_cb(tls_context_.ssl_ctx_.get());
  }

  // Add supported cipher suites from the TLS 1.3 spec:
  // https://tools.ietf.org/html/rfc8446#appendix-B.4
  // AES-CCM cipher suites are removed (no BoringSSL support).
  //
  // Note that if a negotiated cipher suite is outside of this set, we'll issue an ENVOY_BUG.
  stat_name_set_->rememberBuiltins(
      {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"});

  // All supported curves. Source:
  // https://github.com/google/boringssl/blob/3743aafdacff2f7b083615a043a37101f740fa53/ssl/ssl_key_share.cc#L302-L309
  //
  // Note that if a negotiated curve is outside of this set, we'll issue an ENVOY_BUG.
  stat_name_set_->rememberBuiltins({"P-224", "P-256", "P-384", "P-521", "X25519", "CECPQ2"});

  // All supported signature algorithms. Source:
  // https://github.com/google/boringssl/blob/3743aafdacff2f7b083615a043a37101f740fa53/ssl/ssl_privkey.cc#L436-L453
  //
  // Note that if a negotiated algorithm is outside of this set, we'll issue an ENVOY_BUG.
  stat_name_set_->rememberBuiltins({
      "rsa_pkcs1_md5_sha1",
      "rsa_pkcs1_sha1",
      "rsa_pkcs1_sha256",
      "rsa_pkcs1_sha384",
      "rsa_pkcs1_sha512",
      "ecdsa_sha1",
      "ecdsa_secp256r1_sha256",
      "ecdsa_secp384r1_sha384",
      "ecdsa_secp521r1_sha512",
      "rsa_pss_rsae_sha256",
      "rsa_pss_rsae_sha384",
      "rsa_pss_rsae_sha512",
      "ed25519",
  });

  // All supported protocol versions.
  //
  // Note that if a negotiated version is outside of this set, we'll issue an ENVOY_BUG.
  stat_name_set_->rememberBuiltins({"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"});

  if (!config.tlsKeyLogPath().empty()) {
    ENVOY_LOG(debug, "Enable tls key log");
    tls_keylog_file_ = config.accessLogManager().createAccessLog(
        Filesystem::FilePathAndType{Filesystem::DestinationType::File, config.tlsKeyLogPath()});
      SSL_CTX* ctx = tls_context_.ssl_ctx_.get();
      ASSERT(ctx != nullptr);
      SSL_CTX_set_keylog_callback(ctx, keylogCallback);
  }

}

void ContextImpl::keylogCallback(const SSL* ssl, const char* line) {
  ASSERT(ssl != nullptr);
  auto callbacks =
      static_cast<Network::TransportSocketCallbacks*>(SSL_get_ex_data(ssl, sslSocketIndex()));
  auto ctx = static_cast<ContextImpl*>(SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
  ASSERT(callbacks != nullptr);
  ASSERT(ctx != nullptr);

  if ((ctx->tls_keylog_local_.getIpListSize() == 0 ||
       ctx->tls_keylog_local_.contains(
           *(callbacks->connection().connectionInfoProvider().localAddress()))) &&
      (ctx->tls_keylog_remote_.getIpListSize() == 0 ||
       ctx->tls_keylog_remote_.contains(
           *(callbacks->connection().connectionInfoProvider().remoteAddress())))) {
    ctx->tls_keylog_file_->write(absl::StrCat(line, "\n"));
  }
}

int ContextImpl::sslSocketIndex() {
  CONSTRUCT_ON_FIRST_USE(int, []() -> int {
    int ssl_socket_index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    RELEASE_ASSERT(ssl_socket_index >= 0, "");
    return ssl_socket_index;
  }());
}

int ServerContextImpl::alpnSelectCallback(const unsigned char** out, unsigned char* outlen,
                                          const unsigned char* in, unsigned int inlen) {
  // Currently this uses the standard selection algorithm in priority order.
  const uint8_t* alpn_data = parsed_alpn_protocols_.data();
  size_t alpn_data_size = parsed_alpn_protocols_.size();

  if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen, alpn_data, alpn_data_size, in,
                            inlen) != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_NOACK;
  } else {
    return SSL_TLSEXT_ERR_OK;
  }
}

std::vector<uint8_t> ContextImpl::parseAlpnProtocols(const std::string& alpn_protocols) {
  if (alpn_protocols.empty()) {
    return {};
  }

  if (alpn_protocols.size() >= 65535) {
    throw EnvoyException("Invalid ALPN protocol string");
  }

  std::vector<uint8_t> out(alpn_protocols.size() + 1);
  size_t start = 0;
  for (size_t i = 0; i <= alpn_protocols.size(); i++) {
    if (i == alpn_protocols.size() || alpn_protocols[i] == ',') {
      if (i - start > 255) {
        throw EnvoyException("Invalid ALPN protocol string");
      }

      out[start] = i - start;
      start = i + 1;
    } else {
      out[i + 1] = alpn_protocols[i];
    }
  }

  return out;
}

bssl::UniquePtr<SSL>
ContextImpl::newSsl(const Network::TransportSocketOptionsConstSharedPtr& options) {
  // We use the first certificate for a new SSL object, later in the
  // SSL_CTX_set_select_certificate_cb() callback following ClientHello, we replace with the
  // selected certificate via SSL_set_SSL_CTX().
  auto ssl_con = bssl::UniquePtr<SSL>(SSL_new(tls_context_.ssl_ctx_.get()));
  SSL_set_app_data(ssl_con.get(), &options);  
  return ssl_con;//ssl::UniquePtr<SSL>(SSL_new(tls_context_.ssl_ctx_.get()));
}

int ContextImpl::verifyCallback(X509_STORE_CTX* store_ctx, void* arg) {
  ContextImpl* impl = reinterpret_cast<ContextImpl*>(arg);
  SSL* ssl = reinterpret_cast<SSL*>(
      X509_STORE_CTX_get_ex_data(store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));

  X509* cert = X509_STORE_CTX_get_current_cert(store_ctx);
  if (cert == nullptr) {
    cert = X509_STORE_CTX_get0_cert(store_ctx);
  }
  auto transport_socket_options_shared_ptr_ptr =
      static_cast<const Network::TransportSocketOptionsConstSharedPtr*>(SSL_get_app_data(ssl));
  ASSERT(transport_socket_options_shared_ptr_ptr);
  const Network::TransportSocketOptions* transport_socket_options =
      (*transport_socket_options_shared_ptr_ptr).get();
  return impl->cert_validator_->doSynchronousVerifyCertChain(
      store_ctx,
      reinterpret_cast<Envoy::Ssl::SslExtendedSocketInfo*>(
          SSL_get_ex_data(ssl, ContextImpl::sslExtendedSocketInfoIndex())),
      *cert, transport_socket_options);
}

void ContextImpl::incCounter(const Stats::StatName name, absl::string_view value,
                             const Stats::StatName fallback) const {
  const Stats::StatName value_stat_name = stat_name_set_->getBuiltin(value, fallback);
  ENVOY_BUG(value_stat_name != fallback,
            absl::StrCat("Unexpected ", scope_.symbolTable().toString(name), " value: ", value));
  Stats::Utility::counterFromElements(scope_, {name, value_stat_name}).inc();
}

void ContextImpl::logHandshake(SSL* ssl) const {
  stats_.handshake_.inc();

  if (SSL_session_reused(ssl)) {
    stats_.session_reused_.inc();
  }

  incCounter(ssl_ciphers_, SSL_get_cipher_name(ssl), unknown_ssl_cipher_);
  incCounter(ssl_versions_, SSL_get_version(ssl), unknown_ssl_version_);

  // uint16_t curve_id = SSL_get_curve_id(ssl);
  // if (curve_id) {
  //  incCounter(ssl_curves_, SSL_get_curve_name(curve_id), unknown_ssl_curve_);
  //}
  int group = SSL_get_shared_group(ssl, NULL);
  if (group > 0) {
    switch (group) {
    case NID_X25519:
      incCounter(ssl_curves_, "X25519", unknown_ssl_curve_);
      break;
    case NID_X9_62_prime256v1:
      incCounter(ssl_curves_, "P-256", unknown_ssl_curve_);
      break;
    default:
      incCounter(ssl_curves_, "", unknown_ssl_curve_);
      // case NID_secp384r1: {
      //	scope_.counter(fmt::format("ssl.curves.{}", "P-384")).inc();
      //} break;
    }
  }

  // TODO (dmitri-d) sort out ssl_sigalgs_ stats
  // uint16_t sigalg_id = SSL_get_peer_signature_algorithm(ssl);
  // if (sigalg_id) {
  //  const char *sigalg = SSL_get_signature_algorithm_name(sigalg_id, 1 /* include curve */);
  //  incCounter(ssl_sigalgs_, sigalg, unknown_ssl_algorithm_);
  //}

  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl));
  if (!cert.get()) {
    stats_.no_certificate_.inc();
  }
}

std::vector<Ssl::PrivateKeyMethodProviderSharedPtr> ContextImpl::getPrivateKeyMethodProviders() {
  std::vector<Envoy::Ssl::PrivateKeyMethodProviderSharedPtr> providers;

  for (auto& cert : tls_context_.cert_contexts_) {
    Envoy::Ssl::PrivateKeyMethodProviderSharedPtr provider = cert.getPrivateKeyMethodProvider();
    if (provider) {
      providers.push_back(provider);
    }
  }
  return providers;
}

absl::optional<uint32_t> ContextImpl::daysUntilFirstCertExpires() const {
  absl::optional<uint32_t> daysUntilExpiration = cert_validator_->daysUntilFirstCertExpires();
  if (!daysUntilExpiration.has_value()) {
    return absl::nullopt;
  }
  for (auto& ctx : tls_context_.cert_contexts_) {
    const absl::optional<uint32_t> tmp =
        Utility::getDaysUntilExpiration(ctx.cert_chain_.get(), time_source_);
    if (!tmp.has_value()) {
      return absl::nullopt;
    }
    daysUntilExpiration = std::min<uint32_t>(tmp.value(), daysUntilExpiration.value());
  }
  return daysUntilExpiration;
}

absl::optional<uint64_t> ContextImpl::secondsUntilFirstOcspResponseExpires() const {
  absl::optional<uint64_t> secs_until_expiration;
  for (auto& cert : tls_context_.cert_contexts_) {
    if (cert.ocsp_response_) {
      uint64_t next_expiration = cert.ocsp_response_->secondsUntilExpiration();
      secs_until_expiration = std::min<uint64_t>(
          next_expiration, secs_until_expiration.value_or(std::numeric_limits<uint64_t>::max()));
    }
  }

  return secs_until_expiration;
}

Envoy::Ssl::CertificateDetailsPtr ContextImpl::getCaCertInformation() const {
  return cert_validator_->getCaCertInformation();
}

std::vector<Envoy::Ssl::CertificateDetailsPtr> ContextImpl::getCertChainInformation() const {
  std::vector<Envoy::Ssl::CertificateDetailsPtr> cert_details;
  for (auto& cert : tls_context_.cert_contexts_) {
    if (cert.cert_chain_ == nullptr) {
      continue;
    }

    auto detail = Utility::certificateDetails(cert.cert_chain_.get(), cert.getCertChainFileName(),
                                              time_source_);
    auto ocsp_resp = cert.ocsp_response_.get();
    if (ocsp_resp) {
      auto* ocsp_details = detail->mutable_ocsp_details();
      ProtobufWkt::Timestamp* valid_from = ocsp_details->mutable_valid_from();
      TimestampUtil::systemClockToTimestamp(ocsp_resp->getThisUpdate(), *valid_from);
      ProtobufWkt::Timestamp* expiration = ocsp_details->mutable_expiration();
      TimestampUtil::systemClockToTimestamp(ocsp_resp->getNextUpdate(), *expiration);
    }
    cert_details.push_back(std::move(detail));
  }
  return cert_details;
}

ClientContextImpl::ClientContextImpl(Stats::Scope& scope,
                                     const Envoy::Ssl::ClientContextConfig& config,
                                     TimeSource& time_source)
    : ContextImpl(scope, config, time_source),
      server_name_indication_(config.serverNameIndication()),
      allow_renegotiation_(config.allowRenegotiation()),
      max_session_keys_(config.maxSessionKeys()) {
  if (!parsed_alpn_protocols_.empty()) {
    const int rc = SSL_CTX_set_alpn_protos(
        tls_context_.ssl_ctx_.get(), parsed_alpn_protocols_.data(), parsed_alpn_protocols_.size());
    RELEASE_ASSERT(rc == 0, Utility::getLastCryptoError().value_or(""));
  }

  if (!config.signingAlgorithmsForTest().empty()) {
    const uint16_t sigalgs = parseSigningAlgorithmsForTest(config.signingAlgorithmsForTest());
    RELEASE_ASSERT(sigalgs != 0, fmt::format("unsupported signing algorithm {}",
                                             config.signingAlgorithmsForTest()));

    // TODO (dmitri-d) verify this
    // const int rc = SSL_CTX_set_verify_algorithm_prefs(tls_context_.ssl_ctx_.get(), &sigalgs, 1);
    const int rc = SSL_CTX_set1_sigalgs_list(tls_context_.ssl_ctx_.get(),
                                             config.signingAlgorithmsForTest().c_str());
    RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
  }

  if (max_session_keys_ > 0) {
    SSL_CTX_set_session_cache_mode(tls_context_.ssl_ctx_.get(), SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(tls_context_.ssl_ctx_.get(), [](SSL* ssl, SSL_SESSION* session) -> int {
      ContextImpl* context_impl =
          static_cast<ContextImpl*>(SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
      ClientContextImpl* client_context_impl = dynamic_cast<ClientContextImpl*>(context_impl);
      RELEASE_ASSERT(client_context_impl != nullptr, ""); // for Coverity
      return client_context_impl->newSessionKey(session);
    });
  }
}

bool ContextImpl::parseAndSetAlpn(const std::vector<std::string>& alpn, SSL& ssl) {
  std::vector<uint8_t> parsed_alpn = parseAlpnProtocols(absl::StrJoin(alpn, ","));
  if (!parsed_alpn.empty()) {
    const int rc = SSL_set_alpn_protos(&ssl, parsed_alpn.data(), parsed_alpn.size());
    // This should only if memory allocation fails, e.g. OOM.
    RELEASE_ASSERT(rc == 0, Utility::getLastCryptoError().value_or(""));
    return true;
  }

  return false;
}

bssl::UniquePtr<SSL>
ClientContextImpl::newSsl(const Network::TransportSocketOptionsConstSharedPtr& options) {
  bssl::UniquePtr<SSL> ssl_con(ContextImpl::newSsl(options));

  const std::string server_name_indication = options && options->serverNameOverride().has_value()
                                                 ? options->serverNameOverride().value()
                                                 : server_name_indication_;

  if (!server_name_indication.empty()) {
    const int rc = SSL_set_tlsext_host_name(ssl_con.get(), server_name_indication.c_str());
    RELEASE_ASSERT(rc, Utility::getLastCryptoError().value_or(""));
  }

  if (options && !options->verifySubjectAltNameListOverride().empty()) {
    SSL_set_verify(ssl_con.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
  }

  // We determine what ALPN using the following precedence:
  // 1. Option-provided ALPN override.
  // 2. ALPN statically configured in the upstream TLS context.
  // 3. Option-provided ALPN fallback.

  // At this point in the code the ALPN has already been set (if present) to the value specified in
  // the TLS context. We've stored this value in parsed_alpn_protocols_ so we can check that to see
  // if it's already been set.
  bool has_alpn_defined = !parsed_alpn_protocols_.empty();
  if (options) {
    // ALPN override takes precedence over TLS context specified, so blindly overwrite it.
    has_alpn_defined |= parseAndSetAlpn(options->applicationProtocolListOverride(), *ssl_con);
  }

  if (options && !has_alpn_defined && !options->applicationProtocolFallback().empty()) {
    // If ALPN hasn't already been set (either through TLS context or override), use the fallback.
    parseAndSetAlpn(options->applicationProtocolFallback(), *ssl_con);
  }

  if (allow_renegotiation_) {
    Envoy::Extensions::TransportSockets::Tls::allowRenegotiation(ssl_con.get());
  }

  if (max_session_keys_ > 0) {
    if (session_keys_single_use_) {
      // Stored single-use session keys, use write/write locks.
      absl::WriterMutexLock l(&session_keys_mu_);
      if (!session_keys_.empty()) {
        // Use the most recently stored session key, since it has the highest
        // probability of still being recognized/accepted by the server.
        SSL_SESSION* session = session_keys_.front().get();
        SSL_set_session(ssl_con.get(), session);
        // Remove single-use session key (TLS 1.3) after first use.
        if (Envoy::Extensions::TransportSockets::Tls::should_be_single_use(session)) {
          session_keys_.pop_front();
        }
      }
    } else {
      // Never stored single-use session keys, use read/write locks.
      absl::ReaderMutexLock l(&session_keys_mu_);
      if (!session_keys_.empty()) {
        // Use the most recently stored session key, since it has the highest
        // probability of still being recognized/accepted by the server.
        SSL_SESSION* session = session_keys_.front().get();
        SSL_set_session(ssl_con.get(), session);
      }
    }
  }

  return ssl_con;
}

int ClientContextImpl::newSessionKey(SSL_SESSION* session) {
  // In case we ever store single-use session key (TLS 1.3),
  // we need to switch to using write/write locks.
  if (Envoy::Extensions::TransportSockets::Tls::should_be_single_use(session)) {
    session_keys_single_use_ = true;
  }
  absl::WriterMutexLock l(&session_keys_mu_);
  // Evict oldest entries.
  while (session_keys_.size() >= max_session_keys_) {
    session_keys_.pop_back();
  }
  // Add new session key at the front of the queue, so that it's used first.
  session_keys_.push_front(bssl::UniquePtr<SSL_SESSION>(session));
  return 1; // Tell BoringSSL that we took ownership of the session.
}

uint16_t ClientContextImpl::parseSigningAlgorithmsForTest(const std::string& sigalgs) {
  // This is used only when testing RSA/ECDSA certificate selection, so only the signing algorithms
  // used in tests are supported here.
  if (sigalgs == "rsa_pss_rsae_sha256") {
    return 0x0804; // SSL_SIGN_RSA_PSS_RSAE_SHA256
  } else if (sigalgs == "ecdsa_secp256r1_sha256") {
    return 0x0403; // SSL_SIGN_ECDSA_SECP256R1_SHA256
  }
  return 0;
}

ServerContextImpl::ServerContextImpl(Stats::Scope& scope,
                                     const Envoy::Ssl::ServerContextConfig& config,
                                     const std::vector<std::string>& server_names,
                                     TimeSource& time_source)
    : ContextImpl(scope, config, time_source), session_ticket_keys_(config.sessionTicketKeys()),
      ocsp_staple_policy_(config.ocspStaplePolicy()) {
  if (config.tlsCertificates().empty() && !config.capabilities().provides_certificates) {
    throw EnvoyException("Server TlsCertificates must have a certificate specified");
  }

  // Compute the session context ID hash. We use all the certificate identities,
  // since we should have a common ID for session resumption no matter what cert
  // is used. We do this early because it can throw an EnvoyException.
  const SessionContextID session_id = generateHashForSessionContextId(server_names);

  const auto tls_certificates = config.tlsCertificates();
  if (!config.capabilities().verifies_peer_certificates) {
    cert_validator_->addClientValidationContext(tls_context_.ssl_ctx_.get(),
                                                config.requireClientCertificate());
  }

  if (!parsed_alpn_protocols_.empty() && !config.capabilities().handles_alpn_selection) {
    SSL_CTX_set_alpn_select_cb(
        tls_context_.ssl_ctx_.get(),
        [](SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in,
           unsigned int inlen, void* arg) -> int {
          return static_cast<ServerContextImpl*>(arg)->alpnSelectCallback(out, outlen, in, inlen);
        },
        this);
  }

  // If the handshaker handles session tickets natively, don't call
  // `SSL_CTX_set_tlsext_ticket_key_cb`.
  if (config.disableStatelessSessionResumption()) {
    SSL_CTX_set_options(tls_context_.ssl_ctx_.get(), SSL_OP_NO_TICKET);
  } else if (!session_ticket_keys_.empty() && !config.capabilities().handles_alpn_selection) {
    SSL_CTX_set_tlsext_ticket_key_cb(
        tls_context_.ssl_ctx_.get(),
        +[](SSL* ssl, uint8_t* key_name, uint8_t* iv, EVP_CIPHER_CTX* ctx, HMAC_CTX* hmac_ctx,
            int encrypt) -> int {
          ContextImpl* context_impl =
              static_cast<ContextImpl*>(SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
          ServerContextImpl* server_context_impl = dynamic_cast<ServerContextImpl*>(context_impl);
          RELEASE_ASSERT(server_context_impl != nullptr, ""); // for Coverity
          return server_context_impl->sessionTicketProcess(ssl, key_name, iv, ctx, hmac_ctx,
                                                           encrypt);
        });
  }

  if (config.sessionTimeout() && !config.capabilities().handles_session_resumption) {
    auto timeout = config.sessionTimeout().value().count();
    SSL_CTX_set_timeout(tls_context_.ssl_ctx_.get(), uint32_t(timeout));
  }

  int rc = SSL_CTX_set_session_id_context(tls_context_.ssl_ctx_.get(), session_id.data(),
                                          session_id.size());
  RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));

  for (uint32_t i = 0; i < tls_certificates.size(); ++i) {
    auto& ocsp_resp_bytes = tls_certificates[i].get().ocspStaple();
    if (ocsp_resp_bytes.empty()) {
      if (tls_context_.cert_contexts_[i].is_must_staple_) {
        throw EnvoyException("OCSP response is required for must-staple certificate");
      }
      if (ocsp_staple_policy_ == Ssl::ServerContextConfig::OcspStaplePolicy::MustStaple) {
        throw EnvoyException("Required OCSP response is missing from TLS context");
      }
    } else {
      auto response = std::make_unique<Ocsp::OcspResponseWrapper>(ocsp_resp_bytes, time_source_);
      if (!response->matchesCertificate(*tls_context_.cert_contexts_[i].cert_chain_)) {
        throw EnvoyException("OCSP response does not match its TLS certificate");
      }
      tls_context_.cert_contexts_[i].ocsp_response_ = std::move(response);
    }
  }

  // this and the next call always succeed
  SSL_CTX_set_tlsext_status_cb(
      tls_context_.ssl_ctx_.get(), +[](SSL* ssl, void* arg) -> int {
        return static_cast<ServerContextImpl*>(arg)->handleOcspStapling(ssl, arg);
      });
  SSL_CTX_set_tlsext_status_arg(tls_context_.ssl_ctx_.get(), this);
}

ServerContextImpl::SessionContextID
ServerContextImpl::generateHashForSessionContextId(const std::vector<std::string>& server_names) {
  uint8_t hash_buffer[EVP_MAX_MD_SIZE];
  unsigned hash_length = 0;

  bssl::ScopedEVP_MD_CTX md;

  int rc = EVP_DigestInit(md.get(), EVP_sha256());
  RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));

  // Hash the CommonName/SANs of all the server certificates. This makes sure that sessions can only
  // be resumed to certificate(s) for the same name(s), but allows resuming to unique certs in the
  // case that different Envoy instances each have their own certs. All certificates in a
  // ServerContextImpl context are hashed together, since they all constitute a match on a filter
  // chain for resumption purposes.
  if (!capabilities_.provides_certificates) {
    X509* cert = SSL_CTX_get0_certificate(tls_context_.ssl_ctx_.get());
    RELEASE_ASSERT(cert != nullptr, "TLS context should have an active certificate");
    X509_NAME* cert_subject = X509_get_subject_name(cert);
    RELEASE_ASSERT(cert_subject != nullptr, "TLS certificate should have a subject");

    const int cn_index = X509_NAME_get_index_by_NID(cert_subject, NID_commonName, -1);
    if (cn_index >= 0) {
      X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(cert_subject, cn_index);
      RELEASE_ASSERT(cn_entry != nullptr, "certificate subject CN should be present");

      ASN1_STRING* cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
      if (ASN1_STRING_length(cn_asn1) <= 0) {
        throw EnvoyException("Invalid TLS context has an empty subject CN");
      }

      rc = EVP_DigestUpdate(md.get(), ASN1_STRING_data(cn_asn1), ASN1_STRING_length(cn_asn1));
      RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
    }

    unsigned san_count = 0;
    bssl::UniquePtr<GENERAL_NAMES> san_names(static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)));

    if (san_names != nullptr) {
      for (const GENERAL_NAME* san : san_names.get()) {
        switch (san->type) {
        case GEN_IPADD:
          rc = EVP_DigestUpdate(md.get(), san->d.iPAddress->data, san->d.iPAddress->length);
          RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
          ++san_count;
          break;
        case GEN_DNS:
          rc = EVP_DigestUpdate(md.get(), ASN1_STRING_data(san->d.dNSName),
                                ASN1_STRING_length(san->d.dNSName));
          RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
          ++san_count;
          break;
        case GEN_URI:
          rc = EVP_DigestUpdate(md.get(), ASN1_STRING_data(san->d.uniformResourceIdentifier),
                                ASN1_STRING_length(san->d.uniformResourceIdentifier));
          RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
          ++san_count;
          break;
        }
      }
    }

    // It's possible that the certificate doesn't have a subject, but
    // does have SANs. Make sure that we have one or the other.
    if (cn_index < 0 && san_count == 0) {
      throw EnvoyException("Invalid TLS context has neither subject CN nor SAN names");
    }

    rc = X509_NAME_digest(X509_get_issuer_name(cert), EVP_sha256(), hash_buffer, &hash_length);
    RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
    RELEASE_ASSERT(hash_length == SHA256_DIGEST_LENGTH,
                   fmt::format("invalid SHA256 hash length {}", hash_length));

    rc = EVP_DigestUpdate(md.get(), hash_buffer, hash_length);
    RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
  }

  cert_validator_->updateDigestForSessionId(md, hash_buffer, hash_length);

  // Hash configured SNIs for this context, so that sessions cannot be resumed across different
  // filter chains, even when using the same server certificate.
  for (const auto& name : server_names) {
    rc = EVP_DigestUpdate(md.get(), name.data(), name.size());
    RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
  }

  SessionContextID session_id;

  // Ensure that the output size of the hash we are using is no greater than
  // TLS session ID length that we want to generate.
  static_assert(session_id.size() == SHA256_DIGEST_LENGTH, "hash size mismatch");
  static_assert(session_id.size() == SSL_MAX_SSL_SESSION_ID_LENGTH, "TLS session ID size mismatch");

  rc = EVP_DigestFinal(md.get(), session_id.data(), &hash_length);
  RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
  RELEASE_ASSERT(hash_length == session_id.size(),
                 "SHA256 hash length must match TLS Session ID size");

  return session_id;
}

int ServerContextImpl::sessionTicketProcess(SSL*, uint8_t* key_name, uint8_t* iv,
                                            EVP_CIPHER_CTX* ctx, HMAC_CTX* hmac_ctx, int encrypt) {
  const EVP_MD* hmac = EVP_sha256();
  const EVP_CIPHER* cipher = EVP_aes_256_cbc();

  if (encrypt == 1) {
    // Encrypt
    RELEASE_ASSERT(!session_ticket_keys_.empty(), "");
    // TODO(ggreenway): validate in SDS that session_ticket_keys_ cannot be empty,
    // or if we allow it to be emptied, reconfigure the context so this callback
    // isn't set.

    const Envoy::Ssl::ServerContextConfig::SessionTicketKey& key = session_ticket_keys_.front();

    static_assert(std::tuple_size<decltype(key.name_)>::value == SSL_TICKET_KEY_NAME_LEN,
                  "Expected key.name length");
    std::copy_n(key.name_.begin(), SSL_TICKET_KEY_NAME_LEN, key_name);

    const int rc = RAND_bytes(iv, EVP_CIPHER_iv_length(cipher));
    ASSERT(rc);

    // This RELEASE_ASSERT is logically a static_assert, but we can't actually get
    // EVP_CIPHER_key_length(cipher) at compile-time
    // Remove for now because of integer type mismatch.
    // RELEASE_ASSERT(key.aes_key_.size() == EVP_CIPHER_key_length(cipher), "");
    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, key.aes_key_.data(), iv)) {
      return -1;
    }

    if (!HMAC_Init_ex(hmac_ctx, key.hmac_key_.data(), key.hmac_key_.size(), hmac, nullptr)) {
      return -1;
    }

    return 1; // success
  } else {
    // Decrypt
    bool is_enc_key = true; // first element is the encryption key
    for (const Envoy::Ssl::ServerContextConfig::SessionTicketKey& key : session_ticket_keys_) {
      static_assert(std::tuple_size<decltype(key.name_)>::value == SSL_TICKET_KEY_NAME_LEN,
                    "Expected key.name length");
      if (std::equal(key.name_.begin(), key.name_.end(), key_name)) {
        if (!HMAC_Init_ex(hmac_ctx, key.hmac_key_.data(), key.hmac_key_.size(), hmac, nullptr)) {
          return -1;
        }

        // Remove for now because of integer type mismatch.
        // RELEASE_ASSERT(key.aes_key_.size() == EVP_CIPHER_key_length(cipher), "");
        if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, key.aes_key_.data(), iv)) {
          return -1;
        }

        // If our current encryption was not the decryption key, renew
        return is_enc_key ? 1  // success; do not renew
                          : 2; // success: renew key
      }
      is_enc_key = false;
    }

    return 0; // decryption failed
  }
}

bool ServerContextImpl::isClientOcspCapable(SSL* ssl) {
  if (TLSEXT_STATUSTYPE_ocsp == SSL_get_tlsext_status_type(ssl)) {
    return true;
  }

  return false;
}

const CertContext& ServerContextImpl::certificateContext(X509* cert) {
  const auto matched_cert = tls_context_.cert_context_lookup_.find(certificateDigest(cert));
  RELEASE_ASSERT(matched_cert != tls_context_.cert_context_lookup_.end(), "");
  return matched_cert->second.get();
}

OcspStapleAction ServerContextImpl::ocspStapleAction(const CertContext& cert_context,
                                                     bool client_ocsp_capable) {
  if (!client_ocsp_capable) {
    return OcspStapleAction::ClientNotCapable;
  }

  auto& response = cert_context.ocsp_response_;

  auto policy = ocsp_staple_policy_;
  if (cert_context.is_must_staple_) {
    // The certificate has the must-staple extension, so upgrade the policy to match.
    policy = Ssl::ServerContextConfig::OcspStaplePolicy::MustStaple;
  }

  const bool valid_response = response && !response->isExpired();

  switch (policy) {
  case Ssl::ServerContextConfig::OcspStaplePolicy::LenientStapling:
    if (!valid_response) {
      return OcspStapleAction::NoStaple;
    }
    return OcspStapleAction::Staple;

  case Ssl::ServerContextConfig::OcspStaplePolicy::StrictStapling:
    if (valid_response) {
      return OcspStapleAction::Staple;
    }
    if (response) {
      // Expired response.
      return OcspStapleAction::Fail;
    }
    return OcspStapleAction::NoStaple;

  case Ssl::ServerContextConfig::OcspStaplePolicy::MustStaple:
    if (!valid_response) {
      return OcspStapleAction::Fail;
    }
    return OcspStapleAction::Staple;
  }
  PANIC_DUE_TO_CORRUPT_ENUM;
}

int ServerContextImpl::handleOcspStapling(SSL* ssl, void*) {
  const bool client_ocsp_capable = isClientOcspCapable(ssl);
  
  // Loop on all certificates to find at least a good one
  const CertContext* selected_cert_context = nullptr;
  auto  ocsp_staple_action = OcspStapleAction::Fail;
  for(const auto& cert_context : tls_context_.cert_contexts_) {
    RELEASE_ASSERT(SSL_select_current_cert(ssl,cert_context.cert_chain_.get()),
		  "SSL_select_current_cert() failure");
    ocsp_staple_action = ocspStapleAction(cert_context, client_ocsp_capable);
    if (ocsp_staple_action == OcspStapleAction::Fail) {
      continue;
    }
    selected_cert_context = &cert_context;
    break;
  }

  switch (ocsp_staple_action) {
  case OcspStapleAction::Staple: {
    // We avoid setting the OCSP response if the client didn't request it, but doing so is safe.
    RELEASE_ASSERT(selected_cert_context->ocsp_response_,
                   "OCSP response must be present under OcspStapleAction::Staple");
    const std::vector<uint8_t>& raw_bytes = selected_cert_context->ocsp_response_->rawBytes();
    const std::size_t raw_bytes_size = raw_bytes.size();
    unsigned char* raw_bytes_copy = static_cast<unsigned char *>(OPENSSL_memdup(raw_bytes.data(), raw_bytes_size));
    if (raw_bytes_copy == nullptr) { 
      ENVOY_LOG_EVERY_POW_2_MISC(error, "OPENSSL_memdup failure");
      stats_.ocsp_staple_failed_.inc();
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    RELEASE_ASSERT(SSL_set_tlsext_status_ocsp_resp(ssl, raw_bytes_copy, raw_bytes_size),
                   "SSL_set_tlsext_status_ocsp_resp failure");
    stats_.ocsp_staple_responses_.inc();
  }
    return SSL_TLSEXT_ERR_OK;
  case OcspStapleAction::NoStaple:
    stats_.ocsp_staple_omitted_.inc();
    return SSL_TLSEXT_ERR_NOACK;
  case OcspStapleAction::Fail:
    stats_.ocsp_staple_failed_.inc();
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  case OcspStapleAction::ClientNotCapable:
    return SSL_TLSEXT_ERR_NOACK;
  }
  return SSL_TLSEXT_ERR_OK;
}

bool ContextImpl::verifyCertChain(X509& leaf_cert, STACK_OF(X509) & intermediates,
                                  std::string& error_details) {
  bssl::UniquePtr<X509_STORE_CTX> ctx(X509_STORE_CTX_new());

  const SSL_CTX* ssl_ctx = tls_context_.ssl_ctx_.get();
  X509_STORE* store = SSL_CTX_get_cert_store(ssl_ctx);
  if (!X509_STORE_CTX_init(ctx.get(), store, &leaf_cert, &intermediates)) {
    error_details = "Failed to verify certificate chain: X509_STORE_CTX_init";
    return false;
  }
  // Currently this method is only used to verify server certs, so hard-code "ssl_server" for now.
  if (!X509_STORE_CTX_set_default(ctx.get(), "ssl_server") ||
      !X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(ctx.get()),
                              SSL_CTX_get0_param(const_cast<SSL_CTX*>(ssl_ctx)))) {
    error_details =
        "Failed to verify certificate chain: fail to setup X509_STORE_CTX or its param.";
    return false;
  }

  int res = cert_validator_->doSynchronousVerifyCertChain(ctx.get(), nullptr, leaf_cert, nullptr);
  // If |SSL_VERIFY_NONE|, the error is non-fatal, but we keep the error details.
  if (res <= 0 && SSL_CTX_get_verify_mode(ssl_ctx) != SSL_VERIFY_NONE) {
    error_details = Utility::getX509VerificationErrorInfo(ctx.get());
    return false;
  }
  return true;
}

void TlsContext::loadCertificateChain(const uint32_t cert_index, const std::string& data, const std::string& data_path) {
  cert_contexts_[cert_index].cert_chain_file_path_ = data_path;
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(const_cast<char*>(data.data()), data.size()));
  RELEASE_ASSERT(bio != nullptr, "");
  cert_contexts_[cert_index].cert_chain_.reset(PEM_read_bio_X509_AUX(bio.get(), nullptr, nullptr, nullptr));
  if (cert_contexts_[cert_index].cert_chain_ == nullptr || !SSL_CTX_use_certificate(ssl_ctx_.get(), cert_contexts_[cert_index].cert_chain_.get())) {
    logSslErrorChain();
    throw EnvoyException(
        absl::StrCat("Failed to load certificate chain from ", cert_contexts_[cert_index].cert_chain_file_path_));
  }
  // Read rest of the certificate chain.
  while (true) {
    bssl::UniquePtr<X509> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (cert == nullptr) {
      break;
    }
    if (!SSL_CTX_add_extra_chain_cert(ssl_ctx_.get(), cert.get())) {
      throw EnvoyException(
          absl::StrCat("Failed to load certificate chain from ", cert_contexts_[cert_index].cert_chain_file_path_));
    }
    // SSL_CTX_add_extra_chain_cert() takes ownership.
    cert.release();
  }
  // Check for EOF.
  const uint32_t err = ERR_peek_last_error();
  if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
    ERR_clear_error();
  } else {
    throw EnvoyException(
        absl::StrCat("Failed to load certificate chain from ", cert_contexts_[cert_index].cert_chain_file_path_));
  }
}

void TlsContext::loadPrivateKey(const std::string& data, const std::string& data_path,
                                const std::string& password) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(const_cast<char*>(data.data()), data.size()));
  RELEASE_ASSERT(bio != nullptr, "");
  bssl::UniquePtr<EVP_PKEY> pkey(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr,
                              !password.empty() ? const_cast<char*>(password.c_str()) : nullptr));

  if (pkey == nullptr || !SSL_CTX_use_PrivateKey(ssl_ctx_.get(), pkey.get())) {
    throw EnvoyException(fmt::format("Failed to load private key from {}, Cause: {}", data_path,
                                     Utility::getLastCryptoError().value_or("unknown")));
  }

  checkPrivateKey(pkey, data_path);
}


void TlsContext::loadPkcs12(const uint32_t cert_index, 
                            const std::string& data, 
                            const std::string& data_path,
                            const std::string& password) {
  cert_contexts_[cert_index].cert_chain_file_path_ = data_path;
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(const_cast<char*>(data.data()), data.size()));
  RELEASE_ASSERT(bio != nullptr, "");
  bssl::UniquePtr<PKCS12> pkcs12(d2i_PKCS12_bio(bio.get(), nullptr));

  EVP_PKEY* temp_private_key = nullptr;
  X509* temp_cert = nullptr;
  STACK_OF(X509)* temp_ca_certs = nullptr;
  if (pkcs12 == nullptr ||
      !PKCS12_parse(pkcs12.get(), !password.empty() ? const_cast<char*>(password.c_str()) : nullptr,
                    &temp_private_key, &temp_cert, &temp_ca_certs)) {
    logSslErrorChain();
    throw EnvoyException(absl::StrCat("Failed to load pkcs12 from ", data_path));
  }
  cert_contexts_[cert_index].cert_chain_.reset(temp_cert);
  bssl::UniquePtr<EVP_PKEY> pkey(temp_private_key);
  bssl::UniquePtr<STACK_OF(X509)> ca_certificates(temp_ca_certs);
  if (ca_certificates != nullptr) {
    X509* ca_cert = nullptr;
    while ((ca_cert = sk_X509_pop(ca_certificates.get())) != nullptr) {
      // This transfers ownership to ssl_ctx therefore ca_cert does not need to be freed.
      SSL_CTX_add_extra_chain_cert(ssl_ctx_.get(), ca_cert);
    }
  }
  if (!SSL_CTX_use_certificate(ssl_ctx_.get(), cert_contexts_[cert_index].cert_chain_.get())) {
    logSslErrorChain();
    throw EnvoyException(absl::StrCat("Failed to load certificate from ", data_path));
  }
  if (temp_private_key == nullptr || !SSL_CTX_use_PrivateKey(ssl_ctx_.get(), pkey.get())) {
    throw EnvoyException(fmt::format("Failed to load private key from {}, Cause: {}", data_path,
                                     Utility::getLastCryptoError().value_or("unknown")));
  }

  checkPrivateKey(pkey, data_path);
}


void TlsContext::checkPrivateKey(const bssl::UniquePtr<EVP_PKEY>& pkey,
                                 const std::string& key_path) {
#ifdef BORINGSSL_FIPS
  // Verify that private keys are passing FIPS pairwise consistency tests.
  switch (EVP_PKEY_id(pkey.get())) {
  case EVP_PKEY_EC: {
    const EC_KEY* ecdsa_private_key = EVP_PKEY_get0_EC_KEY(pkey.get());
    if (!EC_KEY_check_fips(ecdsa_private_key)) {
      throw EnvoyException(fmt::format("Failed to load private key from {}, ECDSA key failed "
                                       "pairwise consistency test required in FIPS mode",
                                       key_path));
    }
  } break;
  case EVP_PKEY_RSA: {
    RSA* rsa_private_key = EVP_PKEY_get0_RSA(pkey.get());
    if (!RSA_check_fips(rsa_private_key)) {
      throw EnvoyException(fmt::format("Failed to load private key from {}, RSA key failed "
                                       "pairwise consistency test required in FIPS mode",
                                       key_path));
    }
  } break;
  }
#else
  UNREFERENCED_PARAMETER(pkey);
  UNREFERENCED_PARAMETER(key_path);
#endif
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
