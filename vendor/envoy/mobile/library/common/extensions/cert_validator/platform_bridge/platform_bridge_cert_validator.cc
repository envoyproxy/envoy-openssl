#include "library/common/extensions/cert_validator/platform_bridge/platform_bridge_cert_validator.h"

#include <list>
#include <memory>
#include <type_traits>

#include "library/common/data/utility.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

PlatformBridgeCertValidator::PlatformBridgeCertValidator(
    const Envoy::Ssl::CertificateValidationContextConfig* config, SslStats& stats,
    const envoy_cert_validator* platform_validator)
    : allow_untrusted_certificate_(config != nullptr &&
                                   config->trustChainVerification() ==
                                       envoy::extensions::transport_sockets::tls::v3::
                                           CertificateValidationContext::ACCEPT_UNTRUSTED),
      platform_validator_(platform_validator), stats_(stats) {
  ENVOY_BUG(config != nullptr && config->caCert().empty() &&
                config->certificateRevocationList().empty(),
            "Invalid certificate validation context config.");
}

PlatformBridgeCertValidator::~PlatformBridgeCertValidator() {
  // Wait for validation threads to finish.
  for (auto& [id, job] : validation_jobs_) {
    if (job.validation_thread_.joinable()) {
      job.validation_thread_.join();
    }
  }
}

ValidationResults PlatformBridgeCertValidator::doVerifyCertChain(
    STACK_OF(X509) & cert_chain, Ssl::ValidateResultCallbackPtr callback,
    const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options,
    SSL_CTX& /*ssl_ctx*/, const CertValidator::ExtraValidationContext& /*validation_context*/,
    bool is_server, absl::string_view hostname) {
  ASSERT(!is_server);
  if (sk_X509_num(&cert_chain) == 0) {
    const char* error = "verify cert chain failed: empty cert chain.";
    stats_.fail_verify_error_.inc();
    ENVOY_LOG(debug, error);
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt, error};
  }
  if (callback == nullptr) {
    IS_ENVOY_BUG("No callback specified");
    const char* error = "verify cert chain failed: no callback specified.";
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt, error};
  }

  std::vector<envoy_data> certs;
  for (uint64_t i = 0; i < sk_X509_num(&cert_chain); i++) {
    X509* cert = sk_X509_value(&cert_chain, i);
    unsigned char* cert_in_der = nullptr;
    int der_length = i2d_X509(cert, &cert_in_der);
    ASSERT(der_length > 0 && cert_in_der != nullptr);

    absl::string_view cert_str(reinterpret_cast<char*>(cert_in_der),
                               static_cast<size_t>(der_length));
    certs.push_back(Data::Utility::copyToBridgeData(cert_str));
    OPENSSL_free(cert_in_der);
  }

  absl::string_view host;
  if (transport_socket_options != nullptr &&
      !transport_socket_options->verifySubjectAltNameListOverride().empty()) {
    host = transport_socket_options->verifySubjectAltNameListOverride()[0];
  } else {
    host = hostname;
  }

  std::vector<std::string> subject_alt_names;
  if (transport_socket_options != nullptr &&
      !transport_socket_options->verifySubjectAltNameListOverride().empty()) {
    subject_alt_names = transport_socket_options->verifySubjectAltNameListOverride();
  } else {
    subject_alt_names = {std::string(hostname)};
  }

  ValidationJob job;
  job.result_callback_ = std::move(callback);
  job.validation_thread_ = std::thread(&verifyCertChainByPlatform, platform_validator_,
                                       &(job.result_callback_->dispatcher()), std::move(certs),
                                       std::string(host), std::move(subject_alt_names), this);
  std::thread::id thread_id = job.validation_thread_.get_id();
  validation_jobs_[thread_id] = std::move(job);
  return {ValidationResults::ValidationStatus::Pending,
          Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt, absl::nullopt};
}

void PlatformBridgeCertValidator::verifyCertChainByPlatform(
    const envoy_cert_validator* platform_validator, Event::Dispatcher* dispatcher,
    std::vector<envoy_data> cert_chain, std::string hostname,
    std::vector<std::string> subject_alt_names, PlatformBridgeCertValidator* parent) {
  ASSERT(!cert_chain.empty());
  ENVOY_LOG(trace, "Start verifyCertChainByPlatform for host {}", hostname);
  // This is running in a stand alone thread other than the engine thread.
  envoy_data leaf_cert_der = cert_chain[0];
  bssl::UniquePtr<X509> leaf_cert(d2i_X509(
      nullptr, const_cast<const unsigned char**>(&leaf_cert_der.bytes), leaf_cert_der.length));
  envoy_cert_validation_result result =
      platform_validator->validate_cert(cert_chain.data(), cert_chain.size(), hostname.c_str());
  bool success = result.result == ENVOY_SUCCESS;
  if (!success) {
    ENVOY_LOG(debug, result.error_details);
    postVerifyResultAndCleanUp(success, std::move(hostname), result.error_details, result.tls_alert,
                               ValidationFailureType::FAIL_VERIFY_ERROR, platform_validator,
                               dispatcher, parent);
    return;
  }

  absl::string_view error_details;
  // Verify that host name matches leaf cert.
  success = DefaultCertValidator::verifySubjectAltName(leaf_cert.get(), subject_alt_names);
  if (!success) {
    error_details = "PlatformBridgeCertValidator_verifySubjectAltName failed: SNI mismatch.";
    ENVOY_LOG(debug, error_details);
    postVerifyResultAndCleanUp(success, std::move(hostname), error_details, SSL_AD_BAD_CERTIFICATE,
                               ValidationFailureType::FAIL_VERIFY_SAN, platform_validator,
                               dispatcher, parent);
    return;
  }
  postVerifyResultAndCleanUp(success, std::move(hostname), error_details,
                             SSL_AD_CERTIFICATE_UNKNOWN, ValidationFailureType::SUCCESS,
                             platform_validator, dispatcher, parent);
}

void PlatformBridgeCertValidator::postVerifyResultAndCleanUp(
    bool success, std::string hostname, absl::string_view error_details, uint8_t tls_alert,
    ValidationFailureType failure_type, const envoy_cert_validator* platform_validator,
    Event::Dispatcher* dispatcher, PlatformBridgeCertValidator* parent) {
  ENVOY_LOG(trace,
            "Finished platform cert validation for {}, post result callback to network thread",
            hostname);

  if (platform_validator->validation_cleanup) {
    platform_validator->validation_cleanup();
  }
  std::weak_ptr<size_t> weak_alive_indicator(parent->alive_indicator_);

  dispatcher->post([weak_alive_indicator, success, hostname = std::move(hostname),
                    error = std::string(error_details), tls_alert, failure_type,
                    thread_id = std::this_thread::get_id(), parent]() {
    if (weak_alive_indicator.expired()) {
      return;
    }
    parent->onVerificationComplete(thread_id, hostname, success, error, tls_alert, failure_type);
  });
}

void PlatformBridgeCertValidator::onVerificationComplete(std::thread::id thread_id,
                                                         std::string hostname, bool success,
                                                         std::string error, uint8_t tls_alert,
                                                         ValidationFailureType failure_type) {
  ENVOY_LOG(trace, "Got validation result for {} from platform", hostname);

  auto job_handle = validation_jobs_.extract(thread_id);
  if (job_handle.empty()) {
    IS_ENVOY_BUG("No job found for thread");
    return;
  }
  ValidationJob& job = job_handle.mapped();
  job.validation_thread_.join();

  Ssl::ClientValidationStatus detailed_status = Envoy::Ssl::ClientValidationStatus::NotValidated;
  switch (failure_type) {
  case ValidationFailureType::SUCCESS:
    detailed_status = Envoy::Ssl::ClientValidationStatus::Validated;
    break;
  case ValidationFailureType::FAIL_VERIFY_ERROR:
    detailed_status = Envoy::Ssl::ClientValidationStatus::Failed;
    stats_.fail_verify_error_.inc();
  case ValidationFailureType::FAIL_VERIFY_SAN:
    detailed_status = Envoy::Ssl::ClientValidationStatus::Failed;
    stats_.fail_verify_san_.inc();
  }

  job.result_callback_->onCertValidationResult(allow_untrusted_certificate_ || success,
                                               detailed_status, error, tls_alert);
  ENVOY_LOG(trace,
            "Finished platform cert validation for {}, post result callback to network thread",
            hostname);
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
