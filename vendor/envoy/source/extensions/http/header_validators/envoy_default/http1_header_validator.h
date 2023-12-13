#pragma once

#include "source/extensions/http/header_validators/envoy_default/header_validator.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

class Http1HeaderValidator : public HeaderValidator {
public:
  Http1HeaderValidator(
      const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig&
          config,
      ::Envoy::Http::Protocol protocol, ::Envoy::Http::HeaderValidatorStats& stats);

  RequestHeaderMapValidationResult
  validateRequestHeaderMap(::Envoy::Http::RequestHeaderMap& header_map) override;

  ResponseHeaderMapValidationResult
  validateResponseHeaderMap(::Envoy::Http::ResponseHeaderMap& header_map) override;

  TrailerValidationResult
  validateRequestTrailerMap(::Envoy::Http::RequestTrailerMap& trailer_map) override;

  TrailerValidationResult
  validateResponseTrailerMap(::Envoy::Http::ResponseTrailerMap& trailer_map) override;

  /*
   * Validate the Transfer-Encoding header.
   */
  HeaderValueValidationResult
  validateTransferEncodingHeader(const ::Envoy::Http::HeaderString& value) const;

private:
  HeaderEntryValidationResult validateRequestHeaderEntry(const ::Envoy::Http::HeaderString& key,
                                                         const ::Envoy::Http::HeaderString& value);

  HeaderEntryValidationResult validateResponseHeaderEntry(const ::Envoy::Http::HeaderString& key,
                                                          const ::Envoy::Http::HeaderString& value);

  const HeaderValidatorMap request_header_validator_map_;
};

using Http1HeaderValidatorPtr = std::unique_ptr<Http1HeaderValidator>;

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
