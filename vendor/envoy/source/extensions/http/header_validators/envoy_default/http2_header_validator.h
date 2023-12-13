#pragma once

#include "source/extensions/http/header_validators/envoy_default/header_validator.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

class Http2HeaderValidator : public HeaderValidator {
public:
  Http2HeaderValidator(
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
   * Validate the TE header.
   */
  HeaderValueValidationResult validateTEHeader(const ::Envoy::Http::HeaderString& value);

  /*
   * Validate the :authority pseudo header.
   */
  HeaderValueValidationResult validateAuthorityHeader(const ::Envoy::Http::HeaderString& value);

  /*
   * Validate the :protocol header.
   */
  HeaderValueValidationResult validateProtocolHeader(const ::Envoy::Http::HeaderString& value);

  HeaderEntryValidationResult
  validateGenericHeaderName(const ::Envoy::Http::HeaderString& name) override;

private:
  HeaderEntryValidationResult validateRequestHeaderEntry(const ::Envoy::Http::HeaderString& key,
                                                         const ::Envoy::Http::HeaderString& value);

  HeaderEntryValidationResult validateResponseHeaderEntry(const ::Envoy::Http::HeaderString& key,
                                                          const ::Envoy::Http::HeaderString& value);

  const HeaderValidatorMap request_header_validator_map_;
};

using Http2HeaderValidatorPtr = std::unique_ptr<Http2HeaderValidator>;

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
