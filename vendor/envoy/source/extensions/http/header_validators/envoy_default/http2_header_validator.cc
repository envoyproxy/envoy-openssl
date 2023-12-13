#include "source/extensions/http/header_validators/envoy_default/http2_header_validator.h"

#include "envoy/http/header_validator_errors.h"

#include "source/common/http/header_utility.h"
#include "source/extensions/http/header_validators/envoy_default/character_tables.h"

#include "absl/container/node_hash_map.h"
#include "absl/container/node_hash_set.h"
#include "absl/functional/bind_front.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

using ::envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig;
using ::Envoy::Http::HeaderString;
using ::Envoy::Http::HeaderUtility;
using ::Envoy::Http::LowerCaseString;
using ::Envoy::Http::Protocol;
using ::Envoy::Http::UhvResponseCodeDetail;
using HeaderValidatorFunction1 =
    HeaderValidator::HeaderValueValidationResult (Http2HeaderValidator::*)(const HeaderString&);

struct Http2ResponseCodeDetailValues {
  const std::string InvalidTE = "uhv.http2.invalid_te";
  const std::string ConnectionHeaderSanitization = "uhv.http2.connection_header_rejected";
};

using Http2ResponseCodeDetail = ConstSingleton<Http2ResponseCodeDetailValues>;

/*
 * Header validation implementation for the Http/2 codec. This class follows guidance from
 * several RFCS:
 *
 * RFC 3986 <https://datatracker.ietf.org/doc/html/rfc3986> URI Generic Syntax
 * RFC 9110 <https://www.rfc-editor.org/rfc/rfc9110.html> HTTP Semantics
 * RFC 9112 <https://www.rfc-editor.org/rfc/rfc9112.html> HTTP/1.1
 * RFC 9113 <https://www.rfc-editor.org/rfc/rfc9113.html> HTTP/2
 *
 */
Http2HeaderValidator::Http2HeaderValidator(const HeaderValidatorConfig& config, Protocol protocol,
                                           ::Envoy::Http::HeaderValidatorStats& stats)
    : HeaderValidator(config, protocol, stats),
      request_header_validator_map_{
          {":method", absl::bind_front(&HeaderValidator::validateMethodHeader, this)},
          {":authority", absl::bind_front(&Http2HeaderValidator::validateAuthorityHeader, this)},
          {":scheme", absl::bind_front(&HeaderValidator::validateSchemeHeader, this)},
          {":path", absl::bind_front(&HeaderValidator::validatePathHeaderCharacters, this)},
          {":protocol", absl::bind_front(&Http2HeaderValidator::validateProtocolHeader, this)},
          {"te", absl::bind_front(&Http2HeaderValidator::validateTEHeader, this)},
          {"content-length",
           absl::bind_front(&Http2HeaderValidator::validateContentLengthHeader, this)},
      } {}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateRequestHeaderEntry(const HeaderString& key,
                                                 const HeaderString& value) {
  return validateGenericRequestHeaderEntry(key, value, request_header_validator_map_);
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateResponseHeaderEntry(const HeaderString& key,
                                                  const HeaderString& value) {
  const auto& key_string_view = key.getStringView();
  if (key_string_view.empty()) {
    // reject empty header names
    return {HeaderEntryValidationResult::Action::Reject,
            UhvResponseCodeDetail::get().EmptyHeaderName};
  }

  if (key_string_view == ":status") {
    // Validate the :status header against the RFC valid range.
    return validateStatusHeader(value);
  } else if (key_string_view == "content-length") {
    // Validate the Content-Length header
    return validateContentLengthHeader(value);
  } else if (key_string_view.at(0) != ':') {
    auto name_result = validateGenericHeaderName(key);
    if (!name_result) {
      return name_result;
    }
  } else {
    // The only valid pseudo header for responses is :status. If the header name starts with ":"
    // and it's not ":status", then the header name is an unknown pseudo header.
    return {HeaderEntryValidationResult::Action::Reject,
            UhvResponseCodeDetail::get().InvalidPseudoHeader};
  }

  // Validate the header value
  return validateGenericHeaderValue(value);
}

::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult
Http2HeaderValidator::validateRequestHeaderMap(::Envoy::Http::RequestHeaderMap& header_map) {
  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeadersForConnect = {
      ":method", ":authority"};

  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeadersForExtendedConnect = {
      ":method", ":scheme", ":authority", ":path", ":protocol"};

  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeaders = {
      ":method", ":scheme", ":authority", ":path"};

  absl::string_view path = header_map.getPathValue();

  // Step 1: verify that required pseudo headers are present.
  //
  // The method pseudo header is always mandatory.
  if (header_map.getMethodValue().empty()) {
    stats_.incMessagingError();
    return {RequestHeaderMapValidationResult::Action::Reject,
            UhvResponseCodeDetail::get().InvalidMethod};
  }

  // The CONNECT method with the ":protocol" header is called the extended CONNECT and covered in
  // https://datatracker.ietf.org/doc/html/rfc8441#section-4
  // For the purposes of header validation the extended CONNECT is treated as generic (non CONNECT)
  // HTTP/2 requests.
  const bool is_standard_connect_request = HeaderUtility::isStandardConnectRequest(header_map);
  const bool is_extended_connect_request = HeaderUtility::isExtendedH2ConnectRequest(header_map);
  auto is_options_request = header_map.method() == header_values_.MethodValues.Options;
  bool path_is_empty = path.empty();
  bool path_is_asterisk = path == "*";
  bool path_is_absolute = !path_is_empty && path.at(0) == '/';

  if (!is_standard_connect_request && (header_map.getSchemeValue().empty() || path_is_empty)) {
    // If this is not a connect request, then we also need the scheme and path pseudo headers.
    // This is based on RFC 9113, https://www.rfc-editor.org/rfc/rfc9113#section-8.3.1:
    //
    // All HTTP/2 requests MUST include exactly one valid value for the ":method", ":scheme", and
    // ":path" pseudo-header fields, unless they are CONNECT requests (Section 8.5). An HTTP
    // request that omits mandatory pseudo-header fields is malformed (Section 8.1.1).
    auto details = path_is_empty ? UhvResponseCodeDetail::get().InvalidUrl
                                 : UhvResponseCodeDetail::get().InvalidScheme;
    return {RequestHeaderMapValidationResult::Action::Reject, details};
  } else if (is_standard_connect_request) {
    // If this is a CONNECT request, :path and :scheme must be empty and :authority must be
    // provided. This is based on RFC 9113,
    // https://www.rfc-editor.org/rfc/rfc9113#section-8.5:
    //
    //  * The ":method" pseudo-header field is set to CONNECT.
    //  * The ":scheme" and ":path" pseudo-header fields MUST be omitted.
    //  * The ":authority" pseudo-header field contains the host and port to connect to (equivalent
    //    to the authority-form of the request-target of CONNECT requests; see Section 3.2.3 of
    //    [HTTP/1.1]).
    absl::string_view details;
    if (!path_is_empty) {
      details = UhvResponseCodeDetail::get().InvalidUrl;
    } else if (!header_map.getSchemeValue().empty()) {
      details = UhvResponseCodeDetail::get().InvalidScheme;
    } else if (header_map.getHostValue().empty()) {
      details = UhvResponseCodeDetail::get().InvalidHost;
    }

    if (!details.empty()) {
      return {RequestHeaderMapValidationResult::Action::Reject, details};
    }
  }

  // Step 2: Validate and normalize the :path pseudo header
  if (!path_is_absolute && !is_standard_connect_request &&
      (!is_options_request || !path_is_asterisk)) {
    // The :path must be in absolute-form or, for an OPTIONS request, in asterisk-form. This is
    // based on RFC 9113, https://www.rfc-editor.org/rfc/rfc9113#section-8.3.1:
    //
    // This pseudo-header field MUST NOT be empty for "http" or "https" URIs; "http" or "https"
    // URIs that do not contain a path component MUST include a value of '/'. The exceptions to
    // this rule are:
    //
    // * an OPTIONS request for an "http" or "https" URI that does not include a path component;
    //   these MUST include a ":path" pseudo-header field with a value of '*' (see Section 7.1 of
    //   [HTTP]).
    // * CONNECT requests (Section 8.5), where the ":path" pseudo-header field is omitted.
    return {RequestHeaderMapValidationResult::Action::Reject,
            UhvResponseCodeDetail::get().InvalidUrl};
  }

  if (!config_.uri_path_normalization_options().skip_path_normalization() && !path_is_empty) {
    // Validate and normalize the path, which must be a valid URI. This is only run if the config
    // is active and the path is not empty.
    //
    // If path normalization is disabled then the path will be validated against the RFC character
    // set in validateRequestHeaderEntry.
    auto path_result = path_normalizer_.normalizePathUri(header_map);
    if (!path_result) {
      return path_result;
    }

    path = header_map.path();
  }

  // Step 3: Verify each request header
  const auto& allowed_headers =
      is_standard_connect_request
          ? kAllowedPseudoHeadersForConnect
          : (is_extended_connect_request ? kAllowedPseudoHeadersForExtendedConnect
                                         : kAllowedPseudoHeaders);
  std::string reject_details;
  std::vector<absl::string_view> drop_headers;

  // TODO(#23290) - Add support for detecting and validating duplicate headers. This would most
  // likely need to occur within the H2 codec because, at this point, duplicate headers have been
  // concatenated into a list.
  header_map.iterate(
      [this, &reject_details, &allowed_headers, &drop_headers](
          const ::Envoy::Http::HeaderEntry& header_entry) -> ::Envoy::Http::HeaderMap::Iterate {
        const auto& header_name = header_entry.key();
        const auto& header_value = header_entry.value();
        const auto& string_header_name = header_name.getStringView();
        bool is_pseudo_header =
            string_header_name.empty() ? false : string_header_name.at(0) == ':';

        if (is_pseudo_header && !allowed_headers.contains(string_header_name)) {
          // Reject unrecognized or unallowed pseudo header name, from RFC 9113,
          // https://www.rfc-editor.org/rfc/rfc9113#section-8.3:
          //
          // Pseudo-header fields are only valid in the context in which they are defined.
          // Pseudo-header fields defined for requests MUST NOT appear in responses; pseudo-header
          // fields defined for responses MUST NOT appear in requests. Pseudo-header fields MUST
          // NOT appear in a trailer section. Endpoints MUST treat a request or response that
          // contains undefined or invalid pseudo-header fields as malformed (Section 8.1.1).
          reject_details = UhvResponseCodeDetail::get().InvalidPseudoHeader;
        } else {
          auto entry_result = validateRequestHeaderEntry(header_name, header_value);
          if (entry_result.action() == HeaderEntryValidationResult::Action::DropHeader) {
            // drop the header, continue processing the request
            drop_headers.push_back(string_header_name);
          } else if (!entry_result) {
            reject_details = static_cast<std::string>(entry_result.details());
          }
        }

        return reject_details.empty() ? ::Envoy::Http::HeaderMap::Iterate::Continue
                                      : ::Envoy::Http::HeaderMap::Iterate::Break;
      });

  if (!reject_details.empty()) {
    stats_.incMessagingError();
    return {RequestHeaderMapValidationResult::Action::Reject, reject_details};
  }

  for (auto& name : drop_headers) {
    header_map.remove(LowerCaseString(name));
  }

  return RequestHeaderMapValidationResult::success();
}

::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult
Http2HeaderValidator::validateResponseHeaderMap(::Envoy::Http::ResponseHeaderMap& header_map) {
  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeaders = {":status"};
  // Step 1: verify that required pseudo headers are present
  //
  // For HTTP/2 responses, RFC 9113 states that only the :status
  // header is required: https://www.rfc-editor.org/rfc/rfc9113#section-8.3.2:
  //
  // For HTTP/2 responses, a single ":status" pseudo-header field is defined that carries the HTTP
  // status code field (see Section 15 of [HTTP]). This pseudo-header field MUST be included in all
  // responses, including interim responses; otherwise, the response is malformed (Section 8.1.1).
  if (header_map.getStatusValue().empty()) {
    stats_.incMessagingError();
    return {ResponseHeaderMapValidationResult::Action::Reject,
            UhvResponseCodeDetail::get().InvalidStatus};
  }

  // Step 2: Verify each response header
  std::string reject_details;
  std::vector<absl::string_view> drop_headers;
  header_map.iterate(
      [this, &reject_details, &drop_headers](
          const ::Envoy::Http::HeaderEntry& header_entry) -> ::Envoy::Http::HeaderMap::Iterate {
        const auto& header_name = header_entry.key();
        const auto& header_value = header_entry.value();
        const auto& string_header_name = header_name.getStringView();

        auto entry_result = validateResponseHeaderEntry(header_name, header_value);
        if (entry_result.action() == HeaderEntryValidationResult::Action::DropHeader) {
          // drop the header, continue processing the response
          drop_headers.push_back(string_header_name);
        } else if (!entry_result) {
          reject_details = static_cast<std::string>(entry_result.details());
        }

        return reject_details.empty() ? ::Envoy::Http::HeaderMap::Iterate::Continue
                                      : ::Envoy::Http::HeaderMap::Iterate::Break;
      });

  if (!reject_details.empty()) {
    stats_.incMessagingError();
    return {ResponseHeaderMapValidationResult::Action::Reject, reject_details};
  }

  for (auto& name : drop_headers) {
    header_map.remove(LowerCaseString(name));
  }

  return ResponseHeaderMapValidationResult::success();
}

HeaderValidator::HeaderValueValidationResult
Http2HeaderValidator::validateTEHeader(const ::Envoy::Http::HeaderString& value) {
  // Only allow a TE value of "trailers" for HTTP/2, based on
  // RFC 9113, https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2:
  //
  // The only exception to this is the TE header field, which MAY be present in an HTTP/2 request;
  // when it is, it MUST NOT contain any value other than "trailers".
  if (!absl::EqualsIgnoreCase(value.getStringView(), header_values_.TEValues.Trailers)) {
    return {HeaderValueValidationResult::Action::Reject, Http2ResponseCodeDetail::get().InvalidTE};
  }

  return HeaderValueValidationResult::success();
}

HeaderValidator::HeaderValueValidationResult
Http2HeaderValidator::validateAuthorityHeader(const ::Envoy::Http::HeaderString& value) {
  // From RFC 3986, https://datatracker.ietf.org/doc/html/rfc3986#section-3.2:
  //
  // authority = [ userinfo "@" ] host [ ":" port ]
  //
  // HTTP/2 deprecates the userinfo portion of the :authority header. Validate
  // the :authority header and reject the value if the userinfo is present. This
  // is based on RFC 9113, https://www.rfc-editor.org/rfc/rfc9113#section-8.3.1:
  //
  // ":authority" MUST NOT include the deprecated userinfo subcomponent for "http" or "https"
  // schemed URIs.
  //
  // The host portion can be any valid URI host, which this function does not
  // validate. The port, if present, is validated as a valid uint16_t port.
  return validateHostHeader(value);
}

HeaderValidator::HeaderValueValidationResult
Http2HeaderValidator::validateProtocolHeader(const ::Envoy::Http::HeaderString& value) {
  // Extended CONNECT RFC https://datatracker.ietf.org/doc/html/rfc8441#section-4
  // specifies that the :protocol value is one of the registered values from:
  // https://www.iana.org/assignments/http-upgrade-tokens/
  // However it does not say it MUST be so. As such the :protocol value is checked
  // to be a valid generic header value.

  return validateGenericHeaderValue(value);
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateGenericHeaderName(const HeaderString& name) {
  // Verify that the header name is valid. This also honors the underscore in
  // header configuration setting.
  //
  // From RFC 9110, https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1:
  //
  // header-field   = field-name ":" OWS field-value OWS
  // field-name     = token
  // token          = 1*tchar
  //
  // tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
  //                / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
  //                / DIGIT / ALPHA
  //                ; any VCHAR, except delimiters
  //
  // For HTTP/2, connection-specific headers must be treated as malformed. From RFC 9113,
  // https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2:
  //
  // Any message containing connection-specific header fields MUST be treated as malformed (Section
  // 8.1.1).
  static const absl::node_hash_set<absl::string_view> kRejectHeaderNames = {
      "transfer-encoding", "connection", "upgrade", "keep-alive", "proxy-connection"};
  const auto& key_string_view = name.getStringView();
  const auto& underscore_action = config_.headers_with_underscores_action();

  // This header name is initially invalid if the name is empty or if the name
  // matches an incompatible connection-specific header.
  if (key_string_view.empty()) {
    return {HeaderEntryValidationResult::Action::Reject,
            UhvResponseCodeDetail::get().EmptyHeaderName};
  }

  if (kRejectHeaderNames.contains(key_string_view)) {
    return {HeaderEntryValidationResult::Action::Reject,
            Http2ResponseCodeDetail::get().ConnectionHeaderSanitization};
  }

  bool is_valid = true;
  char c = '\0';
  bool has_underscore = false;

  // Verify that the header name is all lowercase. From RFC 9113,
  // https://www.rfc-editor.org/rfc/rfc9113#section-8.2.1:
  //
  // A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a, or 0x7f-0xff (all
  // ranges inclusive). This specifically excludes all non-visible ASCII characters, ASCII SP
  // (0x20), and uppercase characters ('A' to 'Z', ASCII 0x41 to 0x5a).
  for (auto iter = key_string_view.begin(); iter != key_string_view.end() && is_valid; ++iter) {
    c = *iter;
    if (c != '_') {
      is_valid &= testChar(kGenericHeaderNameCharTable, c) && (c < 'A' || c > 'Z');
    } else {
      has_underscore = true;
    }
  }

  if (!is_valid) {
    return {HeaderEntryValidationResult::Action::Reject,
            UhvResponseCodeDetail::get().InvalidNameCharacters};
  }

  if (has_underscore) {
    if (underscore_action == HeaderValidatorConfig::REJECT_REQUEST) {
      stats_.incRequestsRejectedWithUnderscoresInHeaders();
      return {HeaderEntryValidationResult::Action::Reject,
              UhvResponseCodeDetail::get().InvalidUnderscore};
    } else if (underscore_action == HeaderValidatorConfig::DROP_HEADER) {
      stats_.incDroppedHeadersWithUnderscores();
      return {HeaderEntryValidationResult::Action::DropHeader,
              UhvResponseCodeDetail::get().InvalidUnderscore};
    }
  }

  return HeaderEntryValidationResult::success();
}

HeaderValidator::TrailerValidationResult
Http2HeaderValidator::validateRequestTrailerMap(::Envoy::Http::RequestTrailerMap& trailer_map) {
  TrailerValidationResult result = validateTrailers(trailer_map);
  if (!result.ok()) {
    stats_.incMessagingError();
  }
  return result;
}

HeaderValidator::TrailerValidationResult
Http2HeaderValidator::validateResponseTrailerMap(::Envoy::Http::ResponseTrailerMap& trailer_map) {
  TrailerValidationResult result = validateTrailers(trailer_map);
  if (!result.ok()) {
    stats_.incMessagingError();
  }
  return result;
}

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
