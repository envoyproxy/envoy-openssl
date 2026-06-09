#pragma once

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Http {

// Safe default value for CVE-2026-47774 mitigation.
static constexpr uint32_t DEFAULT_MAX_REQUEST_HEADERS_KB = 128;
// Safe default for CVE-2026-47774 mitigation (cookie header expansion in H/2).
static constexpr uint32_t DEFAULT_MAX_HEADERS_COUNT = 1000;

constexpr absl::string_view MaxRequestHeadersCountOverrideKey =
    "envoy.reloadable_features.max_request_headers_count";
constexpr absl::string_view MaxResponseHeadersCountOverrideKey =
    "envoy.reloadable_features.max_response_headers_count";
constexpr absl::string_view MaxRequestHeadersSizeOverrideKey =
    "envoy.reloadable_features.max_request_headers_size_kb";
constexpr absl::string_view MaxResponseHeadersSizeOverrideKey =
    "envoy.reloadable_features.max_response_headers_size_kb";

} // namespace Http
} // namespace Envoy
