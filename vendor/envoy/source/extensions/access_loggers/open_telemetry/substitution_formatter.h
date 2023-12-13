#pragma once

#include <list>
#include <string>
#include <vector>

#include "envoy/formatter/substitution_formatter.h"
#include "envoy/stream_info/stream_info.h"

#include "opentelemetry/proto/common/v1/common.pb.h"

namespace Envoy {
namespace Extensions {
namespace AccessLoggers {
namespace OpenTelemetry {

// Helper classes for OpenTelemetryFormatter::OpenTelemetryMapFormatVisitor.
template <class... Ts> struct OpenTelemetryFormatMapVisitorHelper : Ts... {
  using Ts::operator()...;
};
template <class... Ts>
OpenTelemetryFormatMapVisitorHelper(Ts...) -> OpenTelemetryFormatMapVisitorHelper<Ts...>;

/**
 * A formatter for OpenTelemetry logs, which returns a KeyValueList proto.
 */
class OpenTelemetryFormatter {
public:
  OpenTelemetryFormatter(const ::opentelemetry::proto::common::v1::KeyValueList& format_mapping);

  ::opentelemetry::proto::common::v1::KeyValueList
  format(const Http::RequestHeaderMap& request_headers,
         const Http::ResponseHeaderMap& response_headers,
         const Http::ResponseTrailerMap& response_trailers,
         const StreamInfo::StreamInfo& stream_info, absl::string_view local_reply_body) const;

private:
  struct OpenTelemetryFormatMapWrapper;
  struct OpenTelemetryFormatListWrapper;
  using OpenTelemetryFormatValue =
      absl::variant<const std::vector<Formatter::FormatterProviderPtr>,
                    const OpenTelemetryFormatMapWrapper, const OpenTelemetryFormatListWrapper>;
  // We use std::list to keep the order of the repeated "values" field in the OpenTelemetry
  // KeyValueList.
  using OpenTelemetryFormatMap = std::list<std::pair<std::string, OpenTelemetryFormatValue>>;
  using OpenTelemetryFormatMapPtr = std::unique_ptr<OpenTelemetryFormatMap>;
  struct OpenTelemetryFormatMapWrapper {
    OpenTelemetryFormatMapPtr value_;
  };

  using OpenTelemetryFormatList = std::list<OpenTelemetryFormatValue>;
  using OpenTelemetryFormatListPtr = std::unique_ptr<OpenTelemetryFormatList>;
  struct OpenTelemetryFormatListWrapper {
    OpenTelemetryFormatListPtr value_;
  };

  using OpenTelemetryFormatMapVisitor = OpenTelemetryFormatMapVisitorHelper<
      const std::function<::opentelemetry::proto::common::v1::AnyValue(
          const std::vector<Formatter::FormatterProviderPtr>&)>,
      const std::function<::opentelemetry::proto::common::v1::AnyValue(
          const OpenTelemetryFormatter::OpenTelemetryFormatMapWrapper&)>,
      const std::function<::opentelemetry::proto::common::v1::AnyValue(
          const OpenTelemetryFormatter::OpenTelemetryFormatListWrapper&)>>;

  // Methods for building the format map.
  class FormatBuilder {
  public:
    std::vector<Formatter::FormatterProviderPtr>
    toFormatStringValue(const std::string& string_format) const;
    OpenTelemetryFormatMapWrapper
    toFormatMapValue(const ::opentelemetry::proto::common::v1::KeyValueList& struct_format) const;
    OpenTelemetryFormatListWrapper toFormatListValue(
        const ::opentelemetry::proto::common::v1::ArrayValue& list_value_format) const;
  };

  // Methods for doing the actual formatting.
  ::opentelemetry::proto::common::v1::AnyValue
  providersCallback(const std::vector<Formatter::FormatterProviderPtr>& providers,
                    const Http::RequestHeaderMap& request_headers,
                    const Http::ResponseHeaderMap& response_headers,
                    const Http::ResponseTrailerMap& response_trailers,
                    const StreamInfo::StreamInfo& stream_info,
                    absl::string_view local_reply_body) const;
  ::opentelemetry::proto::common::v1::AnyValue openTelemetryFormatMapCallback(
      const OpenTelemetryFormatter::OpenTelemetryFormatMapWrapper& format_map,
      const OpenTelemetryFormatMapVisitor& visitor) const;
  ::opentelemetry::proto::common::v1::AnyValue openTelemetryFormatListCallback(
      const OpenTelemetryFormatter::OpenTelemetryFormatListWrapper& format_list,
      const OpenTelemetryFormatMapVisitor& visitor) const;

  const OpenTelemetryFormatMapWrapper kv_list_output_format_;
};

} // namespace OpenTelemetry
} // namespace AccessLoggers
} // namespace Extensions
} // namespace Envoy
