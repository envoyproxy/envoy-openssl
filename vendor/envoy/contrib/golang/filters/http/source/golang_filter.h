#pragma once

#include <atomic>

#include "envoy/access_log/access_log.h"
#include "envoy/http/filter.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/buffer/watermark_buffer.h"
#include "source/common/common/linked_object.h"
#include "source/common/common/thread.h"
#include "source/common/grpc/context_impl.h"
#include "source/common/http/utility.h"

#include "contrib/envoy/extensions/filters/http/golang/v3alpha/golang.pb.h"
#include "contrib/golang/common/dso/dso.h"
#include "contrib/golang/filters/http/source/processor_state.h"
#include "contrib/golang/filters/http/source/stats.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Golang {

/**
 * Configuration for the HTTP golang extension filter.
 */
class FilterConfig : Logger::Loggable<Logger::Id::http> {
public:
  FilterConfig(const envoy::extensions::filters::http::golang::v3alpha::Config& proto_config,
               Dso::HttpFilterDsoPtr dso_lib, const std::string& stats_prefix,
               Server::Configuration::FactoryContext& context);
  // TODO: delete config in Go
  virtual ~FilterConfig() = default;

  const std::string& soId() const { return so_id_; }
  const std::string& soPath() const { return so_path_; }
  const std::string& pluginName() const { return plugin_name_; }
  uint64_t getConfigId();
  GolangFilterStats& stats() { return stats_; }

private:
  const std::string plugin_name_;
  const std::string so_id_;
  const std::string so_path_;
  const ProtobufWkt::Any plugin_config_;

  GolangFilterStats stats_;

  Dso::HttpFilterDsoPtr dso_lib_;
  uint64_t config_id_{0};
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

class RoutePluginConfig : Logger::Loggable<Logger::Id::http> {
public:
  RoutePluginConfig(const envoy::extensions::filters::http::golang::v3alpha::RouterPlugin& config)
      : plugin_config_(config.config()) {
    ENVOY_LOG(debug, "initilizing golang filter route plugin config, type_url: {}",
              config.config().type_url());
  };
  // TODO: delete plugin config in Go
  ~RoutePluginConfig() = default;
  uint64_t getMergedConfigId(uint64_t parent_id, std::string so_id);

private:
  const ProtobufWkt::Any plugin_config_;
  uint64_t config_id_{0};
  uint64_t merged_config_id_{0};
};

using RoutePluginConfigPtr = std::shared_ptr<RoutePluginConfig>;

/**
 * Route configuration for the filter.
 */
class FilterConfigPerRoute : public Router::RouteSpecificFilterConfig,
                             Logger::Loggable<Logger::Id::http> {
public:
  FilterConfigPerRoute(const envoy::extensions::filters::http::golang::v3alpha::ConfigsPerRoute&,
                       Server::Configuration::ServerFactoryContext&);
  uint64_t getPluginConfigId(uint64_t parent_id, std::string plugin_name, std::string so_id) const;

  ~FilterConfigPerRoute() override { plugins_config_.clear(); }

private:
  std::map<std::string, RoutePluginConfigPtr> plugins_config_;
};

enum class DestroyReason {
  Normal,
  Terminate,
};

enum class EnvoyValue {
  RouteName = 1,
  FilterChainName,
  Protocol,
  ResponseCode,
  ResponseCodeDetails,
  AttemptCount,
};

struct httpRequestInternal;

/**
 * See docs/configuration/http_filters/golang_extension_filter.rst
 */
class Filter : public Http::StreamFilter,
               public std::enable_shared_from_this<Filter>,
               Logger::Loggable<Logger::Id::http>,
               public AccessLog::Instance {
public:
  explicit Filter(FilterConfigSharedPtr config, Dso::HttpFilterDsoPtr dynamic_lib)
      : config_(config), dynamic_lib_(dynamic_lib), decoding_state_(*this), encoding_state_(*this) {
  }

  // Http::StreamFilterBase
  void onDestroy() ABSL_LOCKS_EXCLUDED(mutex_) override;
  Http::LocalErrorStatus onLocalReply(const LocalReplyData&) override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override {
    decoding_state_.setDecoderFilterCallbacks(callbacks);
  }

  // Http::StreamEncoderFilter
  Http::Filter1xxHeadersStatus encode1xxHeaders(Http::ResponseHeaderMap&) override {
    return Http::Filter1xxHeadersStatus::Continue;
  }
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap& trailers) override;
  Http::FilterMetadataStatus encodeMetadata(Http::MetadataMap&) override {
    return Http::FilterMetadataStatus::Continue;
  }

  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) override {
    encoding_state_.setEncoderFilterCallbacks(callbacks);
  }

  // AccessLog::Instance
  void log(const Http::RequestHeaderMap* request_headers,
           const Http::ResponseHeaderMap* response_headers,
           const Http::ResponseTrailerMap* response_trailers,
           const StreamInfo::StreamInfo& stream_info) override;

  void onStreamComplete() override {}

  CAPIStatus continueStatus(GolangStatus status);

  CAPIStatus sendLocalReply(Http::Code response_code, std::string body_text,
                            std::function<void(Http::ResponseHeaderMap& headers)> modify_headers,
                            Grpc::Status::GrpcStatus grpc_status, std::string details);

  CAPIStatus sendPanicReply(absl::string_view details);

  CAPIStatus getHeader(absl::string_view key, GoString* go_value);
  CAPIStatus copyHeaders(GoString* go_strs, char* go_buf);
  CAPIStatus setHeader(absl::string_view key, absl::string_view value, headerAction act);
  CAPIStatus removeHeader(absl::string_view key);
  CAPIStatus copyBuffer(Buffer::Instance* buffer, char* data);
  CAPIStatus setBufferHelper(Buffer::Instance* buffer, absl::string_view& value,
                             bufferAction action);
  CAPIStatus copyTrailers(GoString* go_strs, char* go_buf);
  CAPIStatus setTrailer(absl::string_view key, absl::string_view value);
  CAPIStatus getStringValue(int id, GoString* value_str);
  CAPIStatus getIntegerValue(int id, uint64_t* value);
  CAPIStatus setDynamicMetadata(std::string filter_name, std::string key, absl::string_view buf);

private:
  ProcessorState& getProcessorState();

  bool doHeaders(ProcessorState& state, Http::RequestOrResponseHeaderMap& headers, bool end_stream);
  GolangStatus doHeadersGo(ProcessorState& state, Http::RequestOrResponseHeaderMap& headers,
                           bool end_stream);
  bool doData(ProcessorState& state, Buffer::Instance&, bool);
  bool doDataGo(ProcessorState& state, Buffer::Instance& data, bool end_stream);
  bool doTrailer(ProcessorState& state, Http::HeaderMap& trailers);
  bool doTrailerGo(ProcessorState& state, Http::HeaderMap& trailers);

  uint64_t getMergedConfigId(ProcessorState& state);

  void continueEncodeLocalReply(ProcessorState& state);
  void continueStatusInternal(GolangStatus status);
  void continueData(ProcessorState& state);

  void onHeadersModified();

  void sendLocalReplyInternal(Http::Code response_code, absl::string_view body_text,
                              std::function<void(Http::ResponseHeaderMap& headers)> modify_headers,
                              Grpc::Status::GrpcStatus grpc_status, absl::string_view details);

  void setDynamicMetadataInternal(ProcessorState& state, std::string filter_name, std::string key,
                                  const absl::string_view& buf);

  const FilterConfigSharedPtr config_;
  Dso::HttpFilterDsoPtr dynamic_lib_;

  Http::RequestOrResponseHeaderMap* headers_ ABSL_GUARDED_BY(mutex_){nullptr};
  Http::HeaderMap* trailers_ ABSL_GUARDED_BY(mutex_){nullptr};

  // save temp values from local reply
  Http::RequestOrResponseHeaderMap* local_headers_{nullptr};
  Http::HeaderMap* local_trailers_{nullptr};

  // The state of the filter on both the encoding and decoding side.
  DecodingProcessorState decoding_state_;
  EncodingProcessorState encoding_state_;

  httpRequestInternal* req_{nullptr};

  // lock for has_destroyed_ and the functions get/set/copy/remove/etc that operate on the
  // headers_/trailers_/etc, to avoid race between envoy c thread and go thread (when calling back
  // from go). it should also be okay without this lock in most cases, just for extreme case.
  Thread::MutexBasicLockable mutex_{};
  bool has_destroyed_ ABSL_GUARDED_BY(mutex_){false};

  // other filter trigger sendLocalReply during go processing in async.
  // will wait go return before continue.
  // this variable is read/write in safe thread, do no need lock.
  bool local_reply_waiting_go_{false};

  // the filter enter encoding phase
  bool enter_encoding_{false};
};

// Go code only touch the fields in httpRequest
struct httpRequestInternal : httpRequest {
  std::weak_ptr<Filter> filter_;
  // anchor a string temporarily, make sure it won't be freed before copied to Go.
  std::string strValue;
  httpRequestInternal(std::weak_ptr<Filter> f) { filter_ = f; }
  std::weak_ptr<Filter> weakFilter() { return filter_; }
};

class FilterLogger : Logger::Loggable<Logger::Id::http> {
public:
  FilterLogger() = default;

  void log(uint32_t level, absl::string_view message) const;
};

} // namespace Golang
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
