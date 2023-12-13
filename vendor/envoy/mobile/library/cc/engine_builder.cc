#include "engine_builder.h"

#include <sstream>

#include "envoy/config/metrics/v3/metrics_service.pb.h"
#include "envoy/extensions/compression/brotli/decompressor/v3/brotli.pb.h"
#include "envoy/extensions/compression/gzip/decompressor/v3/gzip.pb.h"
#include "envoy/extensions/filters/http/alternate_protocols_cache/v3/alternate_protocols_cache.pb.h"
#include "envoy/extensions/filters/http/decompressor/v3/decompressor.pb.h"
#include "envoy/extensions/filters/http/dynamic_forward_proxy/v3/dynamic_forward_proxy.pb.h"
#include "envoy/extensions/http/header_formatters/preserve_case/v3/preserve_case.pb.h"
#include "envoy/extensions/network/dns_resolver/apple/v3/apple_dns_resolver.pb.h"
#include "envoy/extensions/network/dns_resolver/getaddrinfo/v3/getaddrinfo_dns_resolver.pb.h"
#include "envoy/extensions/transport_sockets/http_11_proxy/v3/upstream_http_11_connect.pb.h"
#include "envoy/extensions/transport_sockets/quic/v3/quic_transport.pb.h"
#include "envoy/extensions/transport_sockets/raw_buffer/v3/raw_buffer.pb.h"

#ifdef ENVOY_MOBILE_REQUEST_COMPRESSION
#include "envoy/extensions/compression/brotli/compressor/v3/brotli.pb.h"
#include "envoy/extensions/compression/gzip/compressor/v3/gzip.pb.h"
#include "envoy/extensions/filters/http/composite/v3/composite.pb.h"
#include "envoy/extensions/filters/http/compressor/v3/compressor.pb.h"
#include "envoy/extensions/common/matching/v3/extension_matcher.pb.validate.h"
#endif

#include "source/common/common/assert.h"
#include "source/common/http/matching/inputs.h"
#include "source/extensions/clusters/dynamic_forward_proxy/cluster.h"

#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "fmt/core.h"
#include "library/common/engine.h"
#include "library/common/extensions/cert_validator/platform_bridge/platform_bridge.pb.h"
#include "library/common/extensions/filters/http/local_error/filter.pb.h"
#include "library/common/extensions/filters/http/network_configuration/filter.pb.h"
#include "library/common/extensions/filters/http/socket_tag/filter.pb.h"
#include "library/common/extensions/key_value/platform/platform.pb.h"
#include "library/common/main_interface.h"

namespace Envoy {
namespace Platform {

EngineBuilder::EngineBuilder() : callbacks_(std::make_shared<EngineCallbacks>()) {
#ifndef ENVOY_ENABLE_QUIC
  enable_http3_ = false;
#endif
}

EngineBuilder& EngineBuilder::addLogLevel(LogLevel log_level) {
  log_level_ = log_level;
  return *this;
}

EngineBuilder& EngineBuilder::setOnEngineRunning(std::function<void()> closure) {
  callbacks_->on_engine_running = closure;
  return *this;
}

#ifdef ENVOY_MOBILE_STATS_REPORTING
EngineBuilder& EngineBuilder::addStatsSinks(std::vector<std::string> stats_sinks) {
  stats_sinks_ = std::move(stats_sinks);
  return *this;
}

EngineBuilder& EngineBuilder::addGrpcStatsDomain(std::string stats_domain) {
  stats_domain_ = std::move(stats_domain);
  return *this;
}

EngineBuilder& EngineBuilder::addStatsFlushSeconds(int stats_flush_seconds) {
  stats_flush_seconds_ = stats_flush_seconds;
  return *this;
}
#endif

EngineBuilder& EngineBuilder::addConnectTimeoutSeconds(int connect_timeout_seconds) {
  connect_timeout_seconds_ = connect_timeout_seconds;
  return *this;
}

EngineBuilder& EngineBuilder::addDnsRefreshSeconds(int dns_refresh_seconds) {
  dns_refresh_seconds_ = dns_refresh_seconds;
  return *this;
}

EngineBuilder& EngineBuilder::addDnsMinRefreshSeconds(int dns_min_refresh_seconds) {
  dns_min_refresh_seconds_ = dns_min_refresh_seconds;
  return *this;
}

EngineBuilder& EngineBuilder::addDnsFailureRefreshSeconds(int base, int max) {
  dns_failure_refresh_seconds_base_ = base;
  dns_failure_refresh_seconds_max_ = max;
  return *this;
}

EngineBuilder& EngineBuilder::addDnsQueryTimeoutSeconds(int dns_query_timeout_seconds) {
  dns_query_timeout_seconds_ = dns_query_timeout_seconds;
  return *this;
}

EngineBuilder& EngineBuilder::addDnsPreresolveHostnames(const std::vector<std::string>& hostnames) {
  dns_preresolve_hostnames_ = std::move(hostnames);
  return *this;
}

EngineBuilder& EngineBuilder::addMaxConnectionsPerHost(int max_connections_per_host) {
  max_connections_per_host_ = max_connections_per_host;
  return *this;
}

EngineBuilder& EngineBuilder::useDnsSystemResolver(bool use_system_resolver) {
  use_system_resolver_ = use_system_resolver;
  return *this;
}

EngineBuilder& EngineBuilder::addH2ConnectionKeepaliveIdleIntervalMilliseconds(
    int h2_connection_keepalive_idle_interval_milliseconds) {
  h2_connection_keepalive_idle_interval_milliseconds_ =
      h2_connection_keepalive_idle_interval_milliseconds;
  return *this;
}

EngineBuilder&
EngineBuilder::addH2ConnectionKeepaliveTimeoutSeconds(int h2_connection_keepalive_timeout_seconds) {
  h2_connection_keepalive_timeout_seconds_ = h2_connection_keepalive_timeout_seconds;
  return *this;
}

EngineBuilder& EngineBuilder::addVirtualCluster(std::string virtual_cluster) {
  virtual_clusters_.push_back(std::move(virtual_cluster));
  return *this;
}

EngineBuilder& EngineBuilder::addVirtualCluster(std::string name,
                                                std::vector<MatcherData> matchers) {
  std::pair<std::string, std::vector<MatcherData>> matcher(name, std::move(matchers));
  virtual_cluster_data_.emplace_back(std::move(matcher));
  return *this;
}

EngineBuilder& EngineBuilder::addKeyValueStore(std::string name,
                                               KeyValueStoreSharedPtr key_value_store) {
  key_value_stores_[std::move(name)] = std::move(key_value_store);
  return *this;
}

EngineBuilder& EngineBuilder::setAppVersion(std::string app_version) {
  app_version_ = std::move(app_version);
  return *this;
}

EngineBuilder& EngineBuilder::setAppId(std::string app_id) {
  app_id_ = std::move(app_id);
  return *this;
}

EngineBuilder& EngineBuilder::setDeviceOs(std::string device_os) {
  device_os_ = std::move(device_os);
  return *this;
}

EngineBuilder& EngineBuilder::setStreamIdleTimeoutSeconds(int stream_idle_timeout_seconds) {
  stream_idle_timeout_seconds_ = stream_idle_timeout_seconds;
  return *this;
}

EngineBuilder& EngineBuilder::setPerTryIdleTimeoutSeconds(int per_try_idle_timeout_seconds) {
  per_try_idle_timeout_seconds_ = per_try_idle_timeout_seconds;
  return *this;
}

EngineBuilder& EngineBuilder::enableGzipDecompression(bool gzip_decompression_on) {
  gzip_decompression_filter_ = gzip_decompression_on;
  return *this;
}

EngineBuilder& EngineBuilder::enableBrotliDecompression(bool brotli_decompression_on) {
  brotli_decompression_filter_ = brotli_decompression_on;
  return *this;
}

EngineBuilder& EngineBuilder::enableSocketTagging(bool socket_tagging_on) {
  socket_tagging_filter_ = socket_tagging_on;
  return *this;
}

#ifdef ENVOY_ADMIN_FUNCTIONALITY
EngineBuilder& EngineBuilder::enableAdminInterface(bool admin_interface_on) {
  admin_interface_enabled_ = admin_interface_on;
  return *this;
}
#endif

EngineBuilder& EngineBuilder::enableHappyEyeballs(bool happy_eyeballs_on) {
  enable_happy_eyeballs_ = happy_eyeballs_on;
  return *this;
}

#ifdef ENVOY_ENABLE_QUIC
EngineBuilder& EngineBuilder::enableHttp3(bool http3_on) {
  enable_http3_ = http3_on;
  return *this;
}
#endif

EngineBuilder& EngineBuilder::setForceAlwaysUsev6(bool value) {
  always_use_v6_ = value;
  return *this;
}

EngineBuilder& EngineBuilder::setSkipDnsLookupForProxiedRequests(bool value) {
  skip_dns_lookups_for_proxied_requests_ = value;
  return *this;
}

EngineBuilder& EngineBuilder::enableInterfaceBinding(bool interface_binding_on) {
  enable_interface_binding_ = interface_binding_on;
  return *this;
}

EngineBuilder& EngineBuilder::enableDrainPostDnsRefresh(bool drain_post_dns_refresh_on) {
  enable_drain_post_dns_refresh_ = drain_post_dns_refresh_on;
  return *this;
}

EngineBuilder& EngineBuilder::enforceTrustChainVerification(bool trust_chain_verification_on) {
  enforce_trust_chain_verification_ = trust_chain_verification_on;
  return *this;
}
#ifdef ENVOY_GOOGLE_GRPC
EngineBuilder& EngineBuilder::setNodeId(std::string node_id) {
  node_id_ = std::move(node_id);
  return *this;
}

EngineBuilder& EngineBuilder::setNodeLocality(std::string region, std::string zone,
                                              std::string sub_zone) {
  node_locality_ = {region, zone, sub_zone};
  return *this;
}

EngineBuilder& EngineBuilder::setAggregatedDiscoveryService(std::string address, const int port,
                                                            std::string jwt_token,
                                                            const int jwt_token_lifetime_seconds,
                                                            std::string ssl_root_certs) {
  ads_address_ = address;
  ads_port_ = port;
  ads_jwt_token_ = std::move(jwt_token);
  ads_jwt_token_lifetime_seconds_ =
      jwt_token_lifetime_seconds == 0 ? DefaultJwtTokenLifetimeSeconds : jwt_token_lifetime_seconds;
  ads_ssl_root_certs_ = std::move(ssl_root_certs);
  return *this;
}

EngineBuilder& EngineBuilder::addRtdsLayer(std::string layer_name, const int timeout_seconds) {
  rtds_layer_name_ = std::move(layer_name);
  rtds_timeout_seconds_ = timeout_seconds == 0 ? DefaultXdsTimeout : timeout_seconds;
  return *this;
}

EngineBuilder& EngineBuilder::addCdsLayer(std::string cds_resources_locator,
                                          const int timeout_seconds) {
  enable_cds_ = true;
  cds_resources_locator_ = std::move(cds_resources_locator);
  cds_timeout_seconds_ = timeout_seconds == 0 ? DefaultXdsTimeout : timeout_seconds;
  return *this;
}
#endif

EngineBuilder&
EngineBuilder::enablePlatformCertificatesValidation(bool platform_certificates_validation_on) {
  platform_certificates_validation_on_ = platform_certificates_validation_on;
  return *this;
}

EngineBuilder& EngineBuilder::enableDnsCache(bool dns_cache_on, int save_interval_seconds) {
  dns_cache_on_ = dns_cache_on;
  dns_cache_save_interval_seconds_ = save_interval_seconds;
  return *this;
}

EngineBuilder& EngineBuilder::addStringAccessor(std::string name,
                                                StringAccessorSharedPtr accessor) {
  string_accessors_[std::move(name)] = std::move(accessor);
  return *this;
}

EngineBuilder& EngineBuilder::addNativeFilter(std::string name, std::string typed_config) {
  native_filter_chain_.emplace_back(std::move(name), std::move(typed_config));
  return *this;
}

EngineBuilder& EngineBuilder::addPlatformFilter(std::string name) {
  addNativeFilter(
      "envoy.filters.http.platform_bridge",
      absl::StrCat(
          "{'@type': "
          "type.googleapis.com/envoymobile.extensions.filters.http.platform_bridge.PlatformBridge, "
          "platform_filter_name: ",
          name, "}"));
  return *this;
}

EngineBuilder& EngineBuilder::setRuntimeGuard(std::string guard, bool value) {
  runtime_guards_.push_back({guard, value});
  return *this;
}

EngineBuilder&
EngineBuilder::addDirectResponse(DirectResponseTesting::DirectResponse direct_response) {
  direct_responses_.push_back(direct_response);
  return *this;
}

EngineBuilder& EngineBuilder::setOverrideConfigForTests(std::string config) {
  config_override_for_tests_ = std::move(config);
  return *this;
}

std::unique_ptr<envoy::config::bootstrap::v3::Bootstrap> EngineBuilder::generateBootstrap() const {
  // The yaml utilities have non-relevant thread asserts.
  Thread::SkipAsserts skip;

  std::unique_ptr<envoy::config::bootstrap::v3::Bootstrap> bootstrap =
      std::make_unique<envoy::config::bootstrap::v3::Bootstrap>();

  // Set up the HCM
  envoy::extensions::filters::network::http_connection_manager::v3::EnvoyMobileHttpConnectionManager
      api_listener_config;
  auto* hcm = api_listener_config.mutable_config();
  hcm->set_stat_prefix("hcm");
  hcm->set_server_header_transformation(
      envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager::
          PASS_THROUGH);
  hcm->mutable_stream_idle_timeout()->set_seconds(stream_idle_timeout_seconds_);
  auto* route_config = hcm->mutable_route_config();
  route_config->set_name("api_router");
  auto* remote_service = route_config->add_virtual_hosts();
  remote_service->set_name("remote_service");
  remote_service->add_domains("127.0.0.1");

  for (auto& direct_response_in : direct_responses_) {
    auto* direct_response_route = remote_service->add_routes();
    auto* direct_response = direct_response_route->mutable_direct_response();
    direct_response->set_status(direct_response_in.status);
    direct_response->mutable_body()->set_inline_string(direct_response_in.body);
    auto* direct_response_route_match = direct_response_route->mutable_match();
    auto matcher = direct_response_in.matcher;
    if (!matcher.fullPath.empty()) {
      direct_response_route_match->set_path(matcher.fullPath);
    } else if (!matcher.pathPrefix.empty()) {
      direct_response_route_match->set_prefix(matcher.pathPrefix);
    }

    for (auto& header : matcher.headers) {
      auto* direct_response_headers = direct_response_route_match->add_headers();
      direct_response_headers->set_name(header.name);
      switch (header.mode) {
      case DirectResponseTesting::MatchMode::Contains:
        direct_response_headers->set_contains_match(header.value);
        break;
      case DirectResponseTesting::MatchMode::Exact:
        direct_response_headers->set_exact_match(header.value);
        break;
      case DirectResponseTesting::MatchMode::Prefix:
        direct_response_headers->set_prefix_match(header.value);
        break;
      case DirectResponseTesting::MatchMode::Suffix:
        direct_response_headers->set_suffix_match(header.value);
        break;
      }
    }

    for (auto& header_in : direct_response_in.headers) {
      auto* resp_header = direct_response_route->add_response_headers_to_add();
      auto* header = resp_header->mutable_header();
      header->set_key(header_in.first);
      header->set_value(header_in.second);
    }
  }

  auto* route = remote_service->add_routes();
  route->mutable_match()->set_prefix("/");
  route->mutable_direct_response()->set_status(404);
  route->mutable_direct_response()->mutable_body()->set_inline_string("not found");
  route->add_request_headers_to_remove("x-forwarded-proto");
  route->add_request_headers_to_remove("x-envoy-mobile-cluster");
  auto* api_service = route_config->add_virtual_hosts();
  api_service->set_name("api");
  api_service->set_include_attempt_count_in_response(true);
  api_service->add_domains("*");
  // Virtual clusters
  for (auto& cluster : virtual_clusters_) {
    MessageUtil::loadFromYaml(cluster, *api_service->add_virtual_clusters(),
                              ProtobufMessage::getStrictValidationVisitor());
  }
  for (auto& name_and_data : virtual_cluster_data_) {
    auto* virtual_cluster = api_service->add_virtual_clusters();
    virtual_cluster->set_name(name_and_data.first);
    for (auto& matcher : name_and_data.second) {
      auto* match = virtual_cluster->add_headers();
      match->set_name(matcher.name);
      if (matcher.type == MatcherData::EXACT) {
        match->set_exact_match(matcher.value);
      } else {
        ASSERT(matcher.type == MatcherData::SAFE_REGEX);
        match->mutable_safe_regex_match()->set_regex(matcher.value);
      }
    }
  }

  for (auto& direct_response_in : direct_responses_) {
    auto* this_route = api_service->add_routes();
    auto* mutable_route = this_route->mutable_route();
    mutable_route->set_cluster("fake_remote");
    auto* direct_response_route_match = this_route->mutable_match();
    auto matcher = direct_response_in.matcher;
    if (!matcher.fullPath.empty()) {
      direct_response_route_match->set_path(matcher.fullPath);
    } else if (!matcher.pathPrefix.empty()) {
      direct_response_route_match->set_prefix(matcher.pathPrefix);
    }

    for (auto& header : matcher.headers) {
      auto* direct_response_headers = direct_response_route_match->add_headers();
      direct_response_headers->set_name(header.name);
      switch (header.mode) {
      case DirectResponseTesting::MatchMode::Contains:
        direct_response_headers->set_contains_match(header.value);
        break;
      case DirectResponseTesting::MatchMode::Exact:
        direct_response_headers->set_exact_match(header.value);
        break;
      case DirectResponseTesting::MatchMode::Prefix:
        direct_response_headers->set_prefix_match(header.value);
        break;
      case DirectResponseTesting::MatchMode::Suffix:
        direct_response_headers->set_suffix_match(header.value);
        break;
      }
    }
  }

  route = api_service->add_routes();
  route->mutable_match()->set_prefix("/");
  route->add_request_headers_to_remove("x-forwarded-proto");
  route->add_request_headers_to_remove("x-envoy-mobile-cluster");
  auto* route_to = route->mutable_route();
  route_to->set_cluster_header("x-envoy-mobile-cluster");
  route_to->mutable_timeout()->set_seconds(0);
  route_to->mutable_retry_policy()->mutable_per_try_idle_timeout()->set_seconds(
      per_try_idle_timeout_seconds_);
  auto* backoff = route_to->mutable_retry_policy()->mutable_retry_back_off();
  backoff->mutable_base_interval()->set_nanos(250000000);
  backoff->mutable_max_interval()->set_seconds(60);

  for (auto filter = native_filter_chain_.rbegin(); filter != native_filter_chain_.rend();
       ++filter) {
    auto* native_filter = hcm->add_http_filters();
    native_filter->set_name((*filter).name_);
    MessageUtil::loadFromYaml((*filter).typed_config_, *native_filter->mutable_typed_config(),
                              ProtobufMessage::getStrictValidationVisitor());
  }

  // Set up the optional filters
  if (enable_http3_) {
#ifdef ENVOY_ENABLE_QUIC
    envoy::extensions::filters::http::alternate_protocols_cache::v3::FilterConfig cache_config;
    cache_config.mutable_alternate_protocols_cache_options()->set_name(
        "default_alternate_protocols_cache");
    auto* cache_filter = hcm->add_http_filters();
    cache_filter->set_name("alternate_protocols_cache");
    cache_filter->mutable_typed_config()->PackFrom(cache_config);
#else
    throw std::runtime_error("http3 functionality was not compiled in this build of Envoy Mobile");
#endif
  }

  if (gzip_decompression_filter_) {
    envoy::extensions::compression::gzip::decompressor::v3::Gzip gzip_config;
    gzip_config.mutable_window_bits()->set_value(15);
    envoy::extensions::filters::http::decompressor::v3::Decompressor decompressor_config;
    decompressor_config.mutable_decompressor_library()->set_name("gzip");
    decompressor_config.mutable_decompressor_library()->mutable_typed_config()->PackFrom(
        gzip_config);
    auto* common_request =
        decompressor_config.mutable_request_direction_config()->mutable_common_config();
    common_request->mutable_enabled()->mutable_default_value();
    common_request->mutable_enabled()->set_runtime_key("request_decompressor_enabled");
    decompressor_config.mutable_response_direction_config()
        ->mutable_common_config()
        ->set_ignore_no_transform_header(true);
    auto* gzip_filter = hcm->add_http_filters();
    gzip_filter->set_name("envoy.filters.http.decompressor");
    gzip_filter->mutable_typed_config()->PackFrom(decompressor_config);
  }
  if (brotli_decompression_filter_) {
    envoy::extensions::compression::brotli::decompressor::v3::Brotli brotli_config;
    envoy::extensions::filters::http::decompressor::v3::Decompressor decompressor_config;
    decompressor_config.mutable_decompressor_library()->set_name("text_optimized");
    decompressor_config.mutable_decompressor_library()->mutable_typed_config()->PackFrom(
        brotli_config);
    auto* common_request =
        decompressor_config.mutable_request_direction_config()->mutable_common_config();
    common_request->mutable_enabled()->mutable_default_value();
    common_request->mutable_enabled()->set_runtime_key("request_decompressor_enabled");
    decompressor_config.mutable_response_direction_config()
        ->mutable_common_config()
        ->set_ignore_no_transform_header(true);
    auto* brotli_filter = hcm->add_http_filters();
    brotli_filter->set_name("envoy.filters.http.decompressor");
    brotli_filter->mutable_typed_config()->PackFrom(decompressor_config);
  }
#ifdef ENVOY_MOBILE_REQUEST_COMPRESSION
  auto* compressor_filter = hcm->add_http_filters();
  compressor_filter->set_name("envoy.filters.http.compressor");
  envoy::extensions::common::matching::v3::ExtensionWithMatcher extension_config;
  extension_config.mutable_extension_config()->set_name("composite");
  envoy::extensions::filters::http::composite::v3::Composite composite_config;
  extension_config.mutable_extension_config()->mutable_typed_config()->PackFrom(composite_config);
  auto* matcher_tree = extension_config.mutable_xds_matcher()->mutable_matcher_tree();
  auto* matcher_input = matcher_tree->mutable_input();
  matcher_input->set_name("request-headers");
  envoy::type::matcher::v3::HttpRequestHeaderMatchInput request_header_match_input;
  request_header_match_input.set_header_name("x-envoy-mobile-compression");
  matcher_input->mutable_typed_config()->PackFrom(request_header_match_input);
  auto* exact_match_map = matcher_tree->mutable_exact_match_map()->mutable_map();
  ::xds::type::matcher::v3::Matcher_OnMatch on_gzip_match;
  auto* on_gzip_match_action = on_gzip_match.mutable_action();
  on_gzip_match_action->set_name("composite-action");
  envoy::extensions::filters::http::composite::v3::ExecuteFilterAction execute_gzip_filter_action;
  envoy::extensions::compression::gzip::compressor::v3::Gzip gzip_config;
  gzip_config.mutable_window_bits()->set_value(15);
  envoy::extensions::filters::http::compressor::v3::Compressor gzip_compressor_config;
  gzip_compressor_config.mutable_compressor_library()->set_name("gzip");
  gzip_compressor_config.mutable_compressor_library()->mutable_typed_config()->PackFrom(
      gzip_config);
  auto* gzip_common_request =
      gzip_compressor_config.mutable_request_direction_config()->mutable_common_config();
  gzip_common_request->mutable_enabled()->mutable_default_value()->set_value(true);
  auto* gzip_common_response =
      gzip_compressor_config.mutable_response_direction_config()->mutable_common_config();
  gzip_common_response->mutable_enabled()->mutable_default_value()->set_value(false);
  execute_gzip_filter_action.mutable_typed_config()->set_name("envoy.filters.http.compressor");
  execute_gzip_filter_action.mutable_typed_config()->mutable_typed_config()->PackFrom(
      gzip_compressor_config);
  on_gzip_match_action->mutable_typed_config()->PackFrom(execute_gzip_filter_action);
  (*exact_match_map)["gzip"] = on_gzip_match;
  ::xds::type::matcher::v3::Matcher_OnMatch on_brotli_match;
  auto* on_brotli_match_action = on_brotli_match.mutable_action();
  on_brotli_match_action->set_name("composite-action");
  envoy::extensions::filters::http::composite::v3::ExecuteFilterAction execute_brotli_filter_action;
  envoy::extensions::compression::brotli::compressor::v3::Brotli brotli_config;
  envoy::extensions::filters::http::compressor::v3::Compressor brotli_compressor_config;
  brotli_compressor_config.mutable_compressor_library()->set_name("text_optimized");
  brotli_compressor_config.mutable_compressor_library()->mutable_typed_config()->PackFrom(
      brotli_config);
  auto* brotli_common_request =
      brotli_compressor_config.mutable_request_direction_config()->mutable_common_config();
  brotli_common_request->mutable_enabled()->mutable_default_value()->set_value(true);
  auto* brotli_common_response =
      brotli_compressor_config.mutable_response_direction_config()->mutable_common_config();
  brotli_common_response->mutable_enabled()->mutable_default_value()->set_value(false);
  execute_brotli_filter_action.mutable_typed_config()->set_name("envoy.filters.http.compressor");
  execute_brotli_filter_action.mutable_typed_config()->mutable_typed_config()->PackFrom(
      brotli_compressor_config);
  on_brotli_match_action->mutable_typed_config()->PackFrom(execute_brotli_filter_action);
  (*exact_match_map)["brotli"] = on_brotli_match;
  compressor_filter->mutable_typed_config()->PackFrom(extension_config);
#endif
  if (socket_tagging_filter_) {
    envoymobile::extensions::filters::http::socket_tag::SocketTag tag_config;
    auto* tag_filter = hcm->add_http_filters();
    tag_filter->set_name("envoy.filters.http.socket_tag");
    tag_filter->mutable_typed_config()->PackFrom(tag_config);
  }

  if (!direct_responses_.empty()) {
    auto* cache_reset_filter = hcm->add_http_filters();
    cache_reset_filter->set_name("envoy.filters.http.route_cache_reset");
    cache_reset_filter->mutable_typed_config()->set_type_url(
        "type.googleapis.com/"
        "envoymobile.extensions.filters.http.route_cache_reset.RouteCacheReset");
  }

  // Set up the always-present filters
  envoymobile::extensions::filters::http::network_configuration::NetworkConfiguration
      network_config;
  network_config.set_enable_drain_post_dns_refresh(enable_drain_post_dns_refresh_);
  network_config.set_enable_interface_binding(enable_interface_binding_);
  auto* network_filter = hcm->add_http_filters();
  network_filter->set_name("envoy.filters.http.network_configuration");
  network_filter->mutable_typed_config()->PackFrom(network_config);

  envoymobile::extensions::filters::http::local_error::LocalError local_config;
  auto* local_filter = hcm->add_http_filters();
  local_filter->set_name("envoy.filters.http.local_error");
  local_filter->mutable_typed_config()->PackFrom(local_config);

  envoy::extensions::filters::http::dynamic_forward_proxy::v3::FilterConfig dfp_config;
  auto* dns_cache_config = dfp_config.mutable_dns_cache_config();
  dns_cache_config->set_name("base_dns_cache");
  if (enable_happy_eyeballs_) {
    dns_cache_config->set_dns_lookup_family(envoy::config::cluster::v3::Cluster::ALL);
  } else {
    dns_cache_config->set_dns_lookup_family(envoy::config::cluster::v3::Cluster::V4_PREFERRED);
  }
  dns_cache_config->mutable_host_ttl()->set_seconds(86400);
  dns_cache_config->mutable_dns_min_refresh_rate()->set_seconds(dns_min_refresh_seconds_);
  dns_cache_config->mutable_dns_refresh_rate()->set_seconds(dns_refresh_seconds_);
  dns_cache_config->mutable_dns_failure_refresh_rate()->mutable_base_interval()->set_seconds(
      dns_failure_refresh_seconds_base_);
  dns_cache_config->mutable_dns_failure_refresh_rate()->mutable_max_interval()->set_seconds(
      dns_failure_refresh_seconds_max_);
  dns_cache_config->mutable_dns_query_timeout()->set_seconds(dns_query_timeout_seconds_);
  if (dns_cache_on_) {
    envoymobile::extensions::key_value::platform::PlatformKeyValueStoreConfig kv_config;
    kv_config.set_key("dns_persistent_cache");
    kv_config.mutable_save_interval()->set_seconds(dns_cache_save_interval_seconds_);
    kv_config.set_max_entries(100);
    dns_cache_config->mutable_key_value_config()->mutable_config()->set_name(
        "envoy.key_value.platform");
    dns_cache_config->mutable_key_value_config()
        ->mutable_config()
        ->mutable_typed_config()
        ->PackFrom(kv_config);
  }

#if defined(__APPLE__)
  envoy::extensions::network::dns_resolver::apple::v3::AppleDnsResolverConfig resolver_config;
  dns_cache_config->mutable_typed_dns_resolver_config()->set_name(
      "envoy.network.dns_resolver.apple");
#else
  envoy::extensions::network::dns_resolver::getaddrinfo::v3::GetAddrInfoDnsResolverConfig
      resolver_config;
  dns_cache_config->mutable_typed_dns_resolver_config()->set_name(
      "envoy.network.dns_resolver.getaddrinfo");
#endif
  dns_cache_config->mutable_typed_dns_resolver_config()->mutable_typed_config()->PackFrom(
      resolver_config);

  for (auto& hostname : dns_preresolve_hostnames_) {
    envoy::config::core::v3::SocketAddress* address = dns_cache_config->add_preresolve_hostnames();
    address->set_address(hostname);
    address->set_port_value(443);
  }

  auto* dfp_filter = hcm->add_http_filters();
  dfp_filter->set_name("envoy.filters.http.dynamic_forward_proxy");
  dfp_filter->mutable_typed_config()->PackFrom(dfp_config);

  auto* router_filter = hcm->add_http_filters();
  envoy::extensions::filters::http::router::v3::Router router_config;
  router_filter->set_name("envoy.router");
  router_filter->mutable_typed_config()->PackFrom(router_config);

  auto* static_resources = bootstrap->mutable_static_resources();

  if (!direct_responses_.empty()) {
    auto* fake_remote_listener = static_resources->add_listeners();
    fake_remote_listener->set_name("fake_remote_listener");
    auto* base_address = fake_remote_listener->mutable_address();
    base_address->mutable_socket_address()->set_address("127.0.0.1");
    base_address->mutable_socket_address()->set_port_value(10101);
    auto* filter = fake_remote_listener->add_filter_chains()->add_filters();
    envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager
        fake_remote_listener_config;
    filter->set_name("envoy.filters.network.http_connection_manager");
    fake_remote_listener_config.set_stat_prefix("remote_hcm");
    auto* route_config = fake_remote_listener_config.mutable_route_config();
    route_config->set_name("remote_route");
    auto* virtual_host = route_config->add_virtual_hosts();
    virtual_host->add_domains("*");
    virtual_host->set_name("remote_service");
    auto* route = virtual_host->add_routes();
    route->mutable_match()->set_prefix("/");
    route->mutable_direct_response()->set_status(404);
    route->mutable_direct_response()->mutable_body()->set_inline_string("not found");
    route->add_request_headers_to_remove("x-forwarded-proto");
    route->add_request_headers_to_remove("x-envoy-mobile-cluster");
    auto* router_filter = fake_remote_listener_config.add_http_filters();
    envoy::extensions::filters::http::router::v3::Router router_config;
    router_filter->set_name("envoy.router");
    router_filter->mutable_typed_config()->PackFrom(router_config);
    filter->mutable_typed_config()->PackFrom(fake_remote_listener_config);
  }

  // Finally create the base listener, and point it at the HCM.
  auto* base_listener = static_resources->add_listeners();
  base_listener->set_name("base_api_listener");
  auto* base_address = base_listener->mutable_address();
  base_address->mutable_socket_address()->set_protocol(envoy::config::core::v3::SocketAddress::TCP);
  base_address->mutable_socket_address()->set_address("0.0.0.0");
  base_address->mutable_socket_address()->set_port_value(10000);
  base_listener->mutable_per_connection_buffer_limit_bytes()->set_value(10485760);
  base_listener->mutable_api_listener()->mutable_api_listener()->PackFrom(api_listener_config);

  // Basic TLS config.
  envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext tls_socket;
  tls_socket.mutable_common_tls_context()->mutable_tls_params()->set_tls_maximum_protocol_version(
      envoy::extensions::transport_sockets::tls::v3::TlsParameters::TLSv1_3);
  auto* validation = tls_socket.mutable_common_tls_context()->mutable_validation_context();
  if (enforce_trust_chain_verification_) {
    validation->set_trust_chain_verification(envoy::extensions::transport_sockets::tls::v3::
                                                 CertificateValidationContext::VERIFY_TRUST_CHAIN);
  } else {
    validation->set_trust_chain_verification(envoy::extensions::transport_sockets::tls::v3::
                                                 CertificateValidationContext::ACCEPT_UNTRUSTED);
  }
  if (platform_certificates_validation_on_) {
    envoy_mobile::extensions::cert_validator::platform_bridge::PlatformBridgeCertValidator
        validator;
    validation->mutable_custom_validator_config()->set_name(
        "envoy_mobile.cert_validator.platform_bridge_cert_validator");
    validation->mutable_custom_validator_config()->mutable_typed_config()->PackFrom(validator);

  } else {
    const char* inline_certs = ""
#ifndef EXCLUDE_CERTIFICATES
#include "library/common/config/certificates.inc"
#endif
                               "";
    // The certificates in certificates.inc are prefixed with 2 spaces per
    // line to be ingressed into YAML.
    std::string certs = inline_certs;
    absl::StrReplaceAll({{"\n  ", "\n"}}, &certs);
    validation->mutable_trusted_ca()->set_inline_string(certs);
  }
  envoy::extensions::transport_sockets::http_11_proxy::v3::Http11ProxyUpstreamTransport
      ssl_proxy_socket;
  ssl_proxy_socket.mutable_transport_socket()->set_name("envoy.transport_sockets.tls");
  ssl_proxy_socket.mutable_transport_socket()->mutable_typed_config()->PackFrom(tls_socket);

  envoy::config::core::v3::TransportSocket base_tls_socket;
  base_tls_socket.set_name("envoy.transport_sockets.http_11_proxy");
  base_tls_socket.mutable_typed_config()->PackFrom(ssl_proxy_socket);

  if (!direct_responses_.empty()) {
    // fake remote cluster
    auto* fake_remote_cluster = static_resources->add_clusters();
    fake_remote_cluster->set_name("fake_remote");
    fake_remote_cluster->set_type(envoy::config::cluster::v3::Cluster::LOGICAL_DNS);
    fake_remote_cluster->mutable_connect_timeout()->set_seconds(30);
    fake_remote_cluster->mutable_load_assignment()->set_cluster_name("fake_remote");
    auto* address = fake_remote_cluster->mutable_load_assignment()
                        ->add_endpoints()
                        ->add_lb_endpoints()
                        ->mutable_endpoint()
                        ->mutable_address();
    address->mutable_socket_address()->set_address("127.0.0.1");
    address->mutable_socket_address()->set_port_value(10101);
  }

  envoy::extensions::upstreams::http::v3::HttpProtocolOptions h2_protocol_options;
  h2_protocol_options.mutable_explicit_http_config()->mutable_http2_protocol_options();
  if (!stats_domain_.empty()) {
    // Stats cluster
    auto* stats_cluster = static_resources->add_clusters();
    stats_cluster->set_name("stats");
    stats_cluster->set_type(envoy::config::cluster::v3::Cluster::LOGICAL_DNS);
    stats_cluster->mutable_connect_timeout()->set_seconds(connect_timeout_seconds_);
    stats_cluster->mutable_dns_refresh_rate()->set_seconds(dns_refresh_seconds_);
    stats_cluster->mutable_transport_socket()->CopyFrom(base_tls_socket);
    stats_cluster->mutable_load_assignment()->set_cluster_name("stats");
    auto* address = stats_cluster->mutable_load_assignment()
                        ->add_endpoints()
                        ->add_lb_endpoints()
                        ->mutable_endpoint()
                        ->mutable_address();
    address->mutable_socket_address()->set_address(stats_domain_);
    address->mutable_socket_address()->set_port_value(443);
    (*stats_cluster->mutable_typed_extension_protocol_options())
        ["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]
            .PackFrom(h2_protocol_options);
    stats_cluster->mutable_wait_for_warm_on_init();
  }

  // Base cluster config (DFP cluster config)
  auto* base_cluster = static_resources->add_clusters();
  envoy::extensions::clusters::dynamic_forward_proxy::v3::ClusterConfig base_cluster_config;
  envoy::config::cluster::v3::Cluster::CustomClusterType base_cluster_type;
  base_cluster_config.mutable_dns_cache_config()->CopyFrom(*dns_cache_config);
  base_cluster_type.set_name("envoy.clusters.dynamic_forward_proxy");
  base_cluster_type.mutable_typed_config()->PackFrom(base_cluster_config);

  auto* upstream_opts = base_cluster->mutable_upstream_connection_options();
  upstream_opts->set_set_local_interface_name_on_upstream_connections(true);
  upstream_opts->mutable_tcp_keepalive()->mutable_keepalive_interval()->set_value(5);
  upstream_opts->mutable_tcp_keepalive()->mutable_keepalive_probes()->set_value(1);
  upstream_opts->mutable_tcp_keepalive()->mutable_keepalive_time()->set_value(10);

  auto* circuit_breaker_settings = base_cluster->mutable_circuit_breakers();
  auto* breaker1 = circuit_breaker_settings->add_thresholds();
  breaker1->set_priority(envoy::config::core::v3::RoutingPriority::DEFAULT);
  breaker1->mutable_retry_budget()->mutable_budget_percent()->set_value(100);
  breaker1->mutable_retry_budget()->mutable_min_retry_concurrency()->set_value(0xffffffff);
  auto* breaker2 = circuit_breaker_settings->add_per_host_thresholds();
  breaker2->set_priority(envoy::config::core::v3::RoutingPriority::DEFAULT);
  breaker2->mutable_max_connections()->set_value(max_connections_per_host_);

  envoy::extensions::upstreams::http::v3::HttpProtocolOptions alpn_options;
  alpn_options.mutable_upstream_http_protocol_options()->set_auto_sni(true);
  alpn_options.mutable_upstream_http_protocol_options()->set_auto_san_validation(true);
  auto* h2_options = alpn_options.mutable_auto_config()->mutable_http2_protocol_options();
  if (h2_connection_keepalive_idle_interval_milliseconds_ > 1000) {
    h2_options->mutable_connection_keepalive()->mutable_connection_idle_interval()->set_seconds(
        h2_connection_keepalive_idle_interval_milliseconds_ / 1000);
  } else {
    h2_options->mutable_connection_keepalive()->mutable_connection_idle_interval()->set_nanos(
        h2_connection_keepalive_idle_interval_milliseconds_ * 1000 * 1000);
  }
  h2_options->mutable_connection_keepalive()->mutable_timeout()->set_seconds(
      h2_connection_keepalive_timeout_seconds_);
  h2_options->mutable_max_concurrent_streams()->set_value(100);

  envoy::extensions::http::header_formatters::preserve_case::v3::PreserveCaseFormatterConfig
      preserve_case_config;
  preserve_case_config.set_forward_reason_phrase(false);
  preserve_case_config.set_formatter_type_on_envoy_headers(
      envoy::extensions::http::header_formatters::preserve_case::v3::PreserveCaseFormatterConfig::
          DEFAULT);

  auto* h1_options = alpn_options.mutable_auto_config()->mutable_http_protocol_options();
  auto* formatter = h1_options->mutable_header_key_format()->mutable_stateful_formatter();
  formatter->set_name("preserve_case");
  formatter->mutable_typed_config()->PackFrom(preserve_case_config);

  // Base cluster
  base_cluster->set_name("base");
  base_cluster->mutable_connect_timeout()->set_seconds(connect_timeout_seconds_);
  base_cluster->set_lb_policy(envoy::config::cluster::v3::Cluster::CLUSTER_PROVIDED);
  (*base_cluster->mutable_typed_extension_protocol_options())
      ["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]
          .PackFrom(alpn_options);
  base_cluster->mutable_cluster_type()->CopyFrom(base_cluster_type);
  base_cluster->mutable_transport_socket()->set_name("envoy.transport_sockets.http_11_proxy");
  base_cluster->mutable_transport_socket()->mutable_typed_config()->PackFrom(ssl_proxy_socket);

  // Base clear-text cluster set up
  envoy::extensions::transport_sockets::raw_buffer::v3::RawBuffer raw_buffer;
  envoy::extensions::transport_sockets::http_11_proxy::v3::Http11ProxyUpstreamTransport
      cleartext_proxy_socket;
  cleartext_proxy_socket.mutable_transport_socket()->mutable_typed_config()->PackFrom(raw_buffer);
  cleartext_proxy_socket.mutable_transport_socket()->set_name("envoy.transport_sockets.raw_buffer");
  envoy::extensions::upstreams::http::v3::HttpProtocolOptions h1_protocol_options;
  h1_protocol_options.mutable_upstream_http_protocol_options()->set_auto_sni(true);
  h1_protocol_options.mutable_upstream_http_protocol_options()->set_auto_san_validation(true);
  h1_protocol_options.mutable_explicit_http_config()->mutable_http_protocol_options()->CopyFrom(
      *alpn_options.mutable_auto_config()->mutable_http_protocol_options());

  // Base clear-text cluster.
  auto* base_clear = static_resources->add_clusters();
  base_clear->set_name("base_clear");
  base_clear->mutable_connect_timeout()->set_seconds(connect_timeout_seconds_);
  base_clear->set_lb_policy(envoy::config::cluster::v3::Cluster::CLUSTER_PROVIDED);
  base_clear->mutable_cluster_type()->CopyFrom(base_cluster_type);
  base_clear->mutable_transport_socket()->set_name("envoy.transport_sockets.http_11_proxy");
  base_clear->mutable_transport_socket()->mutable_typed_config()->PackFrom(cleartext_proxy_socket);
  base_clear->mutable_upstream_connection_options()->CopyFrom(
      *base_cluster->mutable_upstream_connection_options());
  base_clear->mutable_circuit_breakers()->CopyFrom(*base_cluster->mutable_circuit_breakers());
  (*base_clear->mutable_typed_extension_protocol_options())
      ["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]
          .PackFrom(h1_protocol_options);

  // Edit and re-pack
  tls_socket.mutable_common_tls_context()->add_alpn_protocols("h2");
  ssl_proxy_socket.mutable_transport_socket()->mutable_typed_config()->PackFrom(tls_socket);

  // Edit base cluster to be an HTTP/3 cluster.
  if (enable_http3_) {
    envoy::extensions::transport_sockets::quic::v3::QuicUpstreamTransport h3_inner_socket;
    tls_socket.mutable_common_tls_context()->mutable_alpn_protocols()->Clear();
    h3_inner_socket.mutable_upstream_tls_context()->CopyFrom(tls_socket);
    envoy::extensions::transport_sockets::http_11_proxy::v3::Http11ProxyUpstreamTransport
        h3_proxy_socket;
    h3_proxy_socket.mutable_transport_socket()->mutable_typed_config()->PackFrom(h3_inner_socket);
    h3_proxy_socket.mutable_transport_socket()->set_name("envoy.transport_sockets.quic");
    alpn_options.mutable_auto_config()->mutable_http3_protocol_options();
    alpn_options.mutable_auto_config()->mutable_alternate_protocols_cache_options()->set_name(
        "default_alternate_protocols_cache");

    base_cluster->mutable_transport_socket()->mutable_typed_config()->PackFrom(h3_proxy_socket);
    (*base_cluster->mutable_typed_extension_protocol_options())
        ["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]
            .PackFrom(alpn_options);
  }

  // Set up stats.
  bootstrap->mutable_stats_flush_interval()->set_seconds(stats_flush_seconds_);
  bootstrap->mutable_stats_sinks();
  auto* list = bootstrap->mutable_stats_config()->mutable_stats_matcher()->mutable_inclusion_list();
  list->add_patterns()->set_prefix("cluster.base.upstream_rq_");
  list->add_patterns()->set_prefix("cluster.stats.upstream_rq_");
  list->add_patterns()->set_prefix("cluster.base.upstream_cx_");
  list->add_patterns()->set_prefix("cluster.stats.upstream_cx_");
  list->add_patterns()->set_exact("cluster.base.http2.keepalive_timeout");
  list->add_patterns()->set_exact("cluster.stats.http2.keepalive_timeout");
  list->add_patterns()->set_prefix("http.hcm.downstream_rq_");
  list->add_patterns()->set_prefix("http.hcm.decompressor.");
  list->add_patterns()->set_prefix("pulse.");
  list->add_patterns()->set_prefix("runtime.load_success");
  list->add_patterns()->mutable_safe_regex()->set_regex(
      "^vhost\\.[\\w]+\\.vcluster\\.[\\w]+?\\.upstream_rq_(?:[12345]xx|[3-5][0-9][0-9]|retry|"
      "total)");
  bootstrap->mutable_stats_config()->mutable_use_all_default_tags()->set_value(false);

  // Set up watchdog
  auto* watchdog = bootstrap->mutable_watchdogs();
  watchdog->mutable_main_thread_watchdog()->mutable_megamiss_timeout()->set_seconds(60);
  watchdog->mutable_main_thread_watchdog()->mutable_miss_timeout()->set_seconds(60);
  watchdog->mutable_worker_watchdog()->mutable_megamiss_timeout()->set_seconds(60);
  watchdog->mutable_worker_watchdog()->mutable_miss_timeout()->set_seconds(60);

  // Set up node
  auto* node = bootstrap->mutable_node();
  node->set_id(node_id_.empty() ? "envoy-mobile" : node_id_);
  node->set_cluster("envoy-mobile");
  if (node_locality_ && !node_locality_->region.empty()) {
    node->mutable_locality()->set_region(node_locality_->region);
    node->mutable_locality()->set_zone(node_locality_->zone);
    node->mutable_locality()->set_sub_zone(node_locality_->sub_zone);
  }
  ProtobufWkt::Struct& metadata = *node->mutable_metadata();
  (*metadata.mutable_fields())["app_id"].set_string_value(app_id_);
  (*metadata.mutable_fields())["app_version"].set_string_value(app_version_);
  (*metadata.mutable_fields())["device_os"].set_string_value(device_os_);

  // Set up runtime.
  auto* runtime = bootstrap->mutable_layered_runtime()->add_layers();
  runtime->set_name("static_layer_0");
  ProtobufWkt::Struct envoy_layer;
  ProtobufWkt::Struct& runtime_values =
      *(*envoy_layer.mutable_fields())["envoy"].mutable_struct_value();
  ProtobufWkt::Struct& flags =
      *(*runtime_values.mutable_fields())["reloadable_features"].mutable_struct_value();
  for (auto& guard_and_value : runtime_guards_) {
    (*flags.mutable_fields())[guard_and_value.first].set_bool_value(guard_and_value.second);
  }
  (*flags.mutable_fields())["always_use_v6"].set_bool_value(always_use_v6_);
  (*flags.mutable_fields())["skip_dns_lookup_for_proxied_requests"].set_bool_value(
      skip_dns_lookups_for_proxied_requests_);
  (*runtime_values.mutable_fields())["disallow_global_stats"].set_bool_value(true);
  ProtobufWkt::Struct& overload_values =
      *(*envoy_layer.mutable_fields())["overload"].mutable_struct_value();
  (*overload_values.mutable_fields())["global_downstream_max_connections"].set_string_value(
      "4294967295");
  runtime->mutable_static_layer()->MergeFrom(envoy_layer);

  bootstrap->mutable_typed_dns_resolver_config()->CopyFrom(
      *dns_cache_config->mutable_typed_dns_resolver_config());

  for (const std::string& sink_yaml : stats_sinks_) {
    auto* sink = bootstrap->add_stats_sinks();
    MessageUtil::loadFromYaml(sink_yaml, *sink, ProtobufMessage::getStrictValidationVisitor());
  }
  if (!stats_domain_.empty()) {
    envoy::config::metrics::v3::MetricsServiceConfig metrics_config;
    metrics_config.mutable_grpc_service()->mutable_envoy_grpc()->set_cluster_name("stats");
    metrics_config.mutable_report_counters_as_deltas()->set_value(true);
    metrics_config.set_transport_api_version(envoy::config::core::v3::ApiVersion::V3);
    metrics_config.set_emit_tags_as_labels(true);
    auto* sink = bootstrap->add_stats_sinks();
    sink->set_name("envoy.metrics_service");
    sink->mutable_typed_config()->PackFrom(metrics_config);
  }

  bootstrap->mutable_dynamic_resources();
  if ((!rtds_layer_name_.empty() || enable_cds_) && ads_address_.empty()) {
    throw std::runtime_error("ADS must be configured when using xDS");
  }
  if (!rtds_layer_name_.empty()) {
    auto* layered_runtime = bootstrap->mutable_layered_runtime();
    auto* layer = layered_runtime->add_layers();
    layer->set_name(rtds_layer_name_);
    auto* rtds_layer = layer->mutable_rtds_layer();
    rtds_layer->set_name(rtds_layer_name_);
    auto* rtds_config = rtds_layer->mutable_rtds_config();
    rtds_config->mutable_ads();
    rtds_config->set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
    rtds_config->mutable_initial_fetch_timeout()->set_seconds(rtds_timeout_seconds_);
  }
  if (!ads_address_.empty()) {
    std::string target_uri = fmt::format(R"({}:{})", ads_address_, ads_port_);
    auto* ads_config = bootstrap->mutable_dynamic_resources()->mutable_ads_config();
    ads_config->set_transport_api_version(envoy::config::core::v3::ApiVersion::V3);
    ads_config->set_set_node_on_first_message_only(true);
    ads_config->set_api_type(envoy::config::core::v3::ApiConfigSource::GRPC);
    auto& grpc_service = *ads_config->add_grpc_services();
    grpc_service.mutable_google_grpc()->set_target_uri(target_uri);
    grpc_service.mutable_google_grpc()->set_stat_prefix("ads");
    if (!ads_ssl_root_certs_.empty()) {
      grpc_service.mutable_google_grpc()
          ->mutable_channel_credentials()
          ->mutable_ssl_credentials()
          ->mutable_root_certs()
          ->set_inline_string(ads_ssl_root_certs_);
    }
    if (!ads_jwt_token_.empty()) {
      auto& jwt = *grpc_service.mutable_google_grpc()
                       ->add_call_credentials()
                       ->mutable_service_account_jwt_access();
      jwt.set_json_key(ads_jwt_token_);
      jwt.set_token_lifetime_seconds(ads_jwt_token_lifetime_seconds_);
    }
  }
  if (enable_cds_) {
    auto* cds_config = bootstrap->mutable_dynamic_resources()->mutable_cds_config();
    if (cds_resources_locator_.empty()) {
      cds_config->mutable_ads();
    } else {
      bootstrap->mutable_dynamic_resources()->set_cds_resources_locator(cds_resources_locator_);
      cds_config->mutable_api_config_source()->set_api_type(
          envoy::config::core::v3::ApiConfigSource::AGGREGATED_GRPC);
      cds_config->mutable_api_config_source()->set_transport_api_version(
          envoy::config::core::v3::ApiVersion::V3);
    }
    cds_config->mutable_initial_fetch_timeout()->set_seconds(cds_timeout_seconds_);
    cds_config->set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
    bootstrap->add_node_context_params("cluster");
    // add a stat prefix we use in test
    list->add_patterns()->set_exact("cluster_manager.active_clusters");
    list->add_patterns()->set_exact("cluster_manager.cluster_added");
  }

  // Admin
  if (admin_interface_enabled_) {
#ifdef ENVOY_ADMIN_FUNCTIONALITY
    auto* admin_address = bootstrap->mutable_admin()->mutable_address()->mutable_socket_address();
    admin_address->set_address("::1");
    admin_address->set_port_value(9901);
#else
    throw std::runtime_error("Admin functionality was not compiled in this build of Envoy Mobile");
#endif
  } else {
    // Default Envoy mobile to the lightweight API listener. This is not
    // supported if the admin interface is enabled.
    envoy::config::listener::v3::ApiListenerManager api;
    auto* listener_manager = bootstrap->mutable_listener_manager();
    listener_manager->mutable_typed_config()->PackFrom(api);
    listener_manager->set_name("envoy.listener_manager_impl.api");
  }

  return bootstrap;
}

EngineSharedPtr EngineBuilder::build() {
  envoy_logger null_logger;
  null_logger.log = nullptr;
  null_logger.release = envoy_noop_const_release;
  null_logger.context = nullptr;

  envoy_event_tracker null_tracker{};

  std::unique_ptr<envoy::config::bootstrap::v3::Bootstrap> bootstrap;
  if (config_override_for_tests_.empty()) {
    bootstrap = generateBootstrap();
  }

  envoy_engine_t envoy_engine =
      init_engine(callbacks_->asEnvoyEngineCallbacks(), null_logger, null_tracker);

  for (const auto& [name, store] : key_value_stores_) {
    // TODO(goaway): This leaks, but it's tied to the life of the engine.
    auto* api = new envoy_kv_store();
    *api = store->asEnvoyKeyValueStore();
    register_platform_api(name.c_str(), api);
  }

  for (const auto& [name, accessor] : string_accessors_) {
    // TODO(RyanTheOptimist): This leaks, but it's tied to the life of the engine.
    auto* api = new envoy_string_accessor();
    *api = StringAccessor::asEnvoyStringAccessor(accessor);
    register_platform_api(name.c_str(), api);
  }

  Engine* engine = new Engine(envoy_engine);

  if (auto cast_engine = reinterpret_cast<Envoy::Engine*>(envoy_engine)) {
    auto options = std::make_unique<Envoy::OptionsImpl>();
    if (bootstrap) {
      options->setConfigProto(std::move(bootstrap));
    } else {
      options->setConfigYaml(config_override_for_tests_);
    }
    options->setLogLevel(options->parseAndValidateLogLevel(logLevelToString(log_level_).c_str()));
    options->setConcurrency(1);
    cast_engine->run(std::move(options));
  }

  // we can't construct via std::make_shared
  // because Engine is only constructible as a friend
  auto engine_ptr = EngineSharedPtr(engine);
  return engine_ptr;
}

} // namespace Platform
} // namespace Envoy
