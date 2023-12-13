#include <string>
#include <vector>

#include "test/test_common/utility.h"

#include "absl/strings/str_replace.h"
#include "absl/synchronization/notification.h"
#include "gtest/gtest.h"
#include "library/cc/engine_builder.h"
#include "library/cc/log_level.h"
#include "library/common/api/external.h"
#include "library/common/data/utility.h"

#if defined(__APPLE__)
#include "source/extensions/network/dns_resolver/apple/apple_dns_impl.h"
#endif

using envoy::config::bootstrap::v3::Bootstrap;
using testing::HasSubstr;
using testing::IsEmpty;
using testing::Not;
using testing::SizeIs;

namespace Envoy {
namespace {

using namespace Platform;

TEST(TestConfig, ConfigIsApplied) {
  EngineBuilder engine_builder;
  engine_builder
#ifdef ENVOY_MOBILE_STATS_REPORTING
      .addGrpcStatsDomain("asdf.fake.website")
      .addStatsFlushSeconds(654)
#endif
      .addConnectTimeoutSeconds(123)
      .addDnsRefreshSeconds(456)
      .addDnsMinRefreshSeconds(567)
      .addDnsFailureRefreshSeconds(789, 987)
      .addDnsQueryTimeoutSeconds(321)
      .addH2ConnectionKeepaliveIdleIntervalMilliseconds(222)
      .addH2ConnectionKeepaliveTimeoutSeconds(333)
      .setAppVersion("1.2.3")
      .setAppId("1234-1234-1234")
      .setRuntimeGuard("test_feature_false", true)
      .enableDnsCache(true, /* save_interval_seconds */ 101)
      .addDnsPreresolveHostnames({"lyft.com", "google.com"})
#ifdef ENVOY_ADMIN_FUNCTIONALITY
      .enableAdminInterface(true)
#endif
      .setForceAlwaysUsev6(true)
#ifdef ENVOY_GOOGLE_GRPC
      .setNodeId("my_test_node")
#endif
      .setDeviceOs("probably-ubuntu-on-CI");

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  const std::string config_str = bootstrap->ShortDebugString();

  std::vector<std::string> must_contain = {
      "connect_timeout { seconds: 123 }",
      "dns_refresh_rate { seconds: 456 }",
      "dns_min_refresh_rate { seconds: 567 }",
      "dns_query_timeout { seconds: 321 }",
      "dns_failure_refresh_rate { base_interval { seconds: 789 } max_interval { seconds: 987 } }",
      "connection_idle_interval { nanos: 222000000 }",
      "connection_keepalive { timeout { seconds: 333 }",
#ifdef ENVOY_MOBILE_STATS_REPORTING
      "asdf.fake.website",
      "stats_flush_interval { seconds: 654 }",
#endif
      "key: \"dns_persistent_cache\" save_interval { seconds: 101 }",
      "key: \"always_use_v6\" value { bool_value: true }",
      "key: \"test_feature_false\" value { bool_value: true }",
      "key: \"device_os\" value { string_value: \"probably-ubuntu-on-CI\" } }",
      "key: \"app_version\" value { string_value: \"1.2.3\" } }",
      "key: \"app_id\" value { string_value: \"1234-1234-1234\" } }",
      "validation_context { trusted_ca {",
  };

  for (const auto& string : must_contain) {
    EXPECT_THAT(config_str, HasSubstr(string)) << "'" << string << "' not found in " << config_str;
  }
}

TEST(TestConfig, MultiFlag) {
  EngineBuilder engine_builder;
  engine_builder.setRuntimeGuard("test_feature_false", true)
      .setRuntimeGuard("test_feature_true", false);

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  const std::string bootstrap_str = bootstrap->ShortDebugString();
  EXPECT_THAT(bootstrap_str, HasSubstr("\"test_feature_false\" value { bool_value: true }"));
  EXPECT_THAT(bootstrap_str, HasSubstr("\"test_feature_true\" value { bool_value: false }"));
}

TEST(TestConfig, ConfigIsValid) {
  EngineBuilder engine_builder;
  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();

  // Test per-platform DNS fixes.
#if defined(__APPLE__)
  EXPECT_THAT(bootstrap->DebugString(), Not(HasSubstr("envoy.network.dns_resolver.getaddrinfo")));
  EXPECT_THAT(bootstrap->DebugString(), HasSubstr("envoy.network.dns_resolver.apple"));
#else
  EXPECT_THAT(bootstrap->DebugString(), HasSubstr("envoy.network.dns_resolver.getaddrinfo"));
  EXPECT_THAT(bootstrap->DebugString(), Not(HasSubstr("envoy.network.dns_resolver.apple")));
#endif
}

TEST(TestConfig, SetGzipDecompression) {
  EngineBuilder engine_builder;

  engine_builder.enableGzipDecompression(false);
  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->DebugString(), Not(HasSubstr("envoy.filters.http.decompressor")));

  engine_builder.enableGzipDecompression(true);
  bootstrap.reset();
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->DebugString(), HasSubstr("envoy.filters.http.decompressor"));
}

TEST(TestConfig, SetBrotliDecompression) {
  EngineBuilder engine_builder;

  engine_builder.enableBrotliDecompression(false);
  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->DebugString(), Not(HasSubstr("brotli.decompressor.v3.Brotli")));

  engine_builder.enableBrotliDecompression(true);
  bootstrap.reset();
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->DebugString(), HasSubstr("brotli.decompressor.v3.Brotli"));
}

TEST(TestConfig, SetSocketTag) {
  EngineBuilder engine_builder;

  engine_builder.enableSocketTagging(false);
  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->DebugString(), Not(HasSubstr("http.socket_tag.SocketTag")));

  engine_builder.enableSocketTagging(true);
  bootstrap.reset();
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->DebugString(), HasSubstr("http.socket_tag.SocketTag"));
}

#ifdef ENVOY_ENABLE_QUIC
TEST(TestConfig, SetAltSvcCache) {
  EngineBuilder engine_builder;
  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->DebugString(), HasSubstr("alternate_protocols_cache"));
}
#endif

TEST(TestConfig, StreamIdleTimeout) {
  EngineBuilder engine_builder;

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("stream_idle_timeout { seconds: 15 }"));

  engine_builder.setStreamIdleTimeoutSeconds(42);
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("stream_idle_timeout { seconds: 42 }"));
}

TEST(TestConfig, PerTryIdleTimeout) {
  EngineBuilder engine_builder;

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("per_try_idle_timeout { seconds: 15 }"));

  engine_builder.setPerTryIdleTimeoutSeconds(42);
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("per_try_idle_timeout { seconds: 42 }"));
}

#ifdef ENVOY_ADMIN_FUNCTIONALITY
TEST(TestConfig, EnableAdminInterface) {
  EngineBuilder engine_builder;

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_FALSE(bootstrap->has_admin());

  engine_builder.enableAdminInterface(true);
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_TRUE(bootstrap->has_admin());
}
#endif

TEST(TestConfig, EnableInterfaceBinding) {
  EngineBuilder engine_builder;

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), Not(HasSubstr("enable_interface_binding")));

  engine_builder.enableInterfaceBinding(true);
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("enable_interface_binding: true"));
}

TEST(TestConfig, EnableDrainPostDnsRefresh) {
  EngineBuilder engine_builder;

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), Not(HasSubstr("enable_drain_post_dns_refresh")));

  engine_builder.enableDrainPostDnsRefresh(true);
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("enable_drain_post_dns_refresh: true"));
}

TEST(TestConfig, EnableHappyEyeballs) {
  EngineBuilder engine_builder;

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  std::string bootstrap_str = bootstrap->ShortDebugString();
  EXPECT_THAT(bootstrap_str, Not(HasSubstr("dns_lookup_family: V4_PREFERRED")));
  EXPECT_THAT(bootstrap_str, HasSubstr("dns_lookup_family: ALL"));

  engine_builder.enableHappyEyeballs(false);
  bootstrap = engine_builder.generateBootstrap();
  bootstrap_str = bootstrap->ShortDebugString();
  EXPECT_THAT(bootstrap_str, HasSubstr("dns_lookup_family: V4_PREFERRED"));
  EXPECT_THAT(bootstrap_str, Not(HasSubstr("dns_lookup_family: ALL")));
}

TEST(TestConfig, EnforceTrustChainVerification) {
  EngineBuilder engine_builder;

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), Not(HasSubstr("trust_chain_verification")));

  engine_builder.enforceTrustChainVerification(false);
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(),
              HasSubstr("trust_chain_verification: ACCEPT_UNTRUSTED"));
}

TEST(TestConfig, AddMaxConnectionsPerHost) {
  EngineBuilder engine_builder;

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("max_connections { value: 7 }"));

  engine_builder.addMaxConnectionsPerHost(16);
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("max_connections { value: 16 }"));
}

#ifdef ENVOY_MOBILE_STATS_REPORTING
std::string statsdSinkConfig(int port) {
  std::string config = R"({ name: envoy.stat_sinks.statsd,
      typed_config: {
        "@type": type.googleapis.com/envoy.config.metrics.v3.StatsdSink,
        address: { socket_address: { address: 127.0.0.1, port_value: )" +
                       fmt::format("{}", port) + " } } } }";
  return config;
}

TEST(TestConfig, AddStatsSinks) {
  EngineBuilder engine_builder;

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_EQ(bootstrap->stats_sinks_size(), 0);

  engine_builder.addStatsSinks({statsdSinkConfig(1), statsdSinkConfig(2)});
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_EQ(bootstrap->stats_sinks_size(), 2);
}
#endif

TEST(TestConfig, DisableHttp3) {
  EngineBuilder engine_builder;

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
#ifdef ENVOY_ENABLE_QUIC
  EXPECT_THAT(bootstrap->ShortDebugString(),
              HasSubstr("envoy.extensions.filters.http.alternate_protocols_cache.v3.FilterConfig"));
#endif
#ifndef ENVOY_ENABLE_QUIC
  EXPECT_THAT(
      bootstrap->ShortDebugString(),
      Not(HasSubstr("envoy.extensions.filters.http.alternate_protocols_cache.v3.FilterConfig")));
#endif

#ifdef ENVOY_ENABLE_QUIC
  engine_builder.enableHttp3(false);
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(
      bootstrap->ShortDebugString(),
      Not(HasSubstr("envoy.extensions.filters.http.alternate_protocols_cache.v3.FilterConfig")));
#endif
}
#ifdef ENVOY_GOOGLE_GRPC
TEST(TestConfig, RtdsWithoutAds) {
  EngineBuilder engine_builder;
  engine_builder.addRtdsLayer("some rtds layer");
  try {
    engine_builder.generateBootstrap();
    FAIL() << "Expected std::runtime_error";
  } catch (std::runtime_error& err) {
    EXPECT_EQ(err.what(), std::string("ADS must be configured when using xDS"));
  }
}

TEST(TestConfig, AdsConfig) {
  EngineBuilder engine_builder;
  engine_builder.setAggregatedDiscoveryService(/*target_uri=*/"fake-td.googleapis.com",
                                               /*port=*/12345);
  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  auto& ads_config = bootstrap->dynamic_resources().ads_config();
  EXPECT_EQ(ads_config.api_type(), envoy::config::core::v3::ApiConfigSource::GRPC);
  EXPECT_EQ(ads_config.grpc_services(0).google_grpc().target_uri(), "fake-td.googleapis.com:12345");
  EXPECT_EQ(ads_config.grpc_services(0).google_grpc().stat_prefix(), "ads");
  EXPECT_THAT(ads_config.grpc_services(0)
                  .google_grpc()
                  .channel_credentials()
                  .ssl_credentials()
                  .root_certs()
                  .inline_string(),
              IsEmpty());
  EXPECT_THAT(ads_config.grpc_services(0).google_grpc().call_credentials(), SizeIs(0));

  // With security credentials.
  engine_builder.setAggregatedDiscoveryService(/*target_uri=*/"fake-td.googleapis.com",
                                               /*port=*/12345, /*jwt_token=*/"my_jwt_token",
                                               /*jwt_token_lifetime_seconds=*/500,
                                               /*ssl_root_certs=*/"my_root_cert");
  bootstrap = engine_builder.generateBootstrap();
  auto& ads_config_with_tokens = bootstrap->dynamic_resources().ads_config();
  EXPECT_EQ(ads_config_with_tokens.api_type(), envoy::config::core::v3::ApiConfigSource::GRPC);
  EXPECT_EQ(ads_config_with_tokens.grpc_services(0).google_grpc().target_uri(),
            "fake-td.googleapis.com:12345");
  EXPECT_EQ(ads_config_with_tokens.grpc_services(0).google_grpc().stat_prefix(), "ads");
  EXPECT_EQ(ads_config_with_tokens.grpc_services(0)
                .google_grpc()
                .channel_credentials()
                .ssl_credentials()
                .root_certs()
                .inline_string(),
            "my_root_cert");
  EXPECT_EQ(ads_config_with_tokens.grpc_services(0)
                .google_grpc()
                .call_credentials(0)
                .service_account_jwt_access()
                .json_key(),
            "my_jwt_token");
  EXPECT_EQ(ads_config_with_tokens.grpc_services(0)
                .google_grpc()
                .call_credentials(0)
                .service_account_jwt_access()
                .token_lifetime_seconds(),
            500);
}
#endif

TEST(TestConfig, EnablePlatformCertificatesValidation) {
  EngineBuilder engine_builder;
  engine_builder.enablePlatformCertificatesValidation(false);
  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(),
              Not(HasSubstr("envoy_mobile.cert_validator.platform_bridge_cert_validator")));
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("trusted_ca"));

  engine_builder.enablePlatformCertificatesValidation(true);
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(),
              HasSubstr("envoy_mobile.cert_validator.platform_bridge_cert_validator"));
  EXPECT_THAT(bootstrap->ShortDebugString(), Not(HasSubstr("trusted_ca")));
}

// Implementation of StringAccessor which tracks the number of times it was used.
class TestStringAccessor : public StringAccessor {
public:
  explicit TestStringAccessor(std::string data) : data_(data) {}
  ~TestStringAccessor() override = default;

  // StringAccessor
  const std::string& get() const override {
    ++count_;
    return data_;
  }

  int count() { return count_; }

private:
  std::string data_;
  mutable int count_ = 0;
};

TEST(TestConfig, AddNativeFilters) {
  EngineBuilder engine_builder;

  std::string filter_name1 = "envoy.filters.http.buffer1";
  std::string filter_name2 = "envoy.filters.http.buffer2";
  std::string filter_config =
      "{\"@type\":\"type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer\","
      "\"max_request_bytes\":5242880}";
  engine_builder.addNativeFilter(filter_name1, filter_config);
  engine_builder.addNativeFilter(filter_name2, filter_config);

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  const std::string hcm_config =
      bootstrap->static_resources().listeners(0).api_listener().DebugString();
  EXPECT_THAT(hcm_config, HasSubstr(filter_name1));
  EXPECT_THAT(hcm_config, HasSubstr(filter_name2));
  EXPECT_THAT(hcm_config,
              HasSubstr("type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer"));
  EXPECT_THAT(hcm_config, HasSubstr(std::to_string(5242880)));
}

TEST(TestConfig, AddPlatformFilter) {
  EngineBuilder engine_builder;

  std::string filter_name = "test_platform_filter";

  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  std::string bootstrap_str = bootstrap->ShortDebugString();
  EXPECT_THAT(bootstrap_str, Not(HasSubstr("http.platform_bridge.PlatformBridge")));
  EXPECT_THAT(bootstrap_str, Not(HasSubstr("platform_filter_name: \"" + filter_name + "\"")));

  engine_builder.addPlatformFilter(filter_name);
  bootstrap = engine_builder.generateBootstrap();
  bootstrap_str = bootstrap->ShortDebugString();
  EXPECT_THAT(bootstrap_str, HasSubstr("http.platform_bridge.PlatformBridge"));
  EXPECT_THAT(bootstrap_str, HasSubstr("platform_filter_name: \"" + filter_name + "\""));
}

// TODO(RyanTheOptimist): This test seems to be flaky. #2641
TEST(TestConfig, DISABLED_StringAccessors) {
  std::string name("accessor_name");
  EngineBuilder engine_builder;
  std::string data_string = "envoy string";
  auto accessor = std::make_shared<TestStringAccessor>(data_string);
  engine_builder.addStringAccessor(name, accessor);
  EngineSharedPtr engine = engine_builder.build();
  auto c_accessor = static_cast<envoy_string_accessor*>(Envoy::Api::External::retrieveApi(name));
  ASSERT_TRUE(c_accessor != nullptr);
  EXPECT_EQ(0, accessor->count());
  envoy_data data = c_accessor->get_string(c_accessor->context);
  EXPECT_EQ(1, accessor->count());
  EXPECT_EQ(data_string, Data::Utility::copyToString(data));
  release_envoy_data(data);
}

TEST(TestConfig, AddVirtualClusterLegacy) {
  EngineBuilder engine_builder;

  engine_builder.addVirtualCluster(
      "{headers: [{name: ':method', string_match: {exact: POST}}], name: cluster1}");
  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("cluster1"));

  engine_builder.addVirtualCluster(
      "{headers: [{name: ':method', string_match: {exact: GET}}], name: cluster2}");
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("cluster2"));
}

TEST(TestConfig, AddVirtualCluster) {
  EngineBuilder engine_builder;

  std::vector<MatcherData> matchers = {{":method", MatcherData::EXACT, "POST"},
                                       {":method", MatcherData::SAFE_REGEX, ".*E.*"}};
  engine_builder.addVirtualCluster("cluster1", matchers);
  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("cluster1"));

  engine_builder.addVirtualCluster("cluster2", matchers);
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("cluster1"));
  EXPECT_THAT(bootstrap->ShortDebugString(), HasSubstr("cluster2"));
}

#ifdef ENVOY_GOOGLE_GRPC
TEST(TestConfig, SetNodeId) {
  EngineBuilder engine_builder;
  const std::string default_node_id = "envoy-mobile";
  EXPECT_EQ(engine_builder.generateBootstrap()->node().id(), default_node_id);

  const std::string test_node_id = "my_test_node";
  engine_builder.setNodeId(test_node_id);
  EXPECT_EQ(engine_builder.generateBootstrap()->node().id(), test_node_id);
}

TEST(TestConfig, SetNodeLocality) {
  EngineBuilder engine_builder;
  const std::string region = "us-west-1";
  const std::string zone = "some_zone";
  const std::string sub_zone = "some_sub_zone";
  engine_builder.setNodeLocality(region, zone, sub_zone);
  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_EQ(bootstrap->node().locality().region(), region);
  EXPECT_EQ(bootstrap->node().locality().zone(), zone);
  EXPECT_EQ(bootstrap->node().locality().sub_zone(), sub_zone);
}

TEST(TestConfig, AddCdsLayer) {
  EngineBuilder engine_builder;
  engine_builder.setAggregatedDiscoveryService(/*address=*/"fake-xds-server", /*port=*/12345);

  engine_builder.addCdsLayer();
  std::unique_ptr<Bootstrap> bootstrap = engine_builder.generateBootstrap();
  EXPECT_EQ(bootstrap->dynamic_resources().cds_resources_locator(), "");
  EXPECT_EQ(bootstrap->dynamic_resources().cds_config().initial_fetch_timeout().seconds(),
            /*default_timeout=*/5);

  const std::string cds_resources_locator =
      "xdstp://traffic-director-global.xds.googleapis.com/envoy.config.cluster.v3.Cluster";
  const int timeout_seconds = 300;
  engine_builder.addCdsLayer(cds_resources_locator, timeout_seconds);
  bootstrap = engine_builder.generateBootstrap();
  EXPECT_EQ(bootstrap->dynamic_resources().cds_resources_locator(), cds_resources_locator);
  EXPECT_EQ(bootstrap->dynamic_resources().cds_config().initial_fetch_timeout().seconds(),
            timeout_seconds);
  EXPECT_EQ(bootstrap->dynamic_resources().cds_config().api_config_source().api_type(),
            envoy::config::core::v3::ApiConfigSource::AGGREGATED_GRPC);
  EXPECT_EQ(bootstrap->dynamic_resources().cds_config().api_config_source().transport_api_version(),
            envoy::config::core::v3::ApiVersion::V3);
}
#endif

} // namespace
} // namespace Envoy
