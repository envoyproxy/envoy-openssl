package io.envoyproxy.envoymobile.engine

import io.envoyproxy.envoymobile.engine.types.EnvoyHTTPFilter
import io.envoyproxy.envoymobile.engine.types.EnvoyHTTPFilterFactory
import io.envoyproxy.envoymobile.engine.EnvoyConfiguration.TrustChainVerification
import io.envoyproxy.envoymobile.engine.JniLibrary
import io.envoyproxy.envoymobile.engine.VirtualClusterConfig
import io.envoyproxy.envoymobile.engine.HeaderMatchConfig
import io.envoyproxy.envoymobile.engine.HeaderMatchConfig.Type
import io.envoyproxy.envoymobile.engine.types.EnvoyStreamIntel
import io.envoyproxy.envoymobile.engine.types.EnvoyFinalStreamIntel
import io.envoyproxy.envoymobile.engine.types.EnvoyHTTPFilterCallbacks
import io.envoyproxy.envoymobile.engine.testing.TestJni
import java.nio.ByteBuffer
import org.assertj.core.api.Assertions.assertThat
import org.junit.Assert.fail
import org.junit.Test
import java.util.regex.Pattern

class TestFilter : EnvoyHTTPFilter {

override fun onRequestHeaders(headers: MutableMap<String, MutableList<String>>, endStream: Boolean, streamIntel: EnvoyStreamIntel): Array<Any> {
  return emptyArray()
}
override fun onRequestData(data: ByteBuffer, endStream: Boolean, streamIntel: EnvoyStreamIntel): Array<Any> {
  return emptyArray()
}
override fun onRequestTrailers(trailers: MutableMap<String, MutableList<String>>, streamIntel: EnvoyStreamIntel): Array<Any> {
  return emptyArray()
}
override fun onResponseHeaders(headers: MutableMap<String, MutableList<String>>, endStream: Boolean, streamIntel: EnvoyStreamIntel): Array<Any> {
  return emptyArray()
}
override fun onResponseData(data: ByteBuffer, endStream: Boolean, streamIntel: EnvoyStreamIntel): Array<Any> {
  return emptyArray()
}
override fun onResponseTrailers(trailers: MutableMap<String, MutableList<String>>, streamIntel: EnvoyStreamIntel): Array<Any> {
  return emptyArray()
}
override fun setRequestFilterCallbacks(callbacks: EnvoyHTTPFilterCallbacks) {
}
override fun setResponseFilterCallbacks(callbacks: EnvoyHTTPFilterCallbacks) {
}
override fun onCancel( streamIntel: EnvoyStreamIntel, finalStreamIntel: EnvoyFinalStreamIntel) {
}
override fun onComplete( streamIntel: EnvoyStreamIntel, finalStreamIntel: EnvoyFinalStreamIntel) {
}
override fun onError(errorCode: Int, message: String, attemptCount: Int, streamIntel: EnvoyStreamIntel, finalStreamIntel: EnvoyFinalStreamIntel) {
}
override fun onResumeRequest(headers: MutableMap<String, MutableList<String>>, data: ByteBuffer, trailers: MutableMap<String, MutableList<String>>, endStream: Boolean, streamIntel: EnvoyStreamIntel): Array<Any> {
  return emptyArray()
}
override fun onResumeResponse(headers: MutableMap<String, MutableList<String>>, data: ByteBuffer, trailers: MutableMap<String, MutableList<String>>, endStream: Boolean, streamIntel: EnvoyStreamIntel): Array<Any> {
  return emptyArray()
}
}

class TestEnvoyHTTPFilterFactory(name : String) : EnvoyHTTPFilterFactory {
 private var filterName = name
 override fun getFilterName(): String {
   return filterName
 }

 override fun create(): EnvoyHTTPFilter {
   return TestFilter()
 }
}

class EnvoyConfigurationTest {

  fun buildTestEnvoyConfiguration(
    adminInterfaceEnabled: Boolean = false,
    grpcStatsDomain: String = "stats.example.com",
    connectTimeoutSeconds: Int = 123,
    dnsRefreshSeconds: Int = 234,
    dnsFailureRefreshSecondsBase: Int = 345,
    dnsFailureRefreshSecondsMax: Int = 456,
    dnsQueryTimeoutSeconds: Int = 321,
    dnsMinRefreshSeconds: Int = 12,
    dnsPreresolveHostnames: MutableList<String> = mutableListOf("hostname1", "hostname2"),
    enableDNSCache: Boolean = false,
    dnsCacheSaveIntervalSeconds: Int = 101,
    enableDrainPostDnsRefresh: Boolean = false,
    enableHttp3: Boolean = true,
    enableGzipDecompression: Boolean = true,
    enableBrotliDecompression: Boolean = false,
    enableSocketTagging: Boolean = false,
    enableHappyEyeballs: Boolean = false,
    enableInterfaceBinding: Boolean = false,
    h2ConnectionKeepaliveIdleIntervalMilliseconds: Int = 222,
    h2ConnectionKeepaliveTimeoutSeconds: Int = 333,
    maxConnectionsPerHost: Int = 543,
    statsFlushSeconds: Int = 567,
    streamIdleTimeoutSeconds: Int = 678,
    perTryIdleTimeoutSeconds: Int = 910,
    appVersion: String = "v1.2.3",
    appId: String = "com.example.myapp",
    trustChainVerification: TrustChainVerification = TrustChainVerification.VERIFY_TRUST_CHAIN,
    legacyVirtualClusters: MutableList<String> = mutableListOf("{name: test1}", "{name: test2}"),
    virtualClusters: List<VirtualClusterConfig> = emptyList(),
    filterChain: MutableList<EnvoyNativeFilterConfig> = mutableListOf(EnvoyNativeFilterConfig("buffer_filter_1", "{'@type': 'type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer'}"), EnvoyNativeFilterConfig("buffer_filter_2", "{'@type': 'type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer'}")),
    platformFilterFactories: MutableList<EnvoyHTTPFilterFactory> = mutableListOf(TestEnvoyHTTPFilterFactory("name1"), TestEnvoyHTTPFilterFactory("name2")),
    runtimeGuards: Map<String,Boolean> = emptyMap(),
    enableSkipDNSLookupForProxiedRequests: Boolean = false,
    statSinks: MutableList<String> = mutableListOf(),
    enablePlatformCertificatesValidation: Boolean = false,
    rtdsLayerName: String = "",
    rtdsTimeoutSeconds: Int = 0,
    adsAddress: String = "",
    adsPort: Int = 0,
    adsJwtToken: String = "",
    adsJwtTokenLifetimeSeconds: Int = 0,
    adsSslRootCerts: String = "",
    nodeId: String = "",
    nodeRegion: String = "",
    nodeZone: String = "",
    nodeSubZone: String = "",
    cdsResourcesLocator: String = "",
    cdsTimeoutSeconds: Int = 0,
    enableCds: Boolean = false,

  ): EnvoyConfiguration {
    return EnvoyConfiguration(
      adminInterfaceEnabled,
      grpcStatsDomain,
      connectTimeoutSeconds,
      dnsRefreshSeconds,
      dnsFailureRefreshSecondsBase,
      dnsFailureRefreshSecondsMax,
      dnsQueryTimeoutSeconds,
      dnsMinRefreshSeconds,
      dnsPreresolveHostnames,
      enableDNSCache,
      dnsCacheSaveIntervalSeconds,
      enableDrainPostDnsRefresh,
      enableHttp3,
      enableGzipDecompression,
      enableBrotliDecompression,
      enableSocketTagging,
      enableHappyEyeballs,
      enableInterfaceBinding,
      h2ConnectionKeepaliveIdleIntervalMilliseconds,
      h2ConnectionKeepaliveTimeoutSeconds,
      maxConnectionsPerHost,
      statsFlushSeconds,
      streamIdleTimeoutSeconds,
      perTryIdleTimeoutSeconds,
      appVersion,
      appId,
      trustChainVerification,
      legacyVirtualClusters,
      virtualClusters,
      filterChain,
      platformFilterFactories,
      emptyMap(),
      emptyMap(),
      statSinks,
      runtimeGuards,
      enableSkipDNSLookupForProxiedRequests,
      enablePlatformCertificatesValidation,
      rtdsLayerName,
      rtdsTimeoutSeconds,
      adsAddress,
      adsPort,
      adsJwtToken,
      adsJwtTokenLifetimeSeconds,
      adsSslRootCerts,
      nodeId,
      nodeRegion,
      nodeZone,
      nodeSubZone,
      cdsResourcesLocator,
      cdsTimeoutSeconds,
      enableCds
    )
  }

  @Test
  fun `configuration default values`() {
    JniLibrary.loadTestLibrary()
    val envoyConfiguration = buildTestEnvoyConfiguration()

    val resolvedTemplate = TestJni.createYaml(envoyConfiguration)
    assertThat(resolvedTemplate).contains("connect_timeout: 123s")

    assertThat(resolvedTemplate).doesNotContain("admin: *admin_interface")

    // DNS
    assertThat(resolvedTemplate).contains("dns_refresh_rate: 234s")
    assertThat(resolvedTemplate).contains("base_interval: 345s")
    assertThat(resolvedTemplate).contains("max_interval: 456s")
    assertThat(resolvedTemplate).contains("dns_query_timeout: 321s")
    assertThat(resolvedTemplate).contains("dns_lookup_family: V4_PREFERRED")
    assertThat(resolvedTemplate).contains("dns_min_refresh_rate: 12s")
    assertThat(resolvedTemplate).contains("preresolve_hostnames:")
    assertThat(resolvedTemplate).contains("hostname1")
    assertThat(resolvedTemplate).contains("hostname1")

    // Forcing IPv6
    assertThat(resolvedTemplate).contains("always_use_v6: true")

    // H2 Ping
    assertThat(resolvedTemplate).contains("connection_idle_interval: 0.222s")
    assertThat(resolvedTemplate).contains("timeout: 333s")

    // H3
    assertThat(resolvedTemplate).contains("http3_protocol_options:");
    assertThat(resolvedTemplate).contains("name: alternate_protocols_cache");

    // Gzip
    assertThat(resolvedTemplate).contains("type.googleapis.com/envoy.extensions.compression.gzip.decompressor.v3.Gzip");

    // Brotli
    assertThat(resolvedTemplate).doesNotContain("type.googleapis.com/envoy.extensions.compression.brotli.decompressor.v3.Brotli");

    // Per Host Limits
    assertThat(resolvedTemplate).contains("max_connections: 543")

    // Metadata
    assertThat(resolvedTemplate).contains("os: Android")
    assertThat(resolvedTemplate).contains("app_version: v1.2.3")
    assertThat(resolvedTemplate).contains("app_id: com.example.myapp")

    assertThat(resolvedTemplate).matches(Pattern.compile(".*virtual_clusters.*name: test1.*name: test2.*", Pattern.DOTALL));

    // Stats
    assertThat(resolvedTemplate).contains("stats_flush_interval: 567s")
    assertThat(resolvedTemplate).contains("stats.example.com");

    // Idle timeouts
    assertThat(resolvedTemplate).contains("stream_idle_timeout: 678s")
    assertThat(resolvedTemplate).contains("per_try_idle_timeout: 910s")

    // Filters
    assertThat(resolvedTemplate).contains("buffer_filter_1")
    assertThat(resolvedTemplate).contains("type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer")

    // Cert Validation
    assertThat(resolvedTemplate).contains("trusted_ca:")

    // Proxying
    assertThat(resolvedTemplate).contains("skip_dns_lookup_for_proxied_requests: false")

    // Validate ordering between filters and platform filters
    assertThat(resolvedTemplate).matches(Pattern.compile(".*name1.*name2.*buffer_filter_1.*buffer_filter_2.*", Pattern.DOTALL));
    // Validate that createYaml doesn't change filter order.
    val resolvedTemplate2 = TestJni.createYaml(envoyConfiguration)
    assertThat(resolvedTemplate2).matches(Pattern.compile(".*name1.*name2.*buffer_filter_1.*buffer_filter_2.*", Pattern.DOTALL));
    // Validate that createBootstrap also doesn't change filter order.
    // This may leak memory as the boostrap isn't used.
    envoyConfiguration.createBootstrap()
    val resolvedTemplate3 = TestJni.createYaml(envoyConfiguration)
    assertThat(resolvedTemplate3).matches(Pattern.compile(".*name1.*name2.*buffer_filter_1.*buffer_filter_2.*", Pattern.DOTALL));
  }

  @Test
  fun `configuration resolves with alternate values`() {
    JniLibrary.loadTestLibrary()
    val envoyConfiguration = buildTestEnvoyConfiguration(
      adminInterfaceEnabled = false,
      grpcStatsDomain = "",
      enableDrainPostDnsRefresh = true,
      enableDNSCache = true,
      dnsCacheSaveIntervalSeconds = 101,
      enableHappyEyeballs = true,
      enableHttp3 = false,
      enableGzipDecompression = false,
      enableBrotliDecompression = true,
      enableSocketTagging = true,
      enableInterfaceBinding = true,
      enableSkipDNSLookupForProxiedRequests = true,
      enablePlatformCertificatesValidation = true,
      dnsPreresolveHostnames = mutableListOf(),
      legacyVirtualClusters = mutableListOf(),
      filterChain = mutableListOf(),
      runtimeGuards = mapOf("test_feature_false" to true),
      statSinks = mutableListOf("{ name: envoy.stat_sinks.statsd, typed_config: { '@type': type.googleapis.com/envoy.config.metrics.v3.StatsdSink, address: { socket_address: { address: 127.0.0.1, port_value: 123 } } } }"),
      trustChainVerification = TrustChainVerification.ACCEPT_UNTRUSTED
    )

    val resolvedTemplate = TestJni.createYaml(envoyConfiguration)

    // TlS Verification
    assertThat(resolvedTemplate).contains("trust_chain_verification: ACCEPT_UNTRUSTED")

    // enableDrainPostDnsRefresh = true
    assertThat(resolvedTemplate).contains("enable_drain_post_dns_refresh: true")

    // enableDNSCache = true
    assertThat(resolvedTemplate).contains("key: dns_persistent_cache")
    // dnsCacheSaveIntervalSeconds = 101
    assertThat(resolvedTemplate).contains("save_interval: 101")

    // enableHappyEyeballs = true
    assertThat(resolvedTemplate).contains("dns_lookup_family: ALL")

    // enableHttp3 = false
    assertThat(resolvedTemplate).doesNotContain("name: alternate_protocols_cache");

    // enableGzipDecompression = false
    assertThat(resolvedTemplate).doesNotContain("type.googleapis.com/envoy.extensions.compression.gzip.decompressor.v3.Gzip");

    assertThat(resolvedTemplate).contains("type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip");

    // enableBrotliDecompression = true
    assertThat(resolvedTemplate).contains("type.googleapis.com/envoy.extensions.compression.brotli.decompressor.v3.Brotli");

    assertThat(resolvedTemplate).contains("type.googleapis.com/envoy.extensions.compression.brotli.compressor.v3.Brotli");

    // enableInterfaceBinding = true
    assertThat(resolvedTemplate).contains("enable_interface_binding: true")

    // enableSkipDNSLookupForProxiedRequests = true
    assertThat(resolvedTemplate).contains("skip_dns_lookup_for_proxied_requests: true")

    // enablePlatformCertificatesValidation = true
    assertThat(resolvedTemplate).doesNotContain("trusted_ca:")

    // statsSinks
    assertThat(resolvedTemplate).contains("envoy.stat_sinks.statsd");

    // ADS and RTDS not included by default
    assertThat(resolvedTemplate).doesNotContain("rtds_layer:");
    assertThat(resolvedTemplate).doesNotContain("ads_config:");
    assertThat(resolvedTemplate).doesNotContain("cds_config:");
  }

  @Test
  fun `test YAML loads with multiple entries`() {
    JniLibrary.loadTestLibrary()
    val envoyConfiguration = buildTestEnvoyConfiguration(
      runtimeGuards = mapOf("test_feature_false" to true, "test_feature_true" to false),
      virtualClusters = listOf(VirtualClusterConfig("cluster1", listOf(HeaderMatchConfig(":method", Type.EXACT, "POST"),
            HeaderMatchConfig(":authority", Type.SAFE_REGEX, "foo")))),
    )

    val resolvedTemplate = TestJni.createYaml(envoyConfiguration)

    assertThat(resolvedTemplate).contains("test_feature_false");
    assertThat(resolvedTemplate).contains("test_feature_true");
    assertThat(resolvedTemplate).matches(Pattern.compile(".*name: :method\n *exact_match: POST.*", Pattern.DOTALL));
    assertThat(resolvedTemplate).matches(Pattern.compile(".*name: :authority\n *safe_regex_match:\n *regex: foo.*", Pattern.DOTALL));
  }

  @Test
  fun `test adding RTDS and ADS`() {
    JniLibrary.loadTestLibrary()
    val envoyConfiguration = buildTestEnvoyConfiguration(
      rtdsLayerName = "fake_rtds_layer", rtdsTimeoutSeconds = 5432, adsAddress = "FAKE_ADDRESS", adsPort = 0
    )

    val resolvedTemplate = TestJni.createYaml(envoyConfiguration)

    assertThat(resolvedTemplate).contains("fake_rtds_layer");
    assertThat(resolvedTemplate).contains("FAKE_ADDRESS");
    assertThat(resolvedTemplate).contains("initial_fetch_timeout: 5432s");
  }

  @Test
  fun `test adding RTDS and CDS`() {
    JniLibrary.loadTestLibrary()
    val envoyConfiguration = buildTestEnvoyConfiguration(
      cdsResourcesLocator = "FAKE_CDS_LOCATOR", cdsTimeoutSeconds = 356, adsAddress = "FAKE_ADDRESS", adsPort = 0, enableCds = true
    )

    val resolvedTemplate = TestJni.createYaml(envoyConfiguration)

    assertThat(resolvedTemplate).contains("FAKE_CDS_LOCATOR");
    assertThat(resolvedTemplate).contains("FAKE_ADDRESS");
    assertThat(resolvedTemplate).contains("initial_fetch_timeout: 356s");
  }

  @Test
  fun `test not using enableCds`() {
    JniLibrary.loadTestLibrary()
    val envoyConfiguration = buildTestEnvoyConfiguration(
      cdsResourcesLocator = "FAKE_CDS_LOCATOR", cdsTimeoutSeconds = 356, adsAddress = "FAKE_ADDRESS", adsPort = 0
    )

    val resolvedTemplate = TestJni.createYaml(envoyConfiguration)

    assertThat(resolvedTemplate).doesNotContain("FAKE_CDS_LOCATOR");
    assertThat(resolvedTemplate).doesNotContain("initial_fetch_timeout: 356s");
  }

  @Test
  fun `test enableCds with default string`() {
    JniLibrary.loadTestLibrary()
    val envoyConfiguration = buildTestEnvoyConfiguration(
      enableCds = true, adsAddress = "FAKE_ADDRESS", adsPort = 0
    )

    val resolvedTemplate = TestJni.createYaml(envoyConfiguration)

    assertThat(resolvedTemplate).contains("cds_config:");
    assertThat(resolvedTemplate).contains("initial_fetch_timeout: 5s");
  }

  @Test
  fun `test RTDS default timeout`() {
    JniLibrary.loadTestLibrary()
    val envoyConfiguration = buildTestEnvoyConfiguration(
      rtdsLayerName = "fake_rtds_layer", adsAddress = "FAKE_ADDRESS", adsPort = 0
    )

    val resolvedTemplate = TestJni.createYaml(envoyConfiguration)

    assertThat(resolvedTemplate).contains("initial_fetch_timeout: 5s")
  }

  @Test
  fun `test YAML loads with stats sinks and stats domain`() {
    JniLibrary.loadTestLibrary()
    val envoyConfiguration = buildTestEnvoyConfiguration(
      grpcStatsDomain = "stats.example.com",
      statSinks = mutableListOf("{ name: envoy.stat_sinks.statsd, typed_config: { '@type': type.googleapis.com/envoy.config.metrics.v3.StatsdSink, address: { socket_address: { address: 127.0.0.1, port_value: 123 } } } }"),
      trustChainVerification = TrustChainVerification.ACCEPT_UNTRUSTED
    )

    val resolvedTemplate = TestJni.createYaml(envoyConfiguration)

    // statsSinks
    assertThat(resolvedTemplate).contains("envoy.stat_sinks.statsd");
    assertThat(resolvedTemplate).contains("stats.example.com");
  }
}
