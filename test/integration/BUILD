licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_fuzz_test",
    "envoy_cc_test",
    "envoy_cc_test_library",
    "envoy_package",
    "envoy_proto_library",
    "envoy_select_hot_restart",
    "envoy_sh_test",
)
load(
    "@envoy//source/extensions:all_extensions.bzl",
    "envoy_all_extensions",
)

envoy_package()

envoy_cc_test_library(
    name = "ads_integration_lib",
    repository = "@envoy",
    srcs = [
        "ads_integration.cc",
    ],
    hdrs = [
        "ads_integration.h",
    ],
    data = [
        "@envoy//test/config/integration/certs",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/config:protobuf_link_hacks",
        "@envoy//source/common/config:resources_lib",
        "@envoy//source/common/protobuf:utility_lib",
        "@envoy//source/extensions/filters/network/redis_proxy:config",
        "@envoy//test/common/grpc:grpc_client_integration_lib",
        "@envoy//test/test_common:network_utility_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/api/v2:pkg_cc_proto",
        "@envoy_api//envoy/service/discovery/v2:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "ads_integration_test",
    repository = "@envoy",
    srcs = ["ads_integration_test.cc"],
    deps = [
        ":ads_integration_lib",
        ":http_integration_lib",
        "@envoy//source/common/config:protobuf_link_hacks",
        "@envoy//source/common/config:resources_lib",
        "@envoy//source/common/protobuf:utility_lib",
        "@envoy//test/common/grpc:grpc_client_integration_lib",
        "@envoy//test/test_common:network_utility_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/api/v2:pkg_cc_proto",
        "@envoy_api//envoy/service/discovery/v2:pkg_cc_proto",
    ],
)

py_binary(
    name = "capture_fuzz_gen",
    srcs = ["capture_fuzz_gen.py"],
    licenses = ["notice"],  # Apache 2
    python_version = "PY3",
    visibility = ["//visibility:public"],
    deps = [
        ":capture_fuzz_proto_py_proto",
        "@envoy_api//envoy/data/tap/v2alpha:pkg_py_proto",
    ],
)

envoy_proto_library(
    name = "capture_fuzz_proto",
    srcs = [":capture_fuzz.proto"],
)

envoy_cc_test(
    name = "cds_integration_test",
    repository = "@envoy",
    srcs = ["cds_integration_test.cc"],
    data = [
        "@envoy//test/config/integration/certs",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/config:protobuf_link_hacks",
        "@envoy//source/common/config:resources_lib",
        "@envoy//source/common/protobuf:utility_lib",
        "@envoy//test/common/grpc:grpc_client_integration_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "//test/mocks/server:server_mocks",
        "@envoy//test/test_common:network_utility_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/api/v2:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "eds_integration_test",
    repository = "@envoy",
    srcs = ["eds_integration_test.cc"],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/upstream:load_balancer_lib",
        "@envoy//test/config:utility_lib",
        "@envoy//test/integration/filters:eds_ready_filter_config_lib",
        "@envoy//test/test_common:network_utility_lib",
        "@envoy_api//envoy/api/v2:pkg_cc_proto",
    ],
)

envoy_proto_library(
    name = "filter_manager_integration_proto",
    srcs = [":filter_manager_integration_test.proto"],
)

envoy_cc_test(
    name = "filter_manager_integration_test",
    repository = "@envoy",
    srcs = [
        "filter_manager_integration_test.cc",
        "filter_manager_integration_test.h",
    ],
    deps = [
        ":filter_manager_integration_proto_cc_proto",
        ":http_integration_lib",
        ":integration_lib",
        "@envoy//source/extensions/filters/network/common:factory_base_lib",
        "@envoy//source/extensions/filters/network/echo:config",
        "@envoy//source/extensions/filters/network/tcp_proxy:config",
        "@envoy//test/server:utility_lib",
        "@envoy//test/test_common:registry_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "cluster_filter_integration_test",
    repository = "@envoy",
    srcs = ["cluster_filter_integration_test.cc"],
    deps = [
        ":integration_lib",
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//source/extensions/filters/network/tcp_proxy:config",
        "@envoy//test/config:utility_lib",
    ],
)

envoy_cc_test(
    name = "custom_cluster_integration_test",
    repository = "@envoy",
    srcs = ["custom_cluster_integration_test.cc"],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/upstream:load_balancer_lib",
        "@envoy//test/config:utility_lib",
        "@envoy//test/integration/clusters:custom_static_cluster",
        "@envoy//test/test_common:network_utility_lib",
        "@envoy_api//envoy/api/v2:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "vhds_integration_test",
    repository = "@envoy",
    srcs = ["vhds_integration_test.cc"],
    data = [
        "@envoy//test/config/integration/certs",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/config:protobuf_link_hacks",
        "@envoy//source/common/config:resources_lib",
        "@envoy//source/common/protobuf:utility_lib",
        "@envoy//test/common/grpc:grpc_client_integration_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "//test/mocks/server:server_mocks",
        "@envoy//test/test_common:network_utility_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/api/v2:pkg_cc_proto",
    ],
)

exports_files(["test_utility.sh"])

envoy_sh_test(
    name = "hotrestart_test",
    srcs = envoy_select_hot_restart([
        "hotrestart_test.sh",
    ]),
    data = [
        "test_utility.sh",
        "@envoy//source/exe:envoy-static",
        "@envoy//test/config/integration:server_config_files",
        "@envoy//tools:socket_passing",
    ],
)

envoy_sh_test(
    name = "run_envoy_test",
    srcs = ["run_envoy_test.sh"],
    data = [
        "test_utility.sh",
        "@envoy//source/exe:envoy-static",
        "@envoy//test/config/integration:server_config_files",
    ],
)

envoy_cc_test(
    name = "header_integration_test",
    repository = "@envoy",
    srcs = [
        "header_integration_test.cc",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/protobuf",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/config/filter/http/router/v2:pkg_cc_proto",
        "@envoy_api//envoy/config/filter/network/http_connection_manager/v2:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "http2_integration_test",
    repository = "@envoy",
    srcs = [
        "http2_integration_test.cc",
        "http2_integration_test.h",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/extensions/filters/http/buffer:config",
        "@envoy//source/extensions/filters/http/dynamo:config",
        "@envoy//source/extensions/filters/http/health_check:config",
        "@envoy//test/common/http/http2:http2_frame",
        "@envoy//test/integration/filters:metadata_stop_all_filter_config_lib",
        "@envoy//test/integration/filters:request_metadata_filter_config_lib",
        "@envoy//test/integration/filters:response_metadata_filter_config_lib",
        "@envoy//test/integration/filters:stop_iteration_and_continue",
        "@envoy//test/mocks/http:http_mocks",
        "@envoy//test/mocks/upstream:upstream_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "http_subset_lb_integration_test",
    repository = "@envoy",
    srcs = [
        "http_subset_lb_integration_test.cc",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//test/common/upstream:utility_lib",
    ],
)

envoy_cc_test(
    name = "transport_socket_match_integration_test",
    repository = "@envoy",
    srcs = [
        "transport_socket_match_integration_test.cc",
    ],
    data = [
        "@envoy//test/config/integration/certs",
    ],
    deps = [
        ":http_integration_lib",
        "//source/extensions/transport_sockets/tls:context_lib",
        "@envoy//test/common/upstream:utility_lib",
    ],
)

envoy_cc_test(
    name = "http_timeout_integration_test",
    repository = "@envoy",
    srcs = [
        "http_timeout_integration_test.cc",
        "http_timeout_integration_test.h",
    ],
    deps = [
        ":http_integration_lib",
    ],
)

envoy_cc_test(
    name = "protocol_integration_test",
    repository = "@envoy",
    srcs = [
        "protocol_integration_test.cc",
    ],
    # As this test has many H1/H2/v4/v6 tests it takes a while to run.
    # Shard it enough to bring the run time in line with other integration tests.
    shard_count = 3,
    deps = [
        ":http_protocol_integration_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/extensions/filters/http/buffer:config",
        "@envoy//source/extensions/filters/http/dynamo:config",
        "@envoy//source/extensions/filters/http/health_check:config",
        "@envoy//test/integration/filters:random_pause_filter_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "http2_upstream_integration_test",
    repository = "@envoy",
    srcs = [
        "http2_upstream_integration_test.cc",
        "http2_upstream_integration_test.h",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/extensions/filters/http/buffer:config",
        "@envoy//source/extensions/filters/http/dynamo:config",
        "@envoy//source/extensions/filters/http/health_check:config",
        "@envoy//test/integration/filters:random_pause_filter_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "integration_admin_test",
    repository = "@envoy",
    srcs = [
        "integration_admin_test.cc",
        "integration_admin_test.h",
    ],
    deps = [
        ":http_protocol_integration_lib",
        "@envoy//include/envoy/http:header_map_interface",
        "@envoy//source/common/stats:stats_matcher_lib",
        "@envoy//source/extensions/filters/http/buffer:config",
        "@envoy//source/extensions/filters/http/health_check:config",
        "@envoy//test/common/stats:stat_test_utility_lib",
        "@envoy_api//envoy/admin/v2alpha:pkg_cc_proto",
        "@envoy_api//envoy/config/metrics/v2:pkg_cc_proto",
    ],
)

envoy_cc_test_library(
    name = "test_host_predicate_lib",
    repository = "@envoy",
    srcs = [
        "test_host_predicate.h",
        "test_host_predicate_config.h",
    ],
    deps = [
        "@envoy//include/envoy/upstream:retry_interface",
    ],
)

envoy_cc_test_library(
    name = "http_integration_lib",
    repository = "@envoy",
    srcs = [
        "http_integration.cc",
    ],
    hdrs = [
        "http_integration.h",
    ],
    deps = [
        ":integration_lib",
        ":test_host_predicate_lib",
        "@envoy//include/envoy/event:timer_interface",
        "@envoy//source/common/common:thread_annotations",
        "@envoy//source/extensions/filters/http/router:config",
        "@envoy//source/extensions/filters/network/http_connection_manager:config",
        "@envoy//test/common/upstream:utility_lib",
        "@envoy//test/integration/filters:add_trailers_filter_config_lib",
        "@envoy//test/integration/filters:call_decodedata_once_filter_config_lib",
        "@envoy//test/integration/filters:decode_headers_return_stop_all_filter_config_lib",
        "@envoy//test/integration/filters:encode_headers_return_stop_all_filter_config_lib",
        "@envoy//test/integration/filters:headers_only_filter_config_lib",
        "@envoy//test/integration/filters:modify_buffer_filter_config_lib",
        "@envoy//test/integration/filters:passthrough_filter_config_lib",
        "@envoy//test/integration/filters:pause_filter_lib",
        "@envoy//test/test_common:registry_lib",
    ],
)

envoy_cc_test_library(
    name = "http_protocol_integration_lib",
    repository = "@envoy",
    srcs = [
        "http_protocol_integration.cc",
    ],
    hdrs = [
        "http_protocol_integration.h",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//test/common/upstream:utility_lib",
    ],
)

envoy_cc_test(
    name = "idle_timeout_integration_test",
    repository = "@envoy",
    srcs = ["idle_timeout_integration_test.cc"],
    # As this test has many pauses for idle timeouts, it takes a while to run.
    # Shard it enough to bring the run time in line with other integration tests.
    shard_count = 2,
    deps = [
        ":http_protocol_integration_lib",
        "@envoy//test/test_common:test_time_lib",
    ],
)

envoy_cc_test_library(
    name = "integration_lib",
    repository = "@envoy",
    srcs = [
        "autonomous_upstream.cc",
        "fake_upstream.cc",
        "integration.cc",
        "server.cc",
        "ssl_utility.cc",
        "utility.cc",
    ],
    hdrs = [
        "autonomous_upstream.h",
        "fake_upstream.h",
        "integration.h",
        "server.h",
        "ssl_utility.h",
        "utility.h",
    ],
    data = ["@envoy//test/common/runtime:filesystem_test_data"],
    deps = [
        ":server_stats_interface",
        ":tcp_dump",
        "@envoy//include/envoy/api:api_interface",
        "@envoy//include/envoy/buffer:buffer_interface",
        "@envoy//include/envoy/event:dispatcher_interface",
        "@envoy//include/envoy/grpc:status",
        "@envoy//include/envoy/http:codec_interface",
        "@envoy//include/envoy/http:header_map_interface",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/server:configuration_interface",
        "@envoy//include/envoy/server:hot_restart_interface",
        "@envoy//include/envoy/server:options_interface",
        "@envoy//include/envoy/stats:stats_interface",
        "@envoy//include/envoy/thread:thread_interface",
        "@envoy//source/common/api:api_lib",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/buffer:zero_copy_input_stream_lib",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:minimal_logger_lib",
        "@envoy//source/common/event:dispatcher_lib",
        "@envoy//source/common/grpc:codec_lib",
        "@envoy//source/common/grpc:common_lib",
        "@envoy//source/common/http:codec_client_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/common/http:headers_lib",
        "@envoy//source/common/http/http1:codec_lib",
        "@envoy//source/common/http/http2:codec_lib",
        "@envoy//source/common/local_info:local_info_lib",
        "@envoy//source/common/network:filter_lib",
        "@envoy//source/common/network:listen_socket_lib",
        "@envoy//source/common/network:utility_lib",
        "@envoy//source/common/runtime:runtime_lib",
        "@envoy//source/common/stats:isolated_store_lib",
        "@envoy//source/common/stats:symbol_table_creator_lib",
        "@envoy//source/common/stats:thread_local_store_lib",
        "@envoy//source/common/thread_local:thread_local_lib",
        "@envoy//source/common/upstream:upstream_includes",
        "@envoy//source/common/upstream:upstream_lib",
        "@envoy//source/extensions/access_loggers/file:config",
        "@envoy//source/extensions/transport_sockets/raw_buffer:config",
        "@envoy//source/extensions/transport_sockets/tap:config",
        "//source/extensions/transport_sockets/tls:config",
        "@envoy//source/server:connection_handler_lib",
        "@envoy//source/server:hot_restart_nop_lib",
        "@envoy//source/server:listener_hooks_lib",
        "@envoy//source/server:process_context_lib",
        "@envoy//source/server:server_lib",
        "@envoy//test/common/grpc:grpc_client_integration_lib",
        "@envoy//test/common/runtime:utility_lib",
        "@envoy//test/common/upstream:utility_lib",
        "@envoy//test/config:utility_lib",
        "@envoy//test/mocks/buffer:buffer_mocks",
        "//test/mocks/server:server_mocks",
        "@envoy//test/mocks/stats:stats_mocks",
        "@envoy//test/mocks/upstream:upstream_mocks",
        "@envoy//test/test_common:environment_lib",
        "@envoy//test/test_common:network_utility_lib",
        "@envoy//test/test_common:printers_lib",
        "@envoy//test/test_common:simulated_time_system_lib",
        "@envoy//test/test_common:test_time_lib",
        "@envoy//test/test_common:test_time_system_interface",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "integration_test",
    repository = "@envoy",
    srcs = [
        "integration_test.cc",
        "integration_test.h",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/common/http:headers_lib",
        "@envoy//source/extensions/filters/http/cors:config",
        "@envoy//source/extensions/filters/http/dynamo:config",
        "@envoy//source/extensions/filters/http/grpc_http1_bridge:config",
        "@envoy//source/extensions/filters/http/health_check:config",
        "@envoy//test/integration/filters:clear_route_cache_filter_lib",
        "@envoy//test/integration/filters:process_context_lib",
        "@envoy//test/mocks/http:http_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "redirect_integration_test",
    repository = "@envoy",
    srcs = [
        "redirect_integration_test.cc",
    ],
    deps = [
        ":http_protocol_integration_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "websocket_integration_test",
    repository = "@envoy",
    srcs = [
        "websocket_integration_test.cc",
        "websocket_integration_test.h",
    ],
    deps = [
        ":http_protocol_integration_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/extensions/access_loggers/file:config",
        "@envoy//source/extensions/filters/http/buffer:config",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "echo_integration_test",
    repository = "@envoy",
    srcs = [
        "echo_integration_test.cc",
    ],
    # This test must be run in exclusive mode: see comments in AddRemoveListener
    tags = ["exclusive"],
    deps = [
        ":integration_lib",
        "@envoy//source/extensions/filters/network/echo:config",
        "@envoy//test/server:utility_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "udp_echo_integration_test",
    repository = "@envoy",
    srcs = [
        "udp_echo_integration_test.cc",
    ],
    deps = [
        ":integration_lib",
        "@envoy//source/common/network:listen_socket_lib",
        "@envoy//source/server:active_raw_udp_listener_config",
        "@envoy//test/integration/filters:udp_listener_echo_filter_lib",
        "@envoy//test/server:utility_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "stats_integration_test",
    repository = "@envoy",
    srcs = ["stats_integration_test.cc"],
    # The symbol table cluster memory tests take a while to run specially under tsan.
    # Shard it to avoid test timeout.
    shard_count = 2,
    deps = [
        ":integration_lib",
        "@envoy//source/common/memory:stats_lib",
        "@envoy//source/common/stats:symbol_table_creator_lib",
        "@envoy//source/extensions/filters/http/router:config",
        "@envoy//source/extensions/filters/network/http_connection_manager:config",
        "@envoy//test/common/stats:stat_test_utility_lib",
        "@envoy//test/test_common:network_utility_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/config/bootstrap/v2:pkg_cc_proto",
        "@envoy_api//envoy/config/metrics/v2:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "load_stats_integration_test",
    repository = "@envoy",
    srcs = ["load_stats_integration_test.cc"],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/config:resources_lib",
        "@envoy//test/config:utility_lib",
        "@envoy//test/test_common:network_utility_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/api/v2:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "hds_integration_test",
    repository = "@envoy",
    srcs = ["hds_integration_test.cc"],
    deps = [
        ":http_integration_lib",
        ":integration_lib",
        "@envoy//include/envoy/upstream:upstream_interface",
        "@envoy//source/common/config:metadata_lib",
        "@envoy//source/common/config:resources_lib",
        "@envoy//source/common/json:config_schemas_lib",
        "@envoy//source/common/json:json_loader_lib",
        "@envoy//source/common/network:utility_lib",
        "@envoy//source/common/upstream:health_checker_lib",
        "@envoy//source/common/upstream:health_discovery_service_lib",
        "@envoy//test/common/upstream:utility_lib",
        "@envoy//test/config:utility_lib",
        "@envoy//test/test_common:network_utility_lib",
        "@envoy_api//envoy/api/v2:pkg_cc_proto",
        "@envoy_api//envoy/service/discovery/v2:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "header_prefix_integration_test",
    repository = "@envoy",
    srcs = ["header_prefix_integration_test.cc"],
    coverage = False,
    deps = [
        ":http_protocol_integration_lib",
    ],
)

envoy_cc_test(
    name = "overload_integration_test",
    repository = "@envoy",
    srcs = ["overload_integration_test.cc"],
    deps = [
        ":http_protocol_integration_lib",
        "@envoy//source/extensions/resource_monitors/injected_resource:config",
    ],
)

envoy_cc_test(
    name = "proxy_proto_integration_test",
    repository = "@envoy",
    srcs = [
        "proxy_proto_integration_test.cc",
        "proxy_proto_integration_test.h",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/http:codec_client_lib",
        "@envoy//source/extensions/filters/listener/proxy_protocol:config",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "ratelimit_integration_test",
    repository = "@envoy",
    srcs = ["ratelimit_integration_test.cc"],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/buffer:zero_copy_input_stream_lib",
        "@envoy//source/common/grpc:codec_lib",
        "@envoy//source/common/grpc:common_lib",
        "@envoy//source/extensions/filters/http/ratelimit:config",
        "@envoy//test/common/grpc:grpc_client_integration_lib",
        "@envoy_api//envoy/service/ratelimit/v2:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "rtds_integration_test",
    repository = "@envoy",
    srcs = ["rtds_integration_test.cc"],
    deps = [
        ":http_integration_lib",
        "@envoy//test/common/grpc:grpc_client_integration_lib",
        "@envoy_api//envoy/service/discovery/v2:pkg_cc_proto",
    ],
)

envoy_cc_test_library(
    name = "server_stats_interface",
    repository = "@envoy",
    hdrs = ["server_stats.h"],
    deps = ["@envoy//include/envoy/stats:stats_interface"],
)

envoy_cc_test(
    name = "sds_static_integration_test",
    repository = "@envoy",
    srcs = [
        "sds_static_integration_test.cc",
    ],
    data = [
        "@envoy//test/config/integration/certs",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/event:dispatcher_includes",
        "@envoy//source/common/event:dispatcher_lib",
        "@envoy//source/common/network:connection_lib",
        "@envoy//source/common/network:utility_lib",
        "@envoy//source/extensions/filters/listener/tls_inspector:config",
        "//source/extensions/transport_sockets/tls:config",
        "//source/extensions/transport_sockets/tls:context_config_lib",
        "//source/extensions/transport_sockets/tls:context_lib",
        "@envoy//test/mocks/secret:secret_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "sds_dynamic_integration_test",
    repository = "@envoy",
    srcs = [
        "sds_dynamic_integration_test.cc",
    ],
    data = [
        "@envoy//test/config/integration/certs",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/config:protobuf_link_hacks",
        "@envoy//source/common/config:resources_lib",
        "@envoy//source/common/event:dispatcher_includes",
        "@envoy//source/common/event:dispatcher_lib",
        "@envoy//source/common/network:connection_lib",
        "@envoy//source/common/network:utility_lib",
        "@envoy//source/extensions/filters/listener/tls_inspector:config",
        "//source/extensions/transport_sockets/tls:config",
        "//source/extensions/transport_sockets/tls:context_config_lib",
        "//source/extensions/transport_sockets/tls:context_lib",
        "@envoy//test/common/grpc:grpc_client_integration_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/secret:secret_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "tcp_proxy_integration_test",
    repository = "@envoy",
    srcs = [
        "tcp_proxy_integration_test.cc",
        "tcp_proxy_integration_test.h",
    ],
    data = [
        "@envoy//test/config/integration/certs",
    ],
    deps = [
        ":integration_lib",
        "@envoy//source/common/event:dispatcher_includes",
        "@envoy//source/common/event:dispatcher_lib",
        "@envoy//source/common/network:utility_lib",
        "@envoy//source/extensions/access_loggers/file:config",
        "@envoy//source/extensions/filters/network/tcp_proxy:config",
        "//source/extensions/transport_sockets/tls:config",
        "//source/extensions/transport_sockets/tls:context_config_lib",
        "//source/extensions/transport_sockets/tls:context_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/secret:secret_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "tcp_conn_pool_integration_test",
    repository = "@envoy",
    srcs = [
        "tcp_conn_pool_integration_test.cc",
    ],
    deps = [
        ":integration_lib",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//include/envoy/tcp:conn_pool_interface",
        "@envoy//test/server:utility_lib",
        "@envoy//test/test_common:registry_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test_library(
    name = "tcp_dump",
    repository = "@envoy",
    srcs = ["tcp_dump.cc"],
    hdrs = ["tcp_dump.h"],
    deps = [
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:fmt_lib",
    ],
)

envoy_cc_test(
    name = "uds_integration_test",
    repository = "@envoy",
    srcs = [
        "uds_integration_test.cc",
        "uds_integration_test.h",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/event:dispatcher_includes",
        "@envoy//source/common/event:dispatcher_lib",
        "@envoy//source/common/http:codec_client_lib",
        "@envoy//source/common/stats:stats_lib",
        "@envoy//test/test_common:environment_lib",
    ],
)

envoy_cc_test(
    name = "dynamic_validation_integration_test",
    repository = "@envoy",
    srcs = ["dynamic_validation_integration_test.cc"],
    data = ["@envoy//test/config/integration:server_xds_files"],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/stats:stats_lib",
    ],
)

envoy_cc_test(
    name = "xds_integration_test",
    repository = "@envoy",
    srcs = ["xds_integration_test.cc"],
    data = ["@envoy//test/config/integration:server_xds_files"],
    deps = [
        ":http_integration_lib",
        ":http_protocol_integration_lib",
        "@envoy//test/test_common:environment_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "xfcc_integration_test",
    repository = "@envoy",
    srcs = [
        "xfcc_integration_test.cc",
        "xfcc_integration_test.h",
    ],
    data = [
        "@envoy//test/config/integration/certs",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/extensions/filters/listener/tls_inspector:config",
        "//source/extensions/transport_sockets/tls:config",
        "//test/mocks/server:server_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test_library(
    name = "h1_fuzz_lib",
    repository = "@envoy",
    srcs = ["h1_fuzz.cc"],
    hdrs = ["h1_fuzz.h"],
    deps = [
        ":capture_fuzz_proto_cc_proto",
        ":http_integration_lib",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//test/fuzz:fuzz_runner_lib",
        "//test/integration:integration_lib",
        "@envoy//test/test_common:environment_lib",
    ],
)

envoy_cc_fuzz_test(
    name = "h1_capture_fuzz_test",
    repository = "@envoy",
    srcs = ["h1_capture_fuzz_test.cc"],
    corpus = "h1_corpus",
    deps = [":h1_fuzz_lib"],
)

envoy_cc_fuzz_test(
    name = "h1_capture_direct_response_fuzz_test",
    repository = "@envoy",
    srcs = ["h1_capture_direct_response_fuzz_test.cc"],
    corpus = "h1_corpus",
    deps = [":h1_fuzz_lib"],
)

envoy_cc_test(
    name = "scoped_rds_integration_test",
    repository = "@envoy",
    srcs = [
        "scoped_rds_integration_test.cc",
    ],
    deps = [
        ":http_integration_lib",
        "@envoy//source/common/config:resources_lib",
        "@envoy//source/common/event:dispatcher_includes",
        "@envoy//source/common/event:dispatcher_lib",
        "@envoy//source/common/network:connection_lib",
        "@envoy//source/common/network:utility_lib",
        "@envoy//test/common/grpc:grpc_client_integration_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "aws_metadata_fetcher_integration_test",
    repository = "@envoy",
    srcs = [
        "aws_metadata_fetcher_integration_test.cc",
    ],
    deps = [
        ":integration_lib",
        "@envoy//source/common/common:fmt_lib",
        "@envoy//source/extensions/filters/http/common/aws:utility_lib",
        "@envoy//source/extensions/filters/http/fault:config",
        "@envoy//source/extensions/filters/http/fault:fault_filter_lib",
        "@envoy//source/extensions/filters/http/router:config",
        "@envoy//source/extensions/filters/network/echo:config",
        "@envoy//source/extensions/filters/network/http_connection_manager:config",
        "@envoy//test/server:utility_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)
