licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_mock",
    "envoy_package",
)

envoy_package()

envoy_cc_mock(
    name = "server_mocks",
    repository = "@envoy",
    srcs = ["mocks.cc"],
    hdrs = ["mocks.h"],
    deps = [
        "@envoy//include/envoy/secret:secret_manager_interface",
        "@envoy//include/envoy/server:admin_interface",
        "@envoy//include/envoy/server:configuration_interface",
        "@envoy//include/envoy/server:drain_manager_interface",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//include/envoy/server:guarddog_interface",
        "@envoy//include/envoy/server:health_checker_config_interface",
        "@envoy//include/envoy/server:instance_interface",
        "@envoy//include/envoy/server:options_interface",
        "@envoy//include/envoy/server:overload_manager_interface",
        "@envoy//include/envoy/server:worker_interface",
        "@envoy//include/envoy/ssl:context_manager_interface",
        "@envoy//include/envoy/upstream:health_checker_interface",
        "@envoy//source/common/grpc:context_lib",
        "@envoy//source/common/http:context_lib",
        "@envoy//source/common/secret:secret_manager_impl_lib",
        "@envoy//source/common/singleton:manager_impl_lib",
        "@envoy//source/common/stats:stats_lib",
        "//source/extensions/transport_sockets/tls:context_lib",
        "@envoy//test/mocks/access_log:access_log_mocks",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/mocks/http:http_mocks",
        "@envoy//test/mocks/init:init_mocks",
        "@envoy//test/mocks/local_info:local_info_mocks",
        "@envoy//test/mocks/network:network_mocks",
        "@envoy//test/mocks/protobuf:protobuf_mocks",
        "@envoy//test/mocks/router:router_mocks",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/secret:secret_mocks",
        "@envoy//test/mocks/thread_local:thread_local_mocks",
        "@envoy//test/mocks/tracing:tracing_mocks",
        "@envoy//test/mocks/upstream:upstream_mocks",
        "@envoy//test/test_common:test_time_lib",
        "@envoy_api//envoy/config/bootstrap/v2:pkg_cc_proto",
    ],
)
