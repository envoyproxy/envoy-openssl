licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_cc_test_library",
    "envoy_package",
    "envoy_select_google_grpc",
)

envoy_package()

envoy_cc_test_library(
    name = "grpc_client_integration_test_harness_lib",
    repository = "@envoy",
    hdrs = ["grpc_client_integration_test_harness.h"],
    deps = [
        "@envoy//test/common/grpc:grpc_client_integration_lib",
        "@envoy//test/common/grpc:utility_lib",
        "@envoy//source/common/api:api_lib",
        "@envoy//source/common/event:dispatcher_lib",
        "@envoy//source/common/http/http2:conn_pool_lib",
        "//test/integration:integration_lib",
        "@envoy//test/mocks/local_info:local_info_mocks",
        "//test/mocks/server:server_mocks",
        "@envoy//test/proto:helloworld_proto_cc_proto",
        "@envoy//test/test_common:global_lib",
        "@envoy//test/test_common:test_time_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)
