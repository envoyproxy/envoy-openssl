licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_cc_test_binary",
    "envoy_package",
)

envoy_package()

envoy_cc_test(
    name = "tls_inspector_test",
    repository = "@envoy",
    srcs = ["tls_inspector_test.cc"],
    deps = [
        ":tls_utility_lib",
        "//source/extensions/filters/listener/tls_inspector:config",
        "//source/extensions/filters/listener/tls_inspector:tls_inspector_lib",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/mocks/network:network_mocks",
        "@envoy//test/mocks/stats:stats_mocks",
        "@envoy//test/test_common:threadsafe_singleton_injector_lib",
    ],
)

envoy_cc_test_binary(
    name = "tls_inspector_benchmark",
    repository = "@envoy",
    srcs = ["tls_inspector_benchmark.cc"],
    external_deps = [
        "benchmark",
    ],
    deps = [
        ":tls_utility_lib",
        "@envoy//source/common/network:listen_socket_lib",
        "//source/extensions/filters/listener/tls_inspector:tls_inspector_lib",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/mocks/network:network_mocks",
        "@envoy//test/mocks/stats:stats_mocks",
        "@envoy//test/test_common:threadsafe_singleton_injector_lib",
    ],
)

envoy_cc_library(
    name = "tls_utility_lib",
    repository = "@envoy",
    srcs = ["tls_utility.cc"],
    hdrs = ["tls_utility.h"],
    external_deps = [
        "ssl",
    ],
    deps = [
        "//boringssl_compat:bssl_compat_lib",
        "@envoy//source/common/common:assert_lib",
        "//source/extensions/filters/listener/tls_inspector:openssl_impl_lib",
    ],
)
