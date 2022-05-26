licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)
load(
    "@envoy//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

envoy_package()

envoy_extension_cc_test(
    name = "utility_test",
    repository = "@envoy",
    srcs = [
        "utility_test.cc",
    ],
    extension_name = "envoy.extensions.common.crypto.utility_lib",
    external_deps = [
        "ssl",
    ],
    deps = [
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:hex_lib",
        "@envoy//source/common/crypto:utility_lib",
        "//source/extensions/common/crypto:utility_lib",
    ],
)
