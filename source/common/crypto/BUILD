licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "utility_lib",
    repository = "@envoy",
    hdrs = [
        "utility.h",
    ],
    deps = [
        "@envoy//include/envoy/buffer:buffer_interface",
        "@envoy//include/envoy/common/crypto:crypto_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:stack_array",
    ],
)
