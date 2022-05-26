licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "bssl_compat_cbs_lib",
    repository = "@envoy",
    srcs = [
        "cbs.cc",
    ],
    hdrs = [
        "cbs.h",
    ],
    deps = ["@openssl//:ssl"],
)

envoy_cc_library(
    name = "bssl_compat_lib",
    repository = "@envoy",
    srcs = [
        "bssl.cc",
    ],
    hdrs = [
        "bssl.h",
    ],
    deps = ["@openssl//:ssl"],
)
