load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_library(
    name = "openssl_handshaker_lib",
    srcs = [
        "openssl_handshaker.cc",
    ],
    hdrs = [
        "openssl_handshaker.h",
    ],
    external_deps = ["ssl"],  # TODO: boringssl/openssl wrapper library
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/extensions/transport_sockets/tls:ssl_socket_lib",
    ],
)

envoy_cc_library(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    repository = "@envoy",
    deps = [
        ":openssl_handshaker_lib",
        "@envoy//envoy/registry",
        "@envoy//source/common/common:logger_lib",
    ],
)
