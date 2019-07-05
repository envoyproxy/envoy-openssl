package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        "@envoy_openssl//extensions/transport_sockets/tls:config",
        "@envoy_openssl//extensions/filters/listener/tls_inspector:config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)
