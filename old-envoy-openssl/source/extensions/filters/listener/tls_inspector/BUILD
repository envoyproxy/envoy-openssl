licenses(["notice"])  # Apache 2

# TLS inspector filter for examining various TLS parameters before routing to a FilterChain.
# Public docs: docs/root/configuration/listener_filters/tls_inspector.rst

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "tls_inspector_lib",
    repository = "@envoy",
    srcs = ["tls_inspector.cc"],
    hdrs = ["tls_inspector.h"],
    external_deps = [
        "ssl",
    ],
    deps = [
        "@envoy//include/envoy/event:dispatcher_interface",
        "@envoy//include/envoy/event:timer_interface",
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/network:listen_socket_interface",
        "@envoy//source/common/api:os_sys_calls_lib",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:minimal_logger_lib",
        "@envoy//source/extensions/transport_sockets:well_known_names",
        "//boringssl_compat:bssl_compat_cbs_lib",
        "//boringssl_compat:bssl_compat_lib",
    ],
)

envoy_cc_extension(
    name = "config",
    repository = "@envoy",
    srcs = ["config.cc"],
    security_posture = "robust_to_untrusted_downstream",
    deps = [
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/listener:well_known_names",
        "//source/extensions/filters/listener/tls_inspector:tls_inspector_lib",
        "@envoy_api//envoy/extensions/filters/listener/tls_inspector/v3:pkg_cc_proto",
    ],
)
