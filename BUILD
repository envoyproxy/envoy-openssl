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
        "@envoy_openssl//source/extensions/transport_sockets/tls:config",
        "@envoy_openssl//source/extensions/transport_sockets/tls:ssl_socket_lib",
        "@envoy_openssl//source/extensions/transport_sockets/tls:context_config_lib",
        "@envoy_openssl//source/extensions/transport_sockets/tls:context_lib",
        "@envoy_openssl//source/extensions/transport_sockets/tls:utility_lib",
        "@envoy_openssl//source/extensions/transport_sockets/tls:openssl_impl_lib",
        "@envoy_openssl//source/extensions/filters/listener/tls_inspector:tls_inspector_lib",
        "@envoy_openssl//source/extensions/filters/listener/tls_inspector:config",
        "@envoy_openssl//source/extensions/filters/listener/tls_inspector:openssl_impl_lib",
        "@envoy_openssl//source/extensions/common/crypto:utility_lib",
        "@envoy_openssl//source/extensions/filters/http/lua:lua_filter_lib",
        "@envoy_openssl//source/extensions/filters/http/lua:wrappers_lib",
        "@envoy_openssl//source/extensions/filters/http/lua:config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)
