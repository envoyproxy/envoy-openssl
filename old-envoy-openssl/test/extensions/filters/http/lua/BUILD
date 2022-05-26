licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load(
    "@envoy//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

envoy_package()

envoy_extension_cc_test(
    name = "lua_filter_test",
    repository = "@envoy",
    srcs = ["lua_filter_test.cc"],
    extension_name = "envoy.filters.http.lua",
    deps = [
        "@envoy//source/common/stream_info:stream_info_lib",
        "@envoy_openssl//source/extensions/filters/http/lua:lua_filter_lib",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/mocks/http:http_mocks",
        "@envoy//test/mocks/network:network_mocks",
        "@envoy//test/mocks/ssl:ssl_mocks",
        "@envoy//test/mocks/thread_local:thread_local_mocks",
        "@envoy//test/mocks/upstream:upstream_mocks",
        "@envoy//test/test_common:logging_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test(
    name = "wrappers_test",
    repository = "@envoy",
    srcs = ["wrappers_test.cc"],
    extension_name = "envoy.filters.http.lua",
    deps = [
        "@envoy//source/common/stream_info:stream_info_lib",
        "@envoy_openssl//source/extensions/filters/http/lua:wrappers_lib",
        "@envoy//test/extensions/filters/common/lua:lua_wrappers_lib",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test(
    name = "lua_integration_test",
    repository = "@envoy",
    srcs = ["lua_integration_test.cc"],
    extension_name = "envoy.filters.http.lua",
    deps = [
        "//source/extensions/filters/http/lua:config",
        "//test/integration:http_integration_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/config/bootstrap/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/network/http_connection_manager/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test(
    name = "config_test",
    repository = "@envoy",
    srcs = ["config_test.cc"],
    extension_name = "envoy.filters.http.lua",
    deps = [
        "//source/extensions/filters/http/lua:config",
        "//test/mocks/server:server_mocks",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/extensions/filters/http/lua/v3:pkg_cc_proto",
    ],
)
