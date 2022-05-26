licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_cc_test_library",
    "envoy_package",
)

envoy_package()

envoy_cc_test(
    name = "ssl_socket_test",
    repository = "@envoy",
    srcs = [
        "ssl_certs_test.h",
        "ssl_socket_test.cc",
    ],
    data = [
        "@envoy//test/extensions/transport_sockets/tls:gen_unittest_certs.sh",
        # TODO(mattklein123): We should consolidate all of our test certs in a single place as
        # right now we have a bunch of duplication which is confusing.
        "@envoy//test/config/integration/certs",
        "@envoy//test/extensions/transport_sockets/tls/test_data:certs",
    ],
    external_deps = ["ssl"],
    shard_count = 4,
    deps = [
        "@envoy//include/envoy/network:transport_socket_interface",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:empty_string",
        "@envoy//source/common/event:dispatcher_includes",
        "@envoy//source/common/event:dispatcher_lib",
        "@envoy//source/common/json:json_loader_lib",
        "@envoy//source/common/network:listen_socket_lib",
        "@envoy//source/common/network:transport_socket_options_lib",
        "@envoy//source/common/network:utility_lib",
        "@envoy//source/common/stats:isolated_store_lib",
        "@envoy//source/common/stats:stats_lib",
        "//source/extensions/transport_sockets/tls:context_config_lib",
        "//source/extensions/transport_sockets/tls:context_lib",
        "//source/extensions/transport_sockets/tls:ssl_socket_lib",
        "//source/extensions/transport_sockets/tls:utility_lib",
        "@envoy//test/extensions/transport_sockets/tls/test_data:cert_infos",
        "@envoy//test/mocks/buffer:buffer_mocks",
        "@envoy//test/mocks/network:network_mocks",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "//test/mocks/server:server_mocks",
        "@envoy//test/mocks/ssl:ssl_mocks",
        "@envoy//test/mocks/stats:stats_mocks",
        "@envoy//test/test_common:environment_lib",
        "@envoy//test/test_common:network_utility_lib",
        "@envoy//test/test_common:registry_lib",
        "@envoy//test/test_common:simulated_time_system_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/config/listener/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/transport_sockets/tls/v3:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "context_impl_test",
    repository = "@envoy",
    srcs = [
        "context_impl_test.cc",
        "ssl_certs_test.h",
    ],
    data = [
        "@envoy//test/extensions/transport_sockets/tls:gen_unittest_certs.sh",
	"@envoy//test/extensions/transport_sockets/tls/test_data:certs",
    ],
    deps = [
        ":ssl_test_utils",
        "@envoy//source/common/json:json_loader_lib",
        "@envoy//source/common/stats:isolated_store_lib",
        "@envoy//source/common/stats:stats_lib",
	"//source/extensions/transport_sockets/tls:context_config_lib",
	"//source/extensions/transport_sockets/tls:context_lib",
        "@envoy//test/extensions/transport_sockets/tls/test_data:cert_infos",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/secret:secret_mocks",
        "//test/mocks/server:server_mocks",
        "@envoy//test/mocks/ssl:ssl_mocks",
        "@envoy//test/test_common:environment_lib",
        "@envoy//test/test_common:simulated_time_system_lib",
        "@envoy//test/test_common:test_runtime_lib",
        "@envoy_api//envoy/admin/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/transport_sockets/tls/v3:pkg_cc_proto",
        "@envoy_api//envoy/type/matcher/v3:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "utility_test",
    repository = "@envoy",
    srcs = [
        "utility_test.cc",
    ],
    data = [
        "@envoy//test/extensions/transport_sockets/tls:gen_unittest_certs.sh",
	"@envoy//test/extensions/transport_sockets/tls/test_data:certs",
    ],
    external_deps = [
        "ssl",
    ],
    deps = [
        ":ssl_test_utils",
	"//source/extensions/transport_sockets/tls:utility_lib",
        "@envoy//test/extensions/transport_sockets/tls/test_data:cert_infos",
        "@envoy//test/test_common:environment_lib",
        "@envoy//test/test_common:simulated_time_system_lib",
    ],
)

envoy_cc_test_library(
    name = "ssl_test_utils",
    repository = "@envoy",
    srcs = [
        "ssl_test_utility.h",
    ],
    deps = [
        "//boringssl_compat:bssl_compat_lib",
	"//source/extensions/transport_sockets/tls:utility_lib",
        "@envoy//test/test_common:environment_lib",
    ],
)
