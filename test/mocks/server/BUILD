load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_mock",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_mock(
    name = "config_tracker_mocks",
	repository = "@envoy",
    srcs = ["config_tracker.cc"],
    hdrs = ["config_tracker.h"],
    deps = [
        "@envoy//include/envoy/server:configuration_interface",
    ],
)

envoy_cc_mock(
    name = "admin_mocks",
	repository = "@envoy",
    srcs = ["admin.cc"],
    hdrs = ["admin.h"],
    deps = [
        "@envoy//include/envoy/server:admin_interface",
        "//test/mocks/server:config_tracker_mocks",
    ],
)

envoy_cc_mock(
    name = "bootstrap_extension_factory_mocks",
	repository = "@envoy",
    srcs = ["bootstrap_extension_factory.cc"],
    hdrs = ["bootstrap_extension_factory.h"],
    deps = [
        "@envoy//include/envoy/server:bootstrap_extension_config_interface",
    ],
)

envoy_cc_mock(
    name = "options_mocks",
	repository = "@envoy",
    srcs = ["options.cc"],
    hdrs = ["options.h"],
    deps = [
        "@envoy//include/envoy/server:options_interface",
        "@envoy_api//envoy/admin/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/bootstrap/v3:pkg_cc_proto",
    ],
)

envoy_cc_mock(
    name = "admin_stream_mocks",
	repository = "@envoy",
    srcs = ["admin_stream.cc"],
    hdrs = ["admin_stream.h"],
    deps = [
        "@envoy//include/envoy/server:admin_interface",
        "@envoy//test/mocks/http:http_mocks",
    ],
)

envoy_cc_mock(
    name = "drain_manager_mocks",
	repository = "@envoy",
    srcs = ["drain_manager.cc"],
    hdrs = ["drain_manager.h"],
    deps = [
        "@envoy//include/envoy/server:drain_manager_interface",
    ],
)

envoy_cc_mock(
    name = "watch_dog_mocks",
	repository = "@envoy",
    srcs = ["watch_dog.cc"],
    hdrs = ["watch_dog.h"],
    deps = [
        "@envoy//include/envoy/server:watchdog_interface",
    ],
)

envoy_cc_mock(
    name = "guard_dog_mocks",
	repository = "@envoy",
    srcs = ["guard_dog.cc"],
    hdrs = ["guard_dog.h"],
    deps = [
        "@envoy//include/envoy/server:guarddog_interface",
        "//test/mocks/server:watch_dog_mocks",
    ],
)

envoy_cc_mock(
    name = "hot_restart_mocks",
	repository = "@envoy",
    srcs = ["hot_restart.cc"],
    hdrs = ["hot_restart.h"],
    deps = [
        "@envoy//include/envoy/server:instance_interface",
        "@envoy//test/mocks/stats:stats_mocks",
    ],
)

envoy_cc_mock(
    name = "listener_component_factory_mocks",
	repository = "@envoy",
    srcs = ["listener_component_factory.cc"],
    hdrs = ["listener_component_factory.h"],
    deps = [
        "@envoy//include/envoy/server:drain_manager_interface",
        "@envoy//include/envoy/server:listener_manager_interface",
        "@envoy//test/mocks/network:network_mocks",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/listener/v3:pkg_cc_proto",
    ],
)

envoy_cc_mock(
    name = "listener_manager_mocks",
	repository = "@envoy",
    srcs = ["listener_manager.cc"],
    hdrs = ["listener_manager.h"],
    deps = [
        "@envoy//include/envoy/server:listener_manager_interface",
    ],
)

envoy_cc_mock(
    name = "server_lifecycle_notifier_mocks",
	repository = "@envoy",
    srcs = ["server_lifecycle_notifier.cc"],
    hdrs = ["server_lifecycle_notifier.h"],
    deps = [
        "@envoy//include/envoy/server:lifecycle_notifier_interface",
    ],
)

envoy_cc_mock(
    name = "worker_factory_mocks",
	repository = "@envoy",
    srcs = ["worker_factory.cc"],
    hdrs = ["worker_factory.h"],
    deps = [
        "@envoy//include/envoy/server:worker_interface",
        "//test/mocks/server:worker_mocks",
    ],
)

envoy_cc_mock(
    name = "worker_mocks",
	repository = "@envoy",
    srcs = ["worker.cc"],
    hdrs = ["worker.h"],
    deps = [
        "@envoy//include/envoy/server:worker_interface",
    ],
)

envoy_cc_mock(
    name = "overload_manager_mocks",
	repository = "@envoy",
    srcs = ["overload_manager.cc"],
    hdrs = ["overload_manager.h"],
    deps = [
        "@envoy//include/envoy/server:overload_manager_interface",
    ],
)

envoy_cc_mock(
    name = "instance_mocks",
	repository = "@envoy",
    srcs = ["instance.cc"],
    hdrs = ["instance.h"],
    deps = [
        "@envoy//include/envoy/server:instance_interface",
        "@envoy//source/common/grpc:context_lib",
        "@envoy//source/common/http:context_lib",
        "@envoy//source/common/secret:secret_manager_impl_lib",
        "@envoy//source/common/singleton:manager_impl_lib",
        "@envoy//source/common/stats:stats_lib",
        "//source/extensions/transport_sockets/tls:context_lib",
        "@envoy//test/mocks/access_log:access_log_mocks",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/mocks/http:http_mocks",
        "@envoy//test/mocks/init:init_mocks",
        "@envoy//test/mocks/local_info:local_info_mocks",
        "@envoy//test/mocks/network:network_mocks",
        "@envoy//test/mocks/protobuf:protobuf_mocks",
        "@envoy//test/mocks/router:router_mocks",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/secret:secret_mocks",
        "//test/mocks/server:admin_mocks",
        "//test/mocks/server:drain_manager_mocks",
        "//test/mocks/server:hot_restart_mocks",
        "//test/mocks/server:listener_manager_mocks",
        "//test/mocks/server:options_mocks",
        "//test/mocks/server:overload_manager_mocks",
        "//test/mocks/server:server_lifecycle_notifier_mocks",
        "//test/mocks/server:transport_socket_factory_context_mocks",
        "@envoy//test/mocks/thread_local:thread_local_mocks",
        "@envoy//test/mocks/tracing:tracing_mocks",
        "@envoy//test/mocks/upstream:upstream_mocks",
    ],
)

envoy_cc_mock(
    name = "main_mocks",
	repository = "@envoy",
    srcs = ["main.cc"],
    hdrs = ["main.h"],
    deps = [
        "@envoy//include/envoy/server:configuration_interface",
        "@envoy//include/envoy/server:overload_manager_interface",
    ],
)

envoy_cc_mock(
    name = "factory_context_mocks",
	repository = "@envoy",
    srcs = ["factory_context.cc"],
    hdrs = ["factory_context.h"],
    deps = [
        "//test/mocks/server:drain_manager_mocks",
        "//test/mocks/server:instance_mocks",
        "//test/mocks/server:overload_manager_mocks",
        "//test/mocks/server:server_lifecycle_notifier_mocks",
    ],
)

envoy_cc_mock(
    name = "transport_socket_factory_context_mocks",
	repository = "@envoy",
    srcs = ["transport_socket_factory_context.cc"],
    hdrs = ["transport_socket_factory_context.h"],
    deps = [
        "@envoy//include/envoy/server:tracer_config_interface",
        "@envoy//source/common/secret:secret_manager_impl_lib",
        "@envoy//test/mocks/api:api_mocks",
        "//test/mocks/server:config_tracker_mocks",
        "@envoy//test/mocks/upstream:upstream_mocks",
    ],
)

envoy_cc_mock(
    name = "listener_factory_context_mocks",
	repository = "@envoy",
    srcs = ["listener_factory_context.cc"],
    hdrs = ["listener_factory_context.h"],
    deps = [
        "@envoy//include/envoy/server:listener_manager_interface",
        "//test/mocks/server:factory_context_mocks",
    ],
)

envoy_cc_mock(
    name = "health_checker_factory_context_mocks",
	repository = "@envoy",
    srcs = ["health_checker_factory_context.cc"],
    hdrs = ["health_checker_factory_context.h"],
    deps = [
        "@envoy//include/envoy/server:health_checker_config_interface",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/mocks/event:event_mocks",
        "@envoy//test/mocks/protobuf:protobuf_mocks",
        "@envoy//test/mocks/router:router_mocks",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/upstream:upstream_mocks",
    ],
)

envoy_cc_mock(
    name = "filter_chain_factory_context_mocks",
	repository = "@envoy",
    srcs = ["filter_chain_factory_context.cc"],
    hdrs = ["filter_chain_factory_context.h"],
    deps = [
        "@envoy//include/envoy/server:filter_config_interface",
        "//test/mocks/server:factory_context_mocks",
    ],
)

envoy_cc_mock(
    name = "tracer_factory_mocks",
	repository = "@envoy",
    srcs = ["tracer_factory.cc"],
    hdrs = ["tracer_factory.h"],
    deps = [
        "@envoy//include/envoy/protobuf:message_validator_interface",
        "@envoy//include/envoy/server:tracer_config_interface",
    ],
)

envoy_cc_mock(
    name = "tracer_factory_context_mocks",
	repository = "@envoy",
    srcs = ["tracer_factory_context.cc"],
    hdrs = ["tracer_factory_context.h"],
    deps = [
        "@envoy//include/envoy/server:configuration_interface",
        "//test/mocks/server:instance_mocks",
        "//test/mocks/server:tracer_factory_mocks",
    ],
)

envoy_cc_mock(
    name = "server_mocks",
	repository = "@envoy",
    srcs = [],
    hdrs = ["mocks.h"],
    deps = [
        "//test/mocks/server:admin_mocks",
        "//test/mocks/server:admin_stream_mocks",
        "//test/mocks/server:bootstrap_extension_factory_mocks",
        "//test/mocks/server:config_tracker_mocks",
        "//test/mocks/server:drain_manager_mocks",
        "//test/mocks/server:factory_context_mocks",
        "//test/mocks/server:filter_chain_factory_context_mocks",
        "//test/mocks/server:guard_dog_mocks",
        "//test/mocks/server:health_checker_factory_context_mocks",
        "//test/mocks/server:hot_restart_mocks",
        "//test/mocks/server:instance_mocks",
        "//test/mocks/server:listener_component_factory_mocks",
        "//test/mocks/server:listener_factory_context_mocks",
        "//test/mocks/server:listener_manager_mocks",
        "//test/mocks/server:main_mocks",
        "//test/mocks/server:options_mocks",
        "//test/mocks/server:overload_manager_mocks",
        "//test/mocks/server:server_lifecycle_notifier_mocks",
        "//test/mocks/server:tracer_factory_context_mocks",
        "//test/mocks/server:tracer_factory_mocks",
        "//test/mocks/server:transport_socket_factory_context_mocks",
        "//test/mocks/server:watch_dog_mocks",
        "//test/mocks/server:worker_factory_mocks",
        "//test/mocks/server:worker_mocks",
    ],
)
