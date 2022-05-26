load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test_library(
    name = "add_body_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "add_body_filter.cc",
    ],
    deps = [
        ":common_lib",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "wait_for_whole_request_and_response_config_lib",
    repository = "@envoy",
    srcs = [
        "wait_for_whole_request_and_response.cc",
    ],
    deps = [
        ":common_lib",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "add_trailers_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "add_trailers_filter.cc",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "backpressure_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "backpressure_filter.cc",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "clear_route_cache_filter_lib",
    repository = "@envoy",
    srcs = [
        "clear_route_cache_filter.cc",
    ],
    deps = [
        ":common_lib",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "eds_ready_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "eds_ready_filter.cc",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/http:header_map_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/common/stats:symbol_table_lib",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "modify_buffer_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "modify_buffer_filter.cc",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "passthrough_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "passthrough_filter.cc",
    ],
    deps = [
        ":common_lib",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "headers_only_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "headers_only_filter.cc",
    ],
    deps = [
        ":common_lib",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "pause_filter_lib",
    repository = "@envoy",
    srcs = [
        "pause_filter.cc",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//source/common/network:connection_lib",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "process_context_lib",
    repository = "@envoy",
    srcs = [
        "process_context_filter.cc",
    ],
    hdrs = [
        "process_context_filter.h",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:process_context_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "stop_iteration_and_continue",
    repository = "@envoy",
    srcs = [
        "stop_iteration_and_continue_filter.cc",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//source/common/network:connection_lib",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "common_lib",
    repository = "@envoy",
    hdrs = [
        "common.h",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test_library(
    name = "request_metadata_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "request_metadata_filter.cc",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "random_pause_filter_lib",
    repository = "@envoy",
    srcs = [
        "random_pause_filter.cc",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//source/common/network:connection_lib",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test_library(
    name = "response_metadata_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "response_metadata_filter.cc",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "decode_headers_return_stop_all_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "decode_headers_return_stop_all_filter.cc",
    ],
    deps = [
        ":common_lib",
        "@envoy//include/envoy/event:timer_interface",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "call_decodedata_once_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "call_decodedata_once_filter.cc",
    ],
    deps = [
        ":common_lib",
        "@envoy//include/envoy/event:timer_interface",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "encode_headers_return_stop_all_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "encode_headers_return_stop_all_filter.cc",
    ],
    deps = [
        ":common_lib",
        "@envoy//include/envoy/event:timer_interface",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "metadata_stop_all_filter_config_lib",
    repository = "@envoy",
    srcs = [
        "metadata_stop_all_filter.cc",
    ],
    deps = [
        ":common_lib",
        "@envoy//include/envoy/event:timer_interface",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)

envoy_cc_test_library(
    name = "encoder_decoder_buffer_filter_lib",
    repository = "@envoy",
    srcs = [
        "encoder_decoder_buffer_filter.cc",
    ],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy//test/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)
