licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "signer_interface",
    repository = "@envoy",
    hdrs = ["signer.h"],
    deps = [
        "@envoy//include/envoy/http:message_interface",
    ],
)

envoy_cc_library(
    name = "signer_impl_lib",
    repository = "@envoy",
    srcs = ["signer_impl.cc"],
    hdrs = ["signer_impl.h"],
    deps = [
        ":credentials_provider_interface",
        ":signer_interface",
        ":utility_lib",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:hex_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/common:utility_lib",
        "@envoy//source/common/crypto:utility_lib",
        "@envoy//source/common/http:headers_lib",
        "@envoy//source/common/singleton:const_singleton",
        "//source/extensions/common/crypto:utility_lib",
    ],
)

envoy_cc_library(
    name = "credentials_provider_interface",
    repository = "@envoy",
    hdrs = ["credentials_provider.h"],
    external_deps = ["abseil_optional"],
)

envoy_cc_library(
    name = "credentials_provider_impl_lib",
    repository = "@envoy",
    srcs = ["credentials_provider_impl.cc"],
    hdrs = ["credentials_provider_impl.h"],
    external_deps = ["abseil_time"],
    deps = [
        ":credentials_provider_interface",
        "@envoy//include/envoy/api:api_interface",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/common:thread_lib",
        "@envoy//source/common/http:utility_lib",
        "@envoy//source/common/json:json_loader_lib",
    ],
)

envoy_cc_library(
    name = "utility_lib",
    repository = "@envoy",
    srcs = ["utility.cc"],
    hdrs = ["utility.h"],
    external_deps = ["curl"],
    deps = [
        "@envoy//source/common/common:utility_lib",
        "@envoy//source/common/http:headers_lib",
    ],
)

envoy_cc_library(
    name = "region_provider_interface",
    repository = "@envoy",
    hdrs = ["region_provider.h"],
    external_deps = ["abseil_optional"],
)

envoy_cc_library(
    name = "region_provider_impl_lib",
    repository = "@envoy",
    srcs = ["region_provider_impl.cc"],
    hdrs = ["region_provider_impl.h"],
    deps = [
        ":region_provider_interface",
        "@envoy//source/common/common:logger_lib",
    ],
)
